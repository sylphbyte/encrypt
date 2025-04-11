package encrypt

import (
	"sync"
	"sync/atomic"
)

// ConcurrentBufferPool 并发安全的字节缓冲区池
type ConcurrentBufferPool struct {
	pool      sync.Pool        // 底层对象池
	mutex     sync.RWMutex     // 保护metrics的读写操作
	active    int32            // 当前活跃（已取出未归还）的缓冲区数量
	created   int64            // 已创建的缓冲区总数
	reused    int64            // 复用的缓冲区次数
	minSize   int              // 最小缓冲区容量
	maxSize   int              // 最大缓冲区容量
	cacheSize int              // 缓存队列大小限制
}

// NewConcurrentBufferPool 创建新的并发安全字节缓冲区池
func NewConcurrentBufferPool(minSize, maxSize, cacheSize int) *ConcurrentBufferPool {
	return &ConcurrentBufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				// 创建新的缓冲区时使用预定义的初始容量
				return make([]byte, 0, minSize)
			},
		},
		minSize:   minSize,
		maxSize:   maxSize,
		cacheSize: cacheSize,
	}
}

// GetBuffer 获取一个字节缓冲区，并发安全
func (p *ConcurrentBufferPool) GetBuffer(size int) []byte {
	// 增加活跃计数
	atomic.AddInt32(&p.active, 1)

	// 从池中获取缓冲区
	buf := p.pool.Get().([]byte)

	// 检查容量是否足够
	if cap(buf) < size {
		// 如果容量不够，创建新的缓冲区
		atomic.AddInt64(&p.created, 1)
		// 将不适用的缓冲区放回池中，以便将来可能的复用
		p.pool.Put(buf[:0])
		return make([]byte, size)
	}

	// 记录复用计数
	atomic.AddInt64(&p.reused, 1)
	// 调整长度，确保返回大小正确的缓冲区
	return buf[:size]
}

// PutBuffer 归还字节缓冲区，并发安全
func (p *ConcurrentBufferPool) PutBuffer(buf []byte) {
	// 检查缓冲区大小是否在可接受范围内
	if buf == nil || cap(buf) < p.minSize || cap(buf) > p.maxSize {
		// 对于nil或不符合大小要求的缓冲区，不放回池中让GC处理
		return
	}

	// 检查当前池中缓存的对象数量
	if atomic.LoadInt32(&p.active) > int32(p.cacheSize) {
		// 如果已经超过了缓存大小限制，不再放回对象
		// 减少活跃计数并返回
		atomic.AddInt32(&p.active, -1)
		return
	}

	// 重置缓冲区长度为0，保留容量
	p.pool.Put(buf[:0])

	// 减少活跃计数
	atomic.AddInt32(&p.active, -1)
}

// GetMetrics 获取池状态指标
func (p *ConcurrentBufferPool) GetMetrics() map[string]int64 {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return map[string]int64{
		"active":  int64(atomic.LoadInt32(&p.active)),
		"created": atomic.LoadInt64(&p.created),
		"reused":  atomic.LoadInt64(&p.reused),
	}
}

// ConcurrentPool 并发安全的通用对象池
type ConcurrentPool struct {
	pool       sync.Pool    // 底层对象池
	mutex      sync.RWMutex // 保护metrics的读写操作
	active     int32        // 当前活跃（已取出未归还）的对象数量
	created    int64        // 已创建的对象总数
	reused     int64        // 复用的对象次数
	sizeLock   sync.Mutex   // 用于限制池大小的锁
	maxSize    int          // 池中允许的最大对象数
	waitGroup  sync.WaitGroup // 用于优雅关闭
	newFunc    func() interface{} // 创建新对象的函数
	resetFunc  func(interface{}) // 重置对象状态的函数
}

// NewConcurrentPool 创建新的并发安全对象池
func NewConcurrentPool(maxSize int, newFunc func() interface{}, resetFunc func(interface{})) *ConcurrentPool {
	pool := &ConcurrentPool{
		maxSize:   maxSize,
		newFunc:   newFunc,
		resetFunc: resetFunc,
	}

	pool.pool = sync.Pool{
		New: func() interface{} {
			atomic.AddInt64(&pool.created, 1)
			return newFunc()
		},
	}

	return pool
}

// Get 获取一个对象，并发安全
func (p *ConcurrentPool) Get() interface{} {
	// 增加活跃计数
	atomic.AddInt32(&p.active, 1)
	p.waitGroup.Add(1)

	// 从池中获取对象
	obj := p.pool.Get()

	// 计数是否复用
	if obj != nil {
		atomic.AddInt64(&p.reused, 1)
	}

	return obj
}

// Put 归还一个对象，并发安全
func (p *ConcurrentPool) Put(obj interface{}) {
	if obj == nil {
		p.waitGroup.Done()
		return
	}

	// 重置对象状态
	if p.resetFunc != nil {
		p.resetFunc(obj)
	}

	// 检查当前池大小是否达到上限
	if p.maxSize > 0 && atomic.LoadInt32(&p.active) > int32(p.maxSize) {
		// 如果已达到上限，不再放回对象
		// 减少活跃计数并返回
		atomic.AddInt32(&p.active, -1)
		p.waitGroup.Done()
		return
	}

	// 放回对象到池中
	p.pool.Put(obj)

	// 减少活跃计数
	atomic.AddInt32(&p.active, -1)
	p.waitGroup.Done()
}

// GetMetrics 获取池状态指标
func (p *ConcurrentPool) GetMetrics() map[string]int64 {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return map[string]int64{
		"active":  int64(atomic.LoadInt32(&p.active)),
		"created": atomic.LoadInt64(&p.created),
		"reused":  atomic.LoadInt64(&p.reused),
	}
}

// Wait 等待所有对象归还（用于优雅关闭）
func (p *ConcurrentPool) Wait() {
	p.waitGroup.Wait()
}

// ConcurrentSymmetricPool 并发安全的对称加密器对象池
type ConcurrentSymmetricPool struct {
	algorithm Algorithm
	pool      *ConcurrentPool
}

// NewConcurrentSymmetricPool 创建并发安全的对称加密器对象池
func NewConcurrentSymmetricPool(algorithm Algorithm, maxSize int, newFunc func() interface{}, resetFunc func(interface{})) *ConcurrentSymmetricPool {
	return &ConcurrentSymmetricPool{
		algorithm: algorithm,
		pool:      NewConcurrentPool(maxSize, newFunc, resetFunc),
	}
}

// Get 获取一个对称加密器实例，并发安全
func (p *ConcurrentSymmetricPool) Get() interface{} {
	return p.pool.Get()
}

// Put 归还一个对称加密器实例，并发安全
func (p *ConcurrentSymmetricPool) Put(encryptor interface{}) {
	p.pool.Put(encryptor)
}

// GetMetrics 获取池状态指标
func (p *ConcurrentSymmetricPool) GetMetrics() map[string]int64 {
	return p.pool.GetMetrics()
}

// ConcurrentAsymmetricPool 并发安全的非对称加密器对象池
type ConcurrentAsymmetricPool struct {
	algorithm Algorithm
	pool      *ConcurrentPool
}

// NewConcurrentAsymmetricPool 创建并发安全的非对称加密器对象池
func NewConcurrentAsymmetricPool(algorithm Algorithm, maxSize int, newFunc func() interface{}, resetFunc func(interface{})) *ConcurrentAsymmetricPool {
	return &ConcurrentAsymmetricPool{
		algorithm: algorithm,
		pool:      NewConcurrentPool(maxSize, newFunc, resetFunc),
	}
}

// Get 获取一个非对称加密器实例，并发安全
func (p *ConcurrentAsymmetricPool) Get() interface{} {
	return p.pool.Get()
}

// Put 归还一个非对称加密器实例，并发安全
func (p *ConcurrentAsymmetricPool) Put(encryptor interface{}) {
	p.pool.Put(encryptor)
}

// GetMetrics 获取池状态指标
func (p *ConcurrentAsymmetricPool) GetMetrics() map[string]int64 {
	return p.pool.GetMetrics()
}