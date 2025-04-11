package encrypt

import (
	"sync"
)

// EncryptorPool 加密器对象池接口
type EncryptorPool interface {
	// Get 获取一个加密器实例
	Get() interface{}

	// Put 归还一个加密器实例
	Put(encryptor interface{})
}

// SymmetricPool 对称加密器对象池
type SymmetricPool struct {
	algorithm Algorithm
	pool      sync.Pool
}

// Get 获取一个对称加密器实例
func (p *SymmetricPool) Get() interface{} {
	return p.pool.Get()
}

// Put 归还一个对称加密器实例
func (p *SymmetricPool) Put(encryptor interface{}) {
	p.pool.Put(encryptor)
}

// AsymmetricPool 非对称加密器对象池
type AsymmetricPool struct {
	algorithm Algorithm
	pool      sync.Pool
}

// Get 获取一个非对称加密器实例
func (p *AsymmetricPool) Get() interface{} {
	return p.pool.Get()
}

// Put 归还一个非对称加密器实例
func (p *AsymmetricPool) Put(encryptor interface{}) {
	p.pool.Put(encryptor)
}

// EncryptorPools 全局加密器池管理
var EncryptorPools = struct {
	AES       *SymmetricPool
	DES       *SymmetricPool
	TripleDES *SymmetricPool
	SM4       *SymmetricPool
	RSA       *AsymmetricPool
	SM2       *AsymmetricPool
}{
	AES:       NewAESPool(),
	DES:       NewDESPool(),
	TripleDES: NewTripleDESPool(),
	SM4:       NewSM4Pool(),
	RSA:       NewRSAPool(),
	SM2:       NewSM2Pool(),
}

// ByteBufferPool 字节缓冲区对象池
var ByteBufferPool = sync.Pool{
	New: func() interface{} {
		// 预分配一个合理大小的缓冲区
		return make([]byte, 0, 1024)
	},
}

// GetBuffer 获取一个字节缓冲区
func GetBuffer(size int) []byte {
	buf := ByteBufferPool.Get().([]byte)
	// 确保容量足够
	if cap(buf) < size {
		// 容量不够，创建新的
		return make([]byte, size)
	}
	// 调整长度
	return buf[:size]
}

// PutBuffer 归还字节缓冲区
func PutBuffer(buf []byte) {
	// 只回收一定大小范围内的buffer，过大的让GC处理
	if cap(buf) <= 8192 {
		ByteBufferPool.Put(buf[:0]) // 重置长度但保持容量
	}
}

// NewAESPool 创建AES加密器对象池
func NewAESPool() *SymmetricPool {
	return &SymmetricPool{
		algorithm: AlgorithmAES,
		pool: sync.Pool{
			New: func() interface{} {
				return &AESEncryptor{
					SymmetricEncryptor: SymmetricEncryptor{
						algorithm: AlgorithmAES,
						blockMode: NewCBCMode(nil),
						padding:   DefaultPKCS7Padding,
						encoding:  Base64Encoding,
					},
				}
			},
		},
	}
}

// NewDESPool 创建DES加密器对象池
func NewDESPool() *SymmetricPool {
	return &SymmetricPool{
		algorithm: AlgorithmDES,
		pool: sync.Pool{
			New: func() interface{} {
				return &DESEncryptor{
					SymmetricEncryptor: SymmetricEncryptor{
						algorithm: AlgorithmDES,
						blockMode: NewCBCMode(nil),
						padding:   DefaultPKCS7Padding,
						encoding:  Base64Encoding,
					},
				}
			},
		},
	}
}

// NewTripleDESPool 创建3DES加密器对象池
func NewTripleDESPool() *SymmetricPool {
	return &SymmetricPool{
		algorithm: Algorithm3DES,
		pool: sync.Pool{
			New: func() interface{} {
				return &TripleDESEncryptor{
					SymmetricEncryptor: SymmetricEncryptor{
						algorithm: Algorithm3DES,
						blockMode: NewCBCMode(nil),
						padding:   DefaultPKCS7Padding,
						encoding:  Base64Encoding,
					},
				}
			},
		},
	}
}

// NewSM4Pool 创建SM4加密器对象池
func NewSM4Pool() *SymmetricPool {
	return &SymmetricPool{
		algorithm: AlgorithmSM4,
		pool: sync.Pool{
			New: func() interface{} {
				return &SM4Encryptor{
					key:          nil,
					iv:           nil,
					blockMode:    ModeCBC,
					padding:      DefaultPKCS7Padding,
					algorithm:    AlgorithmSM4,
					encoding:     Base64Encoding,
					encodingMode: EncodingBase64,
				}
			},
		},
	}
}

// NewRSAPool 创建RSA加密器对象池
func NewRSAPool() *AsymmetricPool {
	return &AsymmetricPool{
		algorithm: AlgorithmRSA,
		pool: sync.Pool{
			New: func() interface{} {
				return &RSAEncryptor{
					keySize: 2048,
				}
			},
		},
	}
}

// NewSM2Pool 创建SM2加密器对象池
func NewSM2Pool() *AsymmetricPool {
	return &AsymmetricPool{
		algorithm: AlgorithmSM2,
		pool: sync.Pool{
			New: func() interface{} {
				return &SM2Encryptor{}
			},
		},
	}
}

// Reset 重置AES加密器状态
func (s *AESEncryptor) Reset() {
	// 清空IV，但保留密钥（密钥由NewAES函数重新设置）
	if s.iv != nil {
		// 安全清理IV数据，避免敏感信息泄露
		for i := range s.iv {
			s.iv[i] = 0
		}
		s.iv = nil
	}

	// 重置加密器状态到默认值
	s.blockMode = NewCBCMode(nil)
	s.padding = DefaultPKCS7Padding
	s.encoding = Base64Encoding
}

// Release 释放AES加密器到对象池
func (s *AESEncryptor) Release() {
	// 检查是否初始化了并发对象池
	if ConcurrentPools.initialized && ConcurrentPools.AES != nil {
		// 清理敏感数据
		s.Reset()
		// 返回到并发安全池
		ConcurrentPools.AES.Put(s)
	} else {
		// 返回到标准池
		s.Reset()
		EncryptorPools.AES.Put(s)
	}
}

// Reset 重置DES加密器状态
func (s *DESEncryptor) Reset() {
	// 清空IV，但保留密钥（密钥由NewDES函数重新设置）
	if s.iv != nil {
		// 安全清理IV数据，避免敏感信息泄露
		for i := range s.iv {
			s.iv[i] = 0
		}
		s.iv = nil
	}

	// 重置加密器状态到默认值
	s.blockMode = NewCBCMode(nil)
	s.padding = DefaultPKCS7Padding
	s.encoding = Base64Encoding
}

// Release 释放DES加密器到对象池
func (s *DESEncryptor) Release() {
	// 检查是否初始化了并发对象池
	if ConcurrentPools.initialized && ConcurrentPools.DES != nil {
		// 清理敏感数据
		s.Reset()
		// 返回到并发安全池
		ConcurrentPools.DES.Put(s)
	} else {
		// 返回到标准池
		s.Reset()
		EncryptorPools.DES.Put(s)
	}
}

// Reset 重置3DES加密器状态
func (s *TripleDESEncryptor) Reset() {
	// 清空IV，但保留密钥（密钥由New3DES函数重新设置）
	if s.iv != nil {
		// 安全清理IV数据，避免敏感信息泄露
		for i := range s.iv {
			s.iv[i] = 0
		}
		s.iv = nil
	}

	// 重置加密器状态到默认值
	s.blockMode = NewCBCMode(nil)
	s.padding = DefaultPKCS7Padding
	s.encoding = Base64Encoding
}

// Release 释放3DES加密器到对象池
func (s *TripleDESEncryptor) Release() {
	// 检查是否初始化了并发对象池
	if ConcurrentPools.initialized && ConcurrentPools.TripleDES != nil {
		// 清理敏感数据
		s.Reset()
		// 返回到并发安全池
		ConcurrentPools.TripleDES.Put(s)
	} else {
		// 返回到标准池
		s.Reset()
		EncryptorPools.TripleDES.Put(s)
	}
}

// Reset 重置SM4加密器状态
func (s *SM4Encryptor) Reset() {
	// 清空IV，但保留密钥（密钥由NewSM4函数重新设置）
	if s.iv != nil {
		// 安全清理IV数据，避免敏感信息泄露
		for i := range s.iv {
			s.iv[i] = 0
		}
		s.iv = nil
	}

	// 重置加密器状态到默认值
	s.blockMode = ModeCBC
	s.padding = DefaultPKCS7Padding
	s.encoding = Base64Encoding
	s.encodingMode = EncodingBase64
}

// Release 释放SM4加密器到对象池
func (s *SM4Encryptor) Release() {
	// 检查是否初始化了并发对象池
	if ConcurrentPools.initialized && ConcurrentPools.SM4 != nil {
		// 清理敏感数据
		s.Reset()
		// 返回到并发安全池
		ConcurrentPools.SM4.Put(s)
	} else {
		// 返回到标准池
		s.Reset()
		EncryptorPools.SM4.Put(s)
	}
}

// Reset 重置RSA加密器状态
func (s *RSAEncryptor) Reset() {
	// 重置状态，但保留密钥
	s.encoding = Base64Encoding
	s.keySize = 2048
}

// Release 释放RSA加密器到对象池
func (s *RSAEncryptor) Release() {
	// 检查是否初始化了并发对象池
	if ConcurrentPools.initialized && ConcurrentPools.RSA != nil {
		// 清理敏感数据
		s.Reset()
		// 返回到并发安全池
		ConcurrentPools.RSA.Put(s)
	} else {
		// 返回到标准池
		s.Reset()
		EncryptorPools.RSA.Put(s)
	}
}

// Reset 重置SM2加密器状态
func (s *SM2Encryptor) Reset() {
	// 重置状态，但保留密钥
	s.encoding = Base64Encoding
	s.encodingMode = EncodingBase64
	s.uid = nil
}

// Release 释放SM2加密器到对象池
func (s *SM2Encryptor) Release() {
	// 检查是否初始化了并发对象池
	if ConcurrentPools.initialized && ConcurrentPools.SM2 != nil {
		// 清理敏感数据
		s.Reset()
		// 返回到并发安全池
		ConcurrentPools.SM2.Put(s)
	} else {
		// 返回到标准池
		s.Reset()
		EncryptorPools.SM2.Put(s)
	}
}
