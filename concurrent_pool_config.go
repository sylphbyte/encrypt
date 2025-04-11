package encrypt

import (
	"crypto/aes"
	"crypto/des"
	"crypto/rand"
	"io"
	"sync"
	
	"github.com/pkg/errors"
)

// 全局并发安全对象池管理
var ConcurrentPools struct {
	// 对称加密算法池
	AES       *ConcurrentSymmetricPool
	DES       *ConcurrentSymmetricPool
	TripleDES *ConcurrentSymmetricPool
	SM4       *ConcurrentSymmetricPool
	
	// 非对称加密算法池
	RSA       *ConcurrentAsymmetricPool
	SM2       *ConcurrentAsymmetricPool
	
	// 字节缓冲区池
	Buffer    *ConcurrentBufferPool
	
	// 初始化标志
	initialized bool
	mutex       sync.Mutex
}

// 对象池大小配置
const (
	// 默认池大小限制
	DefaultPoolSize = 1000
	
	// 缓冲区大小设置
	MinBufferSize = 1024
	MaxBufferSize = 65536
	
	// 默认并发级别
	DefaultConcurrencyLevel = 32
)

// InitConcurrentPools 初始化所有并发安全对象池
func InitConcurrentPools() {
	// 使用Double-Check锁定模式确保线程安全的单次初始化
	if !ConcurrentPools.initialized {
		ConcurrentPools.mutex.Lock()
		defer ConcurrentPools.mutex.Unlock()
		
		if !ConcurrentPools.initialized {
			// 初始化字节缓冲区池
			ConcurrentPools.Buffer = NewConcurrentBufferPool(MinBufferSize, MaxBufferSize, DefaultPoolSize)
			
			// 初始化AES加密器池
			ConcurrentPools.AES = NewConcurrentSymmetricPool(
				AlgorithmAES,
				DefaultPoolSize,
				func() interface{} {
					// 创建默认的AES密钥进行初始化
					tempKey := make([]byte, 16) // AES-128的默认密钥大小
					
					// 利用全局工厂函数创建对象
					aes, _ := NewAES(tempKey)
					return aes
				},
				func(obj interface{}) {
					aes := obj.(*AESEncryptor)
					// 清理所有敏感数据
					aes.Reset()
				},
			)
			
			// 初始化DES加密器池
			ConcurrentPools.DES = NewConcurrentSymmetricPool(
				AlgorithmDES,
				DefaultPoolSize,
				func() interface{} {
					// 创建默认的DES密钥进行初始化
					tempKey := make([]byte, 8) // DES的默认密钥大小
					
					// 利用全局工厂函数创建对象
					des, _ := NewDES(tempKey)
					return des
				},
				func(obj interface{}) {
					des := obj.(*DESEncryptor)
					// 清理所有敏感数据
					des.Reset()
				},
			)
			
			// 初始化3DES加密器池
			ConcurrentPools.TripleDES = NewConcurrentSymmetricPool(
				Algorithm3DES,
				DefaultPoolSize,
				func() interface{} {
					// 创建默认的3DES密钥进行初始化
					tempKey := make([]byte, 24) // 3DES需要24字节密钥
					
					// 利用全局工厂函数创建对象
					tdes, _ := New3DES(tempKey)
					return tdes
				},
				func(obj interface{}) {
					tdes := obj.(*TripleDESEncryptor)
					// 清理所有敏感数据
					tdes.Reset()
				},
			)
			
			// 初始化SM4加密器池
			ConcurrentPools.SM4 = NewConcurrentSymmetricPool(
				AlgorithmSM4,
				DefaultPoolSize,
				func() interface{} {
					// 创建默认的SM4密钥进行初始化
					tempKey := make([]byte, 16) // SM4需要16字节密钥
					
					// 利用全局工厂函数创建对象
					sm4, _ := NewSM4(tempKey)
					return sm4
				},
				func(obj interface{}) {
					sm4 := obj.(*SM4Encryptor)
					// 清理所有敏感数据
					sm4.Reset()
				},
			)
			
			// 初始化RSA加密器池
			ConcurrentPools.RSA = NewConcurrentAsymmetricPool(
				AlgorithmRSA,
				DefaultPoolSize,
				func() interface{} {
					// 利用全局工厂函数创建对象
					rsa, _ := NewRSA()
					return rsa
				},
				func(obj interface{}) {
					rsa := obj.(*RSAEncryptor)
					// 清理敏感数据
					rsa.Reset()
				},
			)
			
			// 初始化SM2加密器池
			ConcurrentPools.SM2 = NewConcurrentAsymmetricPool(
				AlgorithmSM2,
				DefaultPoolSize,
				func() interface{} {
					// 利用全局工厂函数创建对象
					sm2, _ := NewSM2()
					return sm2
				},
				func(obj interface{}) {
					sm2 := obj.(*SM2Encryptor)
					// 清理敏感数据
					sm2.Reset()
				},
			)
			
			ConcurrentPools.initialized = true
		}
	}
}

// GetConcurrentBuffer 获取并发安全的字节缓冲区
func GetConcurrentBuffer(size int) []byte {
	// 确保对象池已初始化
	InitConcurrentPools()
	return ConcurrentPools.Buffer.GetBuffer(size)
}

// PutConcurrentBuffer 归还并发安全的字节缓冲区
func PutConcurrentBuffer(buf []byte) {
	// 确保对象池已初始化
	InitConcurrentPools()
	ConcurrentPools.Buffer.PutBuffer(buf)
}

// NewConcurrentAES 创建新的线程安全AES加密器
func NewConcurrentAES(key []byte) (ISymmetric, error) {
	// 验证密钥长度
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("AES密钥长度必须是16、24或32字节")
	}
	
	// 确保对象池已初始化
	InitConcurrentPools()
	
	// 获取加密器实例
	encryptor := ConcurrentPools.AES.Get().(*AESEncryptor)
	
	// 重置/设置密钥
	if encryptor.key == nil || len(encryptor.key) != len(key) {
		encryptor.key = make([]byte, len(key))
	}
	copy(encryptor.key, key)
	
	// 生成随机IV
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "创建AES器失败")
	}
	
	blockSize := block.BlockSize()
	if encryptor.iv == nil || len(encryptor.iv) != blockSize {
		encryptor.iv = make([]byte, blockSize)
	}
	if _, err := io.ReadFull(rand.Reader, encryptor.iv); err != nil {
		return nil, errors.Wrap(err, "生成随机IV失败")
	}
	
	return encryptor, nil
}

// NewConcurrentDES 创建新的线程安全DES加密器
func NewConcurrentDES(key []byte) (ISymmetric, error) {
	// 验证密钥长度
	if len(key) != 8 {
		return nil, errors.New("DES密钥长度必须是8字节")
	}
	
	// 确保对象池已初始化
	InitConcurrentPools()
	
	// 获取加密器实例
	encryptor := ConcurrentPools.DES.Get().(*DESEncryptor)
	
	// 重置/设置密钥
	if encryptor.key == nil || len(encryptor.key) != len(key) {
		encryptor.key = make([]byte, len(key))
	}
	copy(encryptor.key, key)
	
	// 生成随机IV
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "创建DES器失败")
	}
	
	blockSize := block.BlockSize()
	if encryptor.iv == nil || len(encryptor.iv) != blockSize {
		encryptor.iv = make([]byte, blockSize)
	}
	if _, err := io.ReadFull(rand.Reader, encryptor.iv); err != nil {
		return nil, errors.Wrap(err, "生成随机IV失败")
	}
	
	return encryptor, nil
}

// NewConcurrent3DES 创建新的线程安全3DES加密器
func NewConcurrent3DES(key []byte) (ISymmetric, error) {
	// 验证密钥长度
	if len(key) != 24 {
		return nil, errors.New("3DES密钥长度必须是24字节")
	}
	
	// 确保对象池已初始化
	InitConcurrentPools()
	
	// 获取加密器实例
	encryptor := ConcurrentPools.TripleDES.Get().(*TripleDESEncryptor)
	
	// 重置/设置密钥
	if encryptor.key == nil || len(encryptor.key) != len(key) {
		encryptor.key = make([]byte, len(key))
	}
	copy(encryptor.key, key)
	
	// 生成随机IV
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "创建3DES器失败")
	}
	
	blockSize := block.BlockSize()
	if encryptor.iv == nil || len(encryptor.iv) != blockSize {
		encryptor.iv = make([]byte, blockSize)
	}
	if _, err := io.ReadFull(rand.Reader, encryptor.iv); err != nil {
		return nil, errors.Wrap(err, "生成随机IV失败")
	}
	
	return encryptor, nil
}

// NewConcurrentSM4 创建新的线程安全SM4加密器
func NewConcurrentSM4(key []byte) (ISymmetric, error) {
	// 验证密钥长度
	if len(key) != 16 {
		return nil, errors.New("SM4密钥长度必须是16字节")
	}
	
	// 确保对象池已初始化
	InitConcurrentPools()
	
	// 获取加密器实例
	encryptor := ConcurrentPools.SM4.Get().(*SM4Encryptor)
	
	// 重置/设置密钥
	if encryptor.key == nil || len(encryptor.key) != len(key) {
		encryptor.key = make([]byte, len(key))
	}
	copy(encryptor.key, key)
	
	// 生成随机IV
	if encryptor.iv == nil || len(encryptor.iv) != 16 {
		encryptor.iv = make([]byte, 16) // SM4块大小为16字节
	}
	if _, err := io.ReadFull(rand.Reader, encryptor.iv); err != nil {
		return nil, errors.Wrap(err, "生成随机IV失败")
	}
	
	return encryptor, nil
}

// NewConcurrentRSA 创建新的线程安全RSA加密器
func NewConcurrentRSA() (IAsymmetric, error) {
	// 确保对象池已初始化
	InitConcurrentPools()
	
	// 获取加密器实例
	encryptor := ConcurrentPools.RSA.Get().(*RSAEncryptor)
	
	return encryptor, nil
}

// NewConcurrentSM2 创建新的线程安全SM2加密器
func NewConcurrentSM2() (IAsymmetric, error) {
	// 确保对象池已初始化
	InitConcurrentPools()
	
	// 获取加密器实例
	encryptor := ConcurrentPools.SM2.Get().(*SM2Encryptor)
	
	return encryptor, nil
}

// ReleaseConcurrentBuffer 释放并发安全的字节缓冲区
// 此函数是GetConcurrentBuffer的对等函数
func ReleaseConcurrentBuffer(buf []byte) {
	PutConcurrentBuffer(buf)
}

// GetPoolMetrics 获取所有对象池的指标信息
func GetPoolMetrics() map[string]map[string]int64 {
	// 确保对象池已初始化
	InitConcurrentPools()
	
	// 收集各个池的指标
	return map[string]map[string]int64{
		"Buffer":    ConcurrentPools.Buffer.GetMetrics(),
		"AES":       ConcurrentPools.AES.GetMetrics(),
		"DES":       ConcurrentPools.DES.GetMetrics(),
		"TripleDES": ConcurrentPools.TripleDES.GetMetrics(),
		"SM4":       ConcurrentPools.SM4.GetMetrics(),
		"RSA":       ConcurrentPools.RSA.GetMetrics(),
		"SM2":       ConcurrentPools.SM2.GetMetrics(),
	}
}

// SetKey 为AESEncryptor设置密钥的辅助方法
func (s *AESEncryptor) SetKey(key []byte) {
	if s.key == nil || len(s.key) != len(key) {
		s.key = make([]byte, len(key))
	}
	copy(s.key, key)
}