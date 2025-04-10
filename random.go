package encrypt

import (
	"crypto/rand"
	"fmt"
	"io"
	"sync"
)

// 定义一个随机读取器接口，便于在测试中进行模拟
type RandomReader interface {
	Read(p []byte) (n int, err error)
}

var (
	// 默认的随机数生成器使用crypto/rand
	defaultRandomReader RandomReader = rand.Reader

	// 用于保护随机数生成器的互斥锁
	randomLock sync.Mutex
)

// SetRandomReader 设置自定义随机数生成器（主要用于测试）
func SetRandomReader(reader RandomReader) {
	if reader == nil {
		reader = rand.Reader
	}

	randomLock.Lock()
	defer randomLock.Unlock()

	defaultRandomReader = reader
}

// ReadRandom 安全地生成随机字节
// 该函数是线程安全的，适合高并发场景
func ReadRandom(p []byte) (int, error) {
	randomLock.Lock()
	defer randomLock.Unlock()

	return io.ReadFull(defaultRandomReader, p)
}

// GenerateRandomBytes 生成指定长度的随机字节
func GenerateRandomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("invalid random bytes length: %d", length)
	}

	result := make([]byte, length)
	_, err := ReadRandom(result)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return result, nil
}

// GenerateRandomKey 生成特定大小的随机密钥
func GenerateRandomKey(keySize int) ([]byte, error) {
	return GenerateRandomBytes(keySize)
}

// GenerateRandomIV 生成随机初始化向量
func GenerateRandomIV(blockSize int) ([]byte, error) {
	return GenerateRandomBytes(blockSize)
}
