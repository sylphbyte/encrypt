package tests

import (
	"sync"
	"testing"

	"github.com/sylphbyte/encrypt"
)

// TestConcurrentBufferPool 测试并发字节缓冲区池
func TestConcurrentBufferPool(t *testing.T) {
	// 创建一个并发安全的字节缓冲区池
	// 参数：最小初始容量、最大允许容量、池大小上限
	pool := encrypt.NewConcurrentBufferPool(1024, 8192, 1000)

	var wg sync.WaitGroup
	// 并发获取和归还缓冲区
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				// 获取大小为2048的缓冲区
				buf := pool.GetBuffer(2048)
				// 模拟使用缓冲区
				for k := 0; k < len(buf); k++ {
					buf[k] = byte(k % 256)
				}
				// 归还缓冲区
				pool.PutBuffer(buf)
			}
		}()
	}

	// 等待所有协程完成
	wg.Wait()

	// 验证指标数据
	metrics := pool.GetMetrics()
	t.Logf("Buffer Pool Metrics: %+v", metrics)

	// 检查活跃缓冲区数量是否为0（全部归还）
	if metrics["active"] != 0 {
		t.Errorf("Expected active buffers to be 0, got %d", metrics["active"])
	}

	// 检查复用率
	if metrics["reused"] < 9000 { // 至少有9000次复用
		t.Errorf("Expected reuse count to be at least 9000, got %d", metrics["reused"])
	}
}

// TestConcurrentSymmetricPool 测试并发对称加密器池
func TestConcurrentSymmetricPool(t *testing.T) {
	// 创建一个对称加密器的实例化函数
	newFunc := func() interface{} {
		// 使用工厂方法创建AES加密器
		aes, _ := encrypt.NewAES([]byte("0123456789abcdef"))
		// 转换回具体类型
		return aes.(*encrypt.AESEncryptor)
	}

	// 创建一个对称加密器的重置函数
	resetFunc := func(obj interface{}) {
		aes := obj.(*encrypt.AESEncryptor)
		aes.Reset()
	}

	// 创建并发安全的对称加密器池
	// 参数：算法类型、池大小上限、创建函数、重置函数
	pool := encrypt.NewConcurrentSymmetricPool(encrypt.AlgorithmAES, 100, newFunc, resetFunc)

	// 测试数据
	plaintext := []byte("这是需要加密的测试数据，用于验证并发对象池性能")
	key := []byte("0123456789abcdef") // 16字节AES密钥

	// 并发测试
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				// 从池中获取AES加密器
				aes := pool.Get().(*encrypt.AESEncryptor)

				// 设置密钥
				aes.SetKey(key)

				// 执行加密操作
				ciphertext, err := aes.Encrypt(plaintext)
				if err != nil {
					t.Errorf("加密失败: %v", err)
				}

				// 执行解密操作
				decrypted, err := aes.Decrypt(ciphertext)
				if err != nil {
					t.Errorf("解密失败: %v", err)
				}

				// 验证解密结果
				if string(decrypted) != string(plaintext) {
					t.Errorf("解密结果与原文不匹配")
				}

				// 归还加密器到池中
				pool.Put(aes)
			}
		}()
	}

	// 等待所有协程完成
	wg.Wait()

	// 验证指标数据
	metrics := pool.GetMetrics()
	t.Logf("AES Pool Metrics: %+v", metrics)

	// 检查活跃加密器数量是否为0（全部归还）
	if metrics["active"] != 0 {
		t.Errorf("Expected active encryptors to be 0, got %d", metrics["active"])
	}
}

// BenchmarkConcurrentBufferPool 基准测试并发字节缓冲区池性能
func BenchmarkConcurrentBufferPool(b *testing.B) {
	// 创建一个并发安全的字节缓冲区池
	pool := encrypt.NewConcurrentBufferPool(1024, 8192, 1000)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// 获取缓冲区
			buf := pool.GetBuffer(2048)
			// 写入一些数据
			for i := 0; i < 100; i++ {
				if i < len(buf) {
					buf[i] = byte(i)
				}
			}
			// 归还缓冲区
			pool.PutBuffer(buf)
		}
	})
}

// BenchmarkConcurrentVsStandardPool 比较并发池与标准池性能
func BenchmarkConcurrentVsStandardPool(b *testing.B) {
	// 测试常规对象池
	b.Run("StandardPool", func(b *testing.B) {
		// 测试数据
		plaintext := []byte("这是需要加密的测试数据，用于验证对象池性能")
		key := []byte("0123456789abcdef") // 16字节AES密钥

		b.ReportAllocs()
		b.ResetTimer()

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				// 从工厂方法获取加密器
				aes, _ := encrypt.NewAES(key)

				// 执行加密操作
				ciphertext, _ := aes.CBC().PKCS7().Base64().Encrypt(plaintext)

				// 执行解密操作
				_, _ = aes.Decrypt(ciphertext)

				// 释放加密器到对象池
				aes.Release()
			}
		})
	})

	// 测试并发安全对象池
	b.Run("ConcurrentPool", func(b *testing.B) {
		// 测试数据
		plaintext := []byte("这是需要加密的测试数据，用于验证对象池性能")
		key := []byte("0123456789abcdef") // 16字节AES密钥

		// 创建一个对称加密器的实例化函数
		newFunc := func() interface{} {
			// 使用工厂方法创建AES加密器
			aes, _ := encrypt.NewAES([]byte("0123456789abcdef"))
			// 转换回具体类型
			return aes.(*encrypt.AESEncryptor)
		}

		// 创建一个对称加密器的重置函数
		resetFunc := func(obj interface{}) {
			aes := obj.(*encrypt.AESEncryptor)
			aes.Reset()
		}

		// 创建并发安全的对称加密器池
		pool := encrypt.NewConcurrentSymmetricPool(encrypt.AlgorithmAES, 100, newFunc, resetFunc)

		b.ReportAllocs()
		b.ResetTimer()

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				// 从池中获取AES加密器
				aes := pool.Get().(*encrypt.AESEncryptor)

				// 设置密钥
				aes.SetKey(key)

				// 执行加密操作
				ciphertext, _ := aes.Encrypt(plaintext)

				// 执行解密操作
				_, _ = aes.Decrypt(ciphertext)

				// 归还加密器到池中
				pool.Put(aes)
			}
		})
	})
}