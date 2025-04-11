package tests

import (
	"testing"

	"github.com/sylphbyte/encrypt"
)

// TestObjectPoolPerformance 测试对象池性能
func TestObjectPoolPerformance(t *testing.T) {
	// 测试数据
	plaintext := []byte("这是需要加密的测试数据，用于验证对象池性能")
	key := []byte("0123456789abcdef") // 16字节SM4密钥

	// 1. 测试不使用对象池（每次都创建新的加密器）
	t.Run("WithoutPool", func(t *testing.T) {

		for i := 0; i < 1000; i++ {
			// 每次创建新的加密器
			sm4, err := encrypt.NewSM4(key)
			if err != nil {
				t.Fatalf("创建SM4加密器失败: %v", err)
			}

			// 执行加密操作
			ciphertext, err := sm4.CBC().PKCS7().Base64().Encrypt(plaintext)
			if err != nil {
				t.Fatalf("加密失败: %v", err)
			}

			// 执行解密操作
			_, err = sm4.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("解密失败: %v", err)
			}

			// 注意：这里故意不调用Release()
		}
	})

	// 2. 测试使用对象池（每次使用后归还加密器）
	t.Run("WithPool", func(t *testing.T) {

		for i := 0; i < 1000; i++ {
			// 从对象池获取加密器
			sm4, err := encrypt.NewSM4(key)
			if err != nil {
				t.Fatalf("创建SM4加密器失败: %v", err)
			}

			// 执行加密操作
			ciphertext, err := sm4.CBC().PKCS7().Base64().Encrypt(plaintext)
			if err != nil {
				t.Fatalf("加密失败: %v", err)
			}

			// 执行解密操作
			_, err = sm4.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("解密失败: %v", err)
			}

			// 使用完毕后归还加密器
			sm4.Release()
		}
	})
}

// BenchmarkSM4_WithoutPool 基准测试：不使用对象池
func BenchmarkSM4_WithoutPool(b *testing.B) {
	plaintext := []byte("这是需要加密的测试数据，用于验证对象池性能")
	key := []byte("0123456789abcdef") // 16字节SM4密钥

	b.ReportAllocs() // 报告内存分配情况
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// 每次创建新的加密器
		sm4, _ := encrypt.NewSM4(key)

		// 执行加密操作
		ciphertext, _ := sm4.CBC().PKCS7().Base64().Encrypt(plaintext)

		// 执行解密操作
		_, _ = sm4.Decrypt(ciphertext)

		// 不调用Release()
	}
}

// BenchmarkSM4_WithPool 基准测试：使用对象池
func BenchmarkSM4_WithPool(b *testing.B) {
	plaintext := []byte("这是需要加密的测试数据，用于验证对象池性能")
	key := []byte("0123456789abcdef") // 16字节SM4密钥

	b.ReportAllocs() // 报告内存分配情况
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// 从对象池获取加密器
		sm4, _ := encrypt.NewSM4(key)

		// 执行加密操作
		ciphertext, _ := sm4.CBC().PKCS7().Base64().Encrypt(plaintext)

		// 执行解密操作
		_, _ = sm4.Decrypt(ciphertext)

		// 使用完毕后归还加密器
		sm4.Release()
	}
}

// BenchmarkAES_WithoutPool 基准测试：不使用对象池的AES加密
func BenchmarkAES_WithoutPool(b *testing.B) {
	plaintext := []byte("这是需要加密的测试数据，用于验证对象池性能")
	key := []byte("0123456789abcdef") // 16字节AES-128密钥

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		aes, _ := encrypt.NewAES(key)
		ciphertext, _ := aes.CBC().PKCS7().Base64().Encrypt(plaintext)
		_, _ = aes.Decrypt(ciphertext)
		// 不调用Release()
	}
}

// BenchmarkAES_WithPool 基准测试：使用对象池的AES加密
func BenchmarkAES_WithPool(b *testing.B) {
	plaintext := []byte("这是需要加密的测试数据，用于验证对象池性能")
	key := []byte("0123456789abcdef") // 16字节AES-128密钥

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		aes, _ := encrypt.NewAES(key)
		ciphertext, _ := aes.CBC().PKCS7().Base64().Encrypt(plaintext)
		_, _ = aes.Decrypt(ciphertext)
		aes.Release() // 使用对象池
	}
}

// BenchmarkRSA_WithoutPool 基准测试：不使用对象池的RSA加密
func BenchmarkRSA_WithoutPool(b *testing.B) {
	plaintext := []byte("这是需要加密的测试数据，用于验证对象池性能")

	// 生成RSA密钥对
	rsa, _ := encrypt.NewRSA()
	pubKey, privKey, _ := rsa.WithKeySize(2048).GenerateKeyPair()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// 每次创建新的加密器
		rsa, _ := encrypt.NewRSA()

		// 使用公钥加密
		ciphertext, _ := rsa.WithPublicKey(pubKey).Encrypt(plaintext)

		// 使用私钥解密
		_, _ = rsa.WithPrivateKey(privKey).Decrypt(ciphertext)
		// 不调用Release()
	}
}

// BenchmarkRSA_WithPool 基准测试：使用对象池的RSA加密
func BenchmarkRSA_WithPool(b *testing.B) {
	plaintext := []byte("这是需要加密的测试数据，用于验证对象池性能")

	// 生成RSA密钥对
	rsa, _ := encrypt.NewRSA()
	pubKey, privKey, _ := rsa.WithKeySize(2048).GenerateKeyPair()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// 从对象池获取加密器
		rsa, _ := encrypt.NewRSA()

		// 使用公钥加密
		ciphertext, _ := rsa.WithPublicKey(pubKey).Encrypt(plaintext)

		// 使用私钥解密
		_, _ = rsa.WithPrivateKey(privKey).Decrypt(ciphertext)

		// 使用完毕后归还加密器
		rsa.Release()
	}
}
