package tests

import (
	"testing"

	"github.com/sylphbyte/encrypt"
)

// 测试所有Must版本的工厂方法能正确创建对象
func TestMustFactorySuccess(t *testing.T) {
	// 准备正确的密钥
	aesKey := []byte("0123456789ABCDEF") // 16字节AES密钥
	desKey := []byte("01234567")          // 8字节DES密钥
	tdesKey := []byte("012345678901234567890123") // 24字节TripleDES密钥
	sm4Key := []byte("0123456789ABCDEF")  // 16字节SM4密钥

	// 测试每个工厂函数
	tests := []struct {
		name string
		fn   func()
	}{
		{"MustNewAES", func() { encrypt.MustNewAES(aesKey) }},
		{"MustNewDES", func() { encrypt.MustNewDES(desKey) }},
		{"MustNew3DES", func() { encrypt.MustNew3DES(tdesKey) }},
		{"MustNewSM4", func() { encrypt.MustNewSM4(sm4Key) }},
		{"MustNewRSA", func() { encrypt.MustNewRSA() }},
		{"MustNewSM2", func() { encrypt.MustNewSM2() }},
		{"MustNewConcurrentAES", func() { encrypt.MustNewConcurrentAES(aesKey) }},
		{"MustNewConcurrentDES", func() { encrypt.MustNewConcurrentDES(desKey) }},
		{"MustNewConcurrent3DES", func() { encrypt.MustNewConcurrent3DES(tdesKey) }},
		{"MustNewConcurrentSM4", func() { encrypt.MustNewConcurrentSM4(sm4Key) }},
		{"MustNewConcurrentRSA", func() { encrypt.MustNewConcurrentRSA() }},
		{"MustNewConcurrentSM2", func() { encrypt.MustNewConcurrentSM2() }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// 每个函数都应该能正常运行而不会引起panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s应该能正常运行，但却触发了panic: %v", test.name, r)
				}
			}()
			test.fn()
		})
	}
}

// 测试Must版本的工厂方法在参数错误时会正确触发panic
func TestMustFactoryPanic(t *testing.T) {
	// 准备错误的密钥
	invalidAESKey := []byte("12345") // 非16/24/32字节
	invalidDESKey := []byte("123")   // 非8字节
	invalidTDESKey := []byte("12345") // 非24字节
	invalidSM4Key := []byte("12345")  // 非16字节

	// 测试每个工厂函数
	tests := []struct {
		name string
		fn   func()
	}{
		{"MustNewAES", func() { encrypt.MustNewAES(invalidAESKey) }},
		{"MustNewDES", func() { encrypt.MustNewDES(invalidDESKey) }},
		{"MustNew3DES", func() { encrypt.MustNew3DES(invalidTDESKey) }},
		{"MustNewSM4", func() { encrypt.MustNewSM4(invalidSM4Key) }},
		{"MustNewConcurrentAES", func() { encrypt.MustNewConcurrentAES(invalidAESKey) }},
		{"MustNewConcurrentDES", func() { encrypt.MustNewConcurrentDES(invalidDESKey) }},
		{"MustNewConcurrent3DES", func() { encrypt.MustNewConcurrent3DES(invalidTDESKey) }},
		{"MustNewConcurrentSM4", func() { encrypt.MustNewConcurrentSM4(invalidSM4Key) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// 每个函数应该引起panic
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("%s应该因参数错误而触发panic，但却没有", test.name)
				}
			}()
			test.fn() // 应该触发panic
		})
	}
}

// 测试Must工厂方法创建的对象能正常进行加密解密操作
func TestMustFactoryEncryptDecrypt(t *testing.T) {
	// 准备测试数据
	plaintext := []byte("Hello, Must Factory!")
	aesKey := []byte("0123456789ABCDEF")
	desKey := []byte("01234567")

	// 测试AES
	t.Run("MustNewAES", func(t *testing.T) {
		// 使用Must工厂方法创建加密器
		aes := encrypt.MustNewAES(aesKey)
		
		// 设置模式
		aes.CBC() // 使用CBC模式

		// 加密
		ciphertext, err := aes.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("AES加密失败: %v", err)
		}

		// 解密
		decrypted, err := aes.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("AES解密失败: %v", err)
		}

		// 验证解密结果
		if string(decrypted) != string(plaintext) {
			t.Errorf("解密结果不匹配: 期望 %s, 实际 %s", plaintext, decrypted)
		}
	})

	// 测试DES
	t.Run("MustNewDES", func(t *testing.T) {
		// 使用Must工厂方法创建加密器
		des := encrypt.MustNewDES(desKey)
		
		// 设置模式
		des.CBC() // 使用CBC模式

		// 加密
		ciphertext, err := des.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("DES加密失败: %v", err)
		}

		// 解密
		decrypted, err := des.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("DES解密失败: %v", err)
		}

		// 验证解密结果
		if string(decrypted) != string(plaintext) {
			t.Errorf("解密结果不匹配: 期望 %s, 实际 %s", plaintext, decrypted)
		}
	})

	// 测试并发安全版本
	t.Run("MustNewConcurrentAES", func(t *testing.T) {
		// 使用Must工厂方法创建加密器
		aes := encrypt.MustNewConcurrentAES(aesKey)
		
		// 设置模式
		aes.CBC() // 使用CBC模式

		// 加密
		ciphertext, err := aes.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("并发AES加密失败: %v", err)
		}

		// 解密
		decrypted, err := aes.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("并发AES解密失败: %v", err)
		}

		// 验证解密结果
		if string(decrypted) != string(plaintext) {
			t.Errorf("解密结果不匹配: 期望 %s, 实际 %s", plaintext, decrypted)
		}

		// 测试释放资源
		aes.Release()
	})
}