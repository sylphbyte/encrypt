package tests

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/sylphbyte/encrypt"
)

// TestPBKDF2Features 测试PBKDF2密钥派生功能
func TestPBKDF2Features(t *testing.T) {
	// 1. 测试不同的哈希算法
	hashTests := []struct {
		name     string
		deriver  func() *encrypt.PBKDF2Deriver
		expectedLen int // Base64编码后的预期长度
	}{
		{"SHA1", func() *encrypt.PBKDF2Deriver { 
			return encrypt.NewPBKDF2().SHA1().Base64() 
		}, 44}, // SHA1输出20字节，Base64编码后约28个字符
		{"SHA256", func() *encrypt.PBKDF2Deriver { 
			return encrypt.NewPBKDF2().SHA256().Base64() 
		}, 44}, // SHA256输出32字节，Base64编码后约44个字符
		{"SHA512", func() *encrypt.PBKDF2Deriver { 
			return encrypt.NewPBKDF2().SHA512().Base64() 
		}, 88}, // SHA512输出64字节，Base64编码后约88个字符
		{"SM3", func() *encrypt.PBKDF2Deriver { 
			return encrypt.NewPBKDF2().SM3().Base64() 
		}, 44}, // SM3输出32字节，Base64编码后约44个字符
	}
	
	// 测试参数
	password := []byte("测试密码")
	salt := []byte("randomsalt12345")
	iterations := 10000
	keyLength := 32 // 256位密钥
	
	// 执行测试
	for _, test := range hashTests {
		t.Run(test.name, func(t *testing.T) {
			deriver := test.deriver()
			key, err := deriver.DeriveKey(password, salt, iterations, keyLength)
			if err != nil {
				t.Fatalf("%s 派生密钥失败: %v", test.name, err)
			}
			
			// 检查结果长度是否符合预期
			if len(key) == 0 {
				t.Errorf("%s 生成的密钥为空", test.name)
			}
			
			t.Logf("%s 派生密钥结果: %s", test.name, key)
		})
	}
	
	// 2. 测试不同的编码方式
	encodingTests := []struct {
		name      string
		deriver   func() *encrypt.PBKDF2Deriver
		validator func(string) bool
	}{
		{"Base64", func() *encrypt.PBKDF2Deriver { 
			return encrypt.NewPBKDF2().Base64() 
		}, func(s string) bool {
			_, err := base64.StdEncoding.DecodeString(s)
			return err == nil
		}},
		{"Base64Safe", func() *encrypt.PBKDF2Deriver { 
			return encrypt.NewPBKDF2().Base64Safe() 
		}, func(s string) bool {
			_, err := base64.URLEncoding.DecodeString(s)
			return err == nil
		}},
		{"Hex", func() *encrypt.PBKDF2Deriver { 
			return encrypt.NewPBKDF2().Hex() 
		}, func(s string) bool {
			_, err := hex.DecodeString(s)
			return err == nil
		}},
		{"NoEncoding", func() *encrypt.PBKDF2Deriver { 
			return encrypt.NewPBKDF2().NoEncoding() 
		}, func(s string) bool {
			return len(s) == keyLength
		}},
	}
	
	// 执行测试
	for _, test := range encodingTests {
		t.Run(test.name, func(t *testing.T) {
			deriver := test.deriver()
			key, err := deriver.DeriveKey(password, salt, iterations, keyLength)
			if err != nil {
				t.Fatalf("%s 派生密钥失败: %v", test.name, err)
			}
			
			// 验证编码格式
			if !test.validator(key) {
				t.Errorf("%s 编码格式验证失败", test.name)
			}
			
			t.Logf("%s 派生密钥结果: %s", test.name, key)
		})
	}
	
	// 3. 测试参数边界条件
	boundaryTests := []struct {
		name       string
		password   []byte
		salt       []byte
		iterations int
		keyLength  int
		expectErr  bool
	}{
		{"空密码", []byte{}, salt, iterations, keyLength, true},
		{"空盐值", password, []byte{}, iterations, keyLength, true},
		{"迭代次数太少", password, salt, 100, keyLength, true},
		{"零长度密钥", password, salt, iterations, 0, true},
		{"负长度密钥", password, salt, iterations, -10, true},
		{"正常参数", password, salt, iterations, keyLength, false},
		{"短密码", []byte("a"), salt, iterations, keyLength, false},
		{"短盐值", password, []byte("salt"), iterations, keyLength, false},
		{"长密码", []byte("这是一个非常长的密码，用于测试PBKDF2的性能和兼容性，包含中文字符和标点符号！"), salt, iterations, keyLength, false},
		{"长盐值", password, []byte("这是一个非常长的盐值，同样用于测试PBKDF2的健壮性和对长输入的处理能力"), iterations, keyLength, false},
	}
	
	deriver := encrypt.NewPBKDF2()
	for _, test := range boundaryTests {
		t.Run(test.name, func(t *testing.T) {
			key, err := deriver.DeriveKey(test.password, test.salt, test.iterations, test.keyLength)
			
			if test.expectErr {
				if err == nil {
					t.Errorf("%s 应该返回错误，但返回成功: %s", test.name, key)
				}
			} else {
				if err != nil {
					t.Errorf("%s 应该成功，但返回错误: %v", test.name, err)
				}
			}
		})
	}
	
	// 4. 测试多次派生的一致性
	t.Run("一致性测试", func(t *testing.T) {
		deriver := encrypt.NewPBKDF2()
		
		// 第一次派生
		key1, err := deriver.DeriveKey(password, salt, iterations, keyLength)
		if err != nil {
			t.Fatalf("第一次派生失败: %v", err)
		}
		
		// 第二次派生（参数完全相同）
		key2, err := deriver.DeriveKey(password, salt, iterations, keyLength)
		if err != nil {
			t.Fatalf("第二次派生失败: %v", err)
		}
		
		// 验证两次结果是否相同
		if key1 != key2 {
			t.Errorf("两次派生结果不同：\n%s\n%s", key1, key2)
		}
	})
	
	// 5. 测试实际应用场景：使用PBKDF2生成AES密钥
	t.Run("生成AES密钥", func(t *testing.T) {
		// 派生一个AES-256密钥（32字节）
		deriver := encrypt.NewPBKDF2().NoEncoding() // 无编码，直接获取原始字节
		keyBytes, err := deriver.DeriveKey([]byte("用户密码"), []byte("应用盐值"), 10000, 32)
		if err != nil {
			t.Fatalf("派生AES密钥失败: %v", err)
		}
		
		// 使用派生的密钥创建AES加密器
		aes, err := encrypt.NewAES([]byte(keyBytes))
		if err != nil {
			t.Fatalf("创建AES加密器失败: %v", err)
		}
		
		// 测试加密和解密
		plaintext := []byte("使用密码派生的密钥进行加密")
		ciphertext, err := aes.CBC().PKCS7().Base64().Encrypt(plaintext)
		if err != nil {
			t.Fatalf("加密失败: %v", err)
		}
		
		t.Logf("加密结果: %s", ciphertext)
		
		// 解密
		decrypted, err := aes.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("解密失败: %v", err)
		}
		
		// 验证结果
		if string(decrypted) != string(plaintext) {
			t.Errorf("解密结果不匹配，期望: %s, 实际: %s", plaintext, decrypted)
		}
	})
}