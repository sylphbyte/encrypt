package tests

import (
	"bytes"
	"testing"

	"github.com/sylphbyte/encrypt"
)

// TestSM4Features 测试SM4加密功能
func TestSM4Features(t *testing.T) {
	// 1. 创建加密密钥 (SM4固定为16字节/128位)
	key := []byte("1234567890abcdef")
	
	// 2. 创建SM4加密器
	sm4, err := encrypt.NewSM4(key)
	if err != nil {
		t.Fatalf("创建SM4加密器失败: %v", err)
	}
	
	// 3. 测试不同的模式+填充+编码组合
	modeTests := []struct {
		name     string
		encryptor func() encrypt.ISymmetric
	}{
		{"SM4-CBC-PKCS7-Base64", func() encrypt.ISymmetric { 
			return sm4.CBC().PKCS7().Base64()
		}},
		{"SM4-ECB-PKCS7-Hex", func() encrypt.ISymmetric { 
			return sm4.ECB().PKCS7().Hex() 
		}},
		{"SM4-CFB-NoPadding-Base64", func() encrypt.ISymmetric { 
			return sm4.CFB().NoPadding().Base64() 
		}},
		{"SM4-OFB-NoPadding-Hex", func() encrypt.ISymmetric { 
			return sm4.OFB().NoPadding().Hex() 
		}},
		{"SM4-CTR-NoPadding-NoEncoding", func() encrypt.ISymmetric { 
			return sm4.CTR().NoPadding().NoEncoding() 
		}},
		{"SM4-GCM-NoPadding-Base64Safe", func() encrypt.ISymmetric { 
			return sm4.GCM().NoPadding().Base64Safe() 
		}},
	}
	
	// 4. 执行测试
	for _, test := range modeTests {
		t.Run(test.name, func(t *testing.T) {
			// 准备测试数据
			plaintext := []byte("这是SM4国密算法测试数据")
			
			// 获取加密器
			encryptor := test.encryptor()
			
			// 加密
			ciphertext, err := encryptor.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("%s 加密失败: %v", test.name, err)
			}
			
			// 打印加密结果
			t.Logf("%s 加密结果: %s", test.name, ciphertext)
			
			// 解密
			decrypted, err := encryptor.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("%s 解密失败: %v", test.name, err)
			}
			
			// 验证结果
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("%s 加解密结果与原文不匹配，期望: %s, 实际: %s", 
					test.name, string(plaintext), string(decrypted))
			}
		})
	}
	
	// 5. 测试自定义IV
	t.Run("CustomIV", func(t *testing.T) {
		// 创建固定IV
		customIV := []byte("abcdefghijklmnop") // 16字节
		
		// 使用CBC模式和自定义IV
		sm4CBC := sm4.CBC().PKCS7().Base64().WithIV(customIV)
		
		// 加密数据
		plaintext := []byte("使用自定义IV测试SM4")
		ciphertext, err := sm4CBC.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("使用自定义IV加密失败: %v", err)
		}
		
		// 解密数据
		decrypted, err := sm4CBC.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("使用自定义IV解密失败: %v", err)
		}
		
		// 验证结果
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("使用自定义IV加解密结果与原文不匹配，期望: %s, 实际: %s", 
				string(plaintext), string(decrypted))
		}
	})
	
	// 6. 测试不同长度的数据
	t.Run("DifferentLengths", func(t *testing.T) {
		// 准备不同长度的数据
		dataSet := []struct {
			name string
			data []byte
		}{
			{"Empty", []byte{}},
			{"Short", []byte("短数据")},
			{"Block", bytes.Repeat([]byte("A"), 16)}, // 正好一个分组
			{"MultiBlock", bytes.Repeat([]byte("B"), 32)}, // 两个分组
			{"LongData", bytes.Repeat([]byte("长数据测试"), 50)}, // 较长数据
		}
		
		// 创建加密器 - 使用CBC模式
		encryptor := sm4.CBC().PKCS7().Base64()
		
		// 测试每种数据长度
		for _, ds := range dataSet {
			t.Run(ds.name, func(t *testing.T) {
				// 加密
				ciphertext, err := encryptor.Encrypt(ds.data)
				if err != nil {
					t.Fatalf("%s 加密失败: %v", ds.name, err)
				}
				
				// 解密
				decrypted, err := encryptor.Decrypt(ciphertext)
				if err != nil {
					t.Fatalf("%s 解密失败: %v", ds.name, err)
				}
				
				// 验证结果
				if !bytes.Equal(decrypted, ds.data) {
					t.Errorf("%s 加解密结果与原文不匹配", ds.name)
				}
			})
		}
	})
	
	// 7. 测试密钥生成器支持
	t.Run("KeyGenerator", func(t *testing.T) {
		// 创建密钥生成器
		kg := encrypt.NewKeyGenerator()
		
		// 添加SM4密钥生成方法
		sm4Key, err := kg.GenerateRandomBytes(16)
		if err != nil {
			t.Fatalf("生成SM4密钥失败: %v", err)
		}
		
		t.Logf("生成的SM4密钥: %s", sm4Key)
	})
}