package tests

import (
	"bytes"
	"testing"
	
	"github.com/sylphbyte/encrypt"
)

// TestSimpleRSA 测试基本RSA功能
func TestSimpleRSA(t *testing.T) {
	// 1. 创建RSA加密器
	rsaEncryptor, err := encrypt.NewRSA()
	if err != nil {
		t.Fatalf("创建RSA加密器失败: %v", err)
	}
	rsaEncryptor = rsaEncryptor.Base64()

	// 2. 生成RSA密钥对
	pubKey, privKey, err := rsaEncryptor.GenerateKeyPair()
	if err != nil {
		t.Fatalf("RSA密钥生成失败: %v", err)
	}
	
	// 设置密钥
	rsaEncryptor = rsaEncryptor.WithPublicKey(pubKey).WithPrivateKey(privKey)
	
	// 3. 测试加密解密
	plaintext := []byte("测试RSA加密功能")
	ciphertext, err := rsaEncryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("RSA加密失败: %v", err)
	}
	
	decrypted, err := rsaEncryptor.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("RSA解密失败: %v", err)
	}
	
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("RSA加解密结果与原文不匹配\n原文: %s\n解密: %s", 
			string(plaintext), string(decrypted))
	}
	
	// 4. 测试签名验证
	data := []byte("需要签名的数据")
	signature, err := rsaEncryptor.Sign(data)
	if err != nil {
		t.Fatalf("RSA签名失败: %v", err)
	}
	
	valid, err := rsaEncryptor.Verify(data, signature)
	if err != nil || !valid {
		t.Fatalf("RSA签名验证失败: %v, 结果: %v", err, valid)
	}
}