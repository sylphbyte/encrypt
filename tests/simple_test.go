package tests

import (
	"testing"
	
	"github.com/sylphbyte/encrypt"
)

func TestAESEncryption(t *testing.T) {
	// 创建AES加密器
	key := []byte("1234567890123456") // 16字节的AES-128密钥
	aes, err := encrypt.NewAES(key)
	if err != nil {
		t.Fatalf("创建AES加密器失败: %v", err)
	}
	
	// 设置加密参数 - 使用链式调用
	aes = aes.CBC().PKCS7().Base64()
	
	// 原始数据
	plaintext := []byte("这是要加密的数据")
	
	// 加密
	ciphertext, err := aes.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	
	t.Logf("加密结果: %s", ciphertext)
	
	// 解密
	decrypted, err := aes.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	
	// 验证
	if string(decrypted) != string(plaintext) {
		t.Fatalf("解密结果与原文不匹配:\n原文: %s\n解密: %s", plaintext, decrypted)
	}
	
	t.Logf("解密结果: %s", decrypted)
}

func TestDESEncryption(t *testing.T) {
	// 创建DES加密器
	key := []byte("12345678") // 8字节的DES密钥
	des, err := encrypt.NewDES(key)
	if err != nil {
		t.Fatalf("创建DES加密器失败: %v", err)
	}
	
	// 设置加密参数 - 使用链式调用
	des = des.CBC().PKCS7().Base64()
	
	// 原始数据
	plaintext := []byte("DES测试数据")
	
	// 加密
	ciphertext, err := des.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	
	t.Logf("加密结果: %s", ciphertext)
	
	// 解密
	decrypted, err := des.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	
	// 验证
	if string(decrypted) != string(plaintext) {
		t.Fatalf("解密结果与原文不匹配:\n原文: %s\n解密: %s", plaintext, decrypted)
	}
	
	t.Logf("解密结果: %s", decrypted)
}

func TestRSAEncryption(t *testing.T) {
	// 创建RSA加密器
	rsa, err := encrypt.NewRSA()
	if err != nil {
		t.Fatalf("创建RSA加密器失败: %v", err)
	}
	
	// 生成密钥对
	pubKey, privKey, err := rsa.GenerateKeyPair()
	if err != nil {
		t.Fatalf("生成RSA密钥对失败: %v", err)
	}
	
	t.Logf("RSA公钥长度: %d 字节", len(pubKey))
	t.Logf("RSA私钥长度: %d 字节", len(privKey))
	
	// 设置编码
	rsa = rsa.Base64()
	
	// 原始数据
	plaintext := []byte("RSA测试数据")
	
	// 使用公钥加密
	rsa = rsa.WithPublicKey(pubKey)
	ciphertext, err := rsa.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("RSA加密失败: %v", err)
	}
	
	t.Logf("RSA加密结果: %s", ciphertext)
	
	// 使用私钥解密
	rsa = rsa.WithPrivateKey(privKey)
	decrypted, err := rsa.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("RSA解密失败: %v", err)
	}
	
	// 验证
	if string(decrypted) != string(plaintext) {
		t.Fatalf("RSA解密结果与原文不匹配:\n原文: %s\n解密: %s", plaintext, decrypted)
	}
	
	t.Logf("RSA解密结果: %s", decrypted)
	
	// 测试签名和验证
	signature, err := rsa.Sign(plaintext)
	if err != nil {
		t.Fatalf("RSA签名失败: %v", err)
	}
	
	t.Logf("RSA签名结果: %s", signature)
	
	// 验证签名
	valid, err := rsa.Verify(plaintext, signature)
	if err != nil {
		t.Fatalf("RSA验证签名出错: %v", err)
	}
	
	if !valid {
		t.Fatalf("RSA签名验证失败")
	}
	
	t.Logf("RSA签名验证成功")
}