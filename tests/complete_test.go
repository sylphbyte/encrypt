package tests

import (
	"bytes"
	"testing"
	
	"github.com/sylphbyte/encrypt"
)

// TestAllSymmetricFeatures 测试所有对称加密功能
func TestAllSymmetricFeatures(t *testing.T) {
	// 1. AES-128 密钥
	key128 := []byte("0123456789abcdef") // 16字节
	plaintext := []byte("测试链式调用API的所有功能")
	
	// 2. 测试不同的模式+填充+编码组合
	modeTests := []struct {
		name     string
		encryptor func() (encrypt.ISymmetric, error)
	}{
		{"AES-CBC-PKCS7-Base64", func() (encrypt.ISymmetric, error) { 
			aes, err := encrypt.NewAES(key128)
			if err != nil {
				return nil, err
			}
			return aes.CBC().PKCS7().Base64(), nil
		}},
		{"AES-ECB-PKCS7-Hex", func() (encrypt.ISymmetric, error) { 
			aes, err := encrypt.NewAES(key128)
			if err != nil {
				return nil, err
			}
			return aes.ECB().PKCS7().Hex(), nil 
		}},
		{"AES-CFB-PKCS7-Base64Safe", func() (encrypt.ISymmetric, error) { 
			aes, err := encrypt.NewAES(key128)
			if err != nil {
				return nil, err
			}
			return aes.CFB().PKCS7().Base64Safe(), nil 
		}},
		{"AES-OFB-ZeroPadding-Hex", func() (encrypt.ISymmetric, error) { 
			aes, err := encrypt.NewAES(key128)
			if err != nil {
				return nil, err
			}
			return aes.OFB().ZeroPadding().Hex(), nil 
		}},
		{"AES-CTR-PKCS7-NoEncoding", func() (encrypt.ISymmetric, error) { 
			aes, err := encrypt.NewAES(key128)
			if err != nil {
				return nil, err
			}
			return aes.CTR().PKCS7().NoEncoding(), nil 
		}},
	}
	
	for _, test := range modeTests {
		t.Run(test.name, func(t *testing.T) {
			encryptor, err := test.encryptor()
			if err != nil {
				t.Fatalf("%s 初始化失败: %v", test.name, err)
			}
			
			// 加密
			ciphertext, err := encryptor.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("%s 加密失败: %v", test.name, err)
			}
			
			// 解密
			decrypted, err := encryptor.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("%s 解密失败: %v", test.name, err)
			}
			
			// 验证结果
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("%s 加解密结果与原文不匹配\n原文: %s\n解密: %s", 
					test.name, string(plaintext), string(decrypted))
			}
		})
	}
	
	// 3. 自定义IV
	iv := []byte("abcdefghijklmnop") // 16字节
	aes, err := encrypt.NewAES(key128)
	if err != nil {
		t.Fatalf("创建AES失败: %v", err)
	}
	encryptorWithIV := aes.CBC().PKCS7().Base64().WithIV(iv)
	ciphertext, err := encryptorWithIV.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("使用自定义IV加密失败: %v", err)
	}
	
	decrypted, err := encryptorWithIV.Decrypt(ciphertext)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("使用自定义IV解密失败: %v", err)
	}
	
	// 4. 使用不同大小的AES密钥
	key192 := []byte("0123456789abcdef01234567") // 24字节
	key256 := []byte("0123456789abcdef0123456789abcdef") // 32字节
	
	// 简单测试192和256位密钥
	aes192, err := encrypt.NewAES(key192)
	if err != nil {
		t.Fatalf("创建AES-192失败: %v", err)
	}
	aes192Enc := aes192.CBC().PKCS7().Base64()
	
	aes256, err := encrypt.NewAES(key256)
	if err != nil {
		t.Fatalf("创建AES-256失败: %v", err)
	}
	aes256Enc := aes256.CBC().PKCS7().Base64()
	
	// 用192位密钥加密
	ciphertext192, err := aes192Enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("AES-192加密失败: %v", err)
	}
	
	// 用256位密钥加密
	ciphertext256, err := aes256Enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("AES-256加密失败: %v", err)
	}
	
	// 使用各自的密钥解密并验证
	decrypted192, err := aes192Enc.Decrypt(ciphertext192)
	if err != nil || !bytes.Equal(decrypted192, plaintext) {
		t.Fatalf("AES-192解密失败: %v", err)
	}
	
	decrypted256, err := aes256Enc.Decrypt(ciphertext256)
	if err != nil || !bytes.Equal(decrypted256, plaintext) {
		t.Fatalf("AES-256解密失败: %v", err)
	}
	
	// 5. 使用DES和3DES
	desKey := []byte("01234567") // 8字节
	tripleDesKey := []byte("01234567890123456789abcd") // 24字节
	
	desEncryptor, err := encrypt.NewDES(desKey)
	if err != nil {
		t.Fatalf("创建DES失败: %v", err)
	}
	desEnc := desEncryptor.CBC().PKCS7().Base64()
	
	tripleDesEncryptor, err := encrypt.New3DES(tripleDesKey)
	if err != nil {
		t.Fatalf("创建3DES失败: %v", err)
	}
	tripleDesEnc := tripleDesEncryptor.CBC().PKCS7().Base64()
	
	// DES加密/解密
	desCiphertext, err := desEnc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("DES加密失败: %v", err)
	}
	
	desDecrypted, err := desEnc.Decrypt(desCiphertext)
	if err != nil || !bytes.Equal(desDecrypted, plaintext) {
		t.Fatalf("DES解密失败: %v", err)
	}
	
	// 3DES加密/解密
	tripleDesCiphertext, err := tripleDesEnc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("3DES加密失败: %v", err)
	}
	
	tripleDesDecrypted, err := tripleDesEnc.Decrypt(tripleDesCiphertext)
	if err != nil || !bytes.Equal(tripleDesDecrypted, plaintext) {
		t.Fatalf("3DES解密失败: %v", err)
	}
}

// TestRSAFeatures 测试RSA功能
func TestRSAFeatures(t *testing.T) {
	// 1. 创建RSA加密器
	rsaEncryptor, err := encrypt.NewRSA()
	if err != nil {
		t.Fatalf("创建RSA失败: %v", err)
	}
	rsaEncryptor = rsaEncryptor.WithKeySize(2048).Base64()
	
	// 2. 生成密钥对
	pubKey, privKey, err := rsaEncryptor.GenerateKeyPair()
	if err != nil {
		t.Fatalf("生成RSA密钥对失败: %v", err)
	}
	
	// 3. 加密/解密数据
	plaintext := []byte("RSA测试数据")
	
	// 使用公钥加密
	rsaEncryptor = rsaEncryptor.WithPublicKey(pubKey)
	ciphertext, err := rsaEncryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("RSA加密失败: %v", err)
	}
	
	// 使用私钥解密
	rsaEncryptor = rsaEncryptor.WithPrivateKey(privKey)
	decrypted, err := rsaEncryptor.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("RSA解密失败: %v", err)
	}
	
	// 验证结果
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("RSA解密结果与原文不匹配")
	}
	
	// 4. 测试签名和验证
	signature, err := rsaEncryptor.Sign(plaintext)
	if err != nil {
		t.Fatalf("RSA签名失败: %v", err)
	}
	
	valid, err := rsaEncryptor.Verify(plaintext, signature)
	if err != nil {
		t.Fatalf("RSA验证签名出错: %v", err)
	}
	
	if !valid {
		t.Fatalf("RSA签名验证失败")
	}
	
	// 5. 测试使用现有密钥创建新的加密器
	newRsaEncryptor, err := encrypt.NewRSA()
	if err != nil {
		t.Fatalf("创建新RSA失败: %v", err)
	}
	newRsaEncryptor = newRsaEncryptor.WithPublicKey(pubKey).WithPrivateKey(privKey).Base64()
	
	ciphertext2, err := newRsaEncryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("使用现有密钥的RSA加密失败: %v", err)
	}
	
	decrypted2, err := newRsaEncryptor.Decrypt(ciphertext2)
	if err != nil || !bytes.Equal(decrypted2, plaintext) {
		t.Fatalf("使用现有密钥的RSA解密失败: %v", err)
	}
}

// TestSM2Features 测试SM2功能
func TestSM2Features(t *testing.T) {
	// 1. 创建SM2加密器
	sm2Encryptor, err := encrypt.NewSM2()
	if err != nil {
		t.Fatalf("创建SM2失败: %v", err)
	}
	sm2Encryptor = sm2Encryptor.Base64()
	
	// 2. 生成密钥对
	pubKey, privKey, err := sm2Encryptor.GenerateKeyPair()
	if err != nil {
		t.Fatalf("SM2密钥生成失败: %v", err)
	}
	
	t.Logf("SM2公钥长度: %d, 私钥长度: %d", len(pubKey), len(privKey))
	
	// 3. 测试明文
	plaintext := []byte("这是SM2加密测试数据")
	
	// 4. 测试加密和解密
	// 使用公钥加密
	sm2EncryptorPub := sm2Encryptor.WithPublicKey(pubKey)
	ciphertext, err := sm2EncryptorPub.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("SM2加密失败: %v", err)
	}
	
	// 使用私钥解密
	sm2EncryptorPriv := sm2Encryptor.WithPrivateKey(privKey)
	decrypted, err := sm2EncryptorPriv.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("SM2解密失败: %v", err)
	}
	
	// 验证结果
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("SM2解密结果与原文不匹配")
	}
	
	// 5. 测试签名和验证
	// 使用完整的加密器（包含公私钥）
	completeSM2 := sm2Encryptor.WithPrivateKey(privKey).WithPublicKey(pubKey)
	
	// 签名
	signature, err := completeSM2.Sign(plaintext)
	if err != nil {
		t.Fatalf("SM2签名失败: %v", err)
	}
	
	// 验证签名
	valid, err := completeSM2.Verify(plaintext, signature)
	if err != nil {
		t.Fatalf("SM2验证签名出错: %v", err)
	}
	
	if !valid {
		t.Fatalf("SM2签名验证失败")
	}
	
	// 6. 测试不同编码格式
	encodingTests := []struct {
		name     string
		encoding func(encrypt.IAsymmetric) encrypt.IAsymmetric
	}{
		{"Base64", func(e encrypt.IAsymmetric) encrypt.IAsymmetric { return e.Base64() }},
		{"Base64Safe", func(e encrypt.IAsymmetric) encrypt.IAsymmetric { return e.Base64Safe() }},
		{"Hex", func(e encrypt.IAsymmetric) encrypt.IAsymmetric { return e.Hex() }},
		{"NoEncoding", func(e encrypt.IAsymmetric) encrypt.IAsymmetric { return e.NoEncoding() }},
	}
	
	for _, test := range encodingTests {
		t.Run(test.name, func(t *testing.T) {
			// 创建新的SM2加密器，并设置编码格式
			newSM2, _ := encrypt.NewSM2()
			newSM2 = test.encoding(newSM2.(encrypt.IAsymmetric)).(encrypt.IAsymmetric)
			newSM2 = newSM2.WithPublicKey(pubKey).WithPrivateKey(privKey)
			
			// 加密
			ciphertext, err := newSM2.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("%s 加密失败: %v", test.name, err)
			}
			
			// 解密
			decrypted, err := newSM2.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("%s 解密失败: %v", test.name, err)
			}
			
			// 验证结果
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("%s 解密结果与原文不匹配", test.name)
			}
			
			// 签名
			signature, err := newSM2.Sign(plaintext)
			if err != nil {
				t.Fatalf("%s 签名失败: %v", test.name, err)
			}
			
			// 验证签名
			valid, err := newSM2.Verify(plaintext, signature)
			if err != nil {
				t.Fatalf("%s 验证签名出错: %v", test.name, err)
			}
			
			if !valid {
				t.Fatalf("%s 签名验证失败", test.name)
			}
		})
	}
	
	// 7. 测试自定义UID
	customUID := []byte("custom-uid-for-sm2-test")
	sm2WithUID := sm2Encryptor.WithPublicKey(pubKey).WithPrivateKey(privKey).(encrypt.IAsymmetric).WithUID(customUID)
	
	// 使用自定义UID签名
	signatureWithUID, err := sm2WithUID.Sign(plaintext)
	if err != nil {
		t.Fatalf("使用自定义UID的SM2签名失败: %v", err)
	}
	
	// 使用自定义UID验证签名
	validWithUID, err := sm2WithUID.Verify(plaintext, signatureWithUID)
	if err != nil {
		t.Fatalf("使用自定义UID的SM2验证签名出错: %v", err)
	}
	
	if !validWithUID {
		t.Fatalf("使用自定义UID的SM2签名验证失败")
	}
}

// 去掉了TestFactoryFunctions测试函数，因为我们的重构不包含这个函数