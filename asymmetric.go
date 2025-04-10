package encrypt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	
	"github.com/pkg/errors"
)

// AsymmetricBase 非对称加密基础结构
type AsymmetricBase struct {
	algorithm    Algorithm
	encodingMode EncodingMode
	encoding     Encoding
}

// RSAEncryptor RSA加密实现
type RSAEncryptor struct {
	AsymmetricBase
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keySize    int
}

// Algorithm 获取算法类型
func (r *RSAEncryptor) Algorithm() Algorithm {
	return r.algorithm
}

// WithKeySize 设置RSA密钥大小
func (r *RSAEncryptor) WithKeySize(size int) IAsymmetric {
	// 验证密钥大小是否合法
	if size < 1024 || size > 4096 || size%8 != 0 {
		panic("RSA密钥大小必须在1024-4096之间，且为8的倍数")
	}
	r.keySize = size
	return r
}

// WithPublicKey 设置公钥
func (r *RSAEncryptor) WithPublicKey(publicKeyData []byte) IAsymmetric {
	// 尝试解析PEM格式的公钥
	block, _ := pem.Decode(publicKeyData)
	if block == nil {
		panic("无法解析PEM编码的公钥")
	}
	
	var err error
	var pubKey interface{}
	
	// 尝试解析公钥
	switch block.Type {
	case "RSA PUBLIC KEY":
		// PKCS#1格式
		pubKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			panic(fmt.Sprintf("解析PKCS1公钥失败: %s", err))
		}
		r.publicKey = pubKey.(*rsa.PublicKey)
	case "PUBLIC KEY":
		// PKCS#8格式
		pubKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			panic(fmt.Sprintf("解析PKIX公钥失败: %s", err))
		}
		var ok bool
		r.publicKey, ok = pubKey.(*rsa.PublicKey)
		if !ok {
			panic("提供的不是RSA公钥")
		}
	default:
		panic(fmt.Sprintf("不支持的密钥类型: %s", block.Type))
	}
	
	return r
}

// WithPrivateKey 设置私钥
func (r *RSAEncryptor) WithPrivateKey(privateKeyData []byte) IAsymmetric {
	// 尝试解析PEM格式的私钥
	block, _ := pem.Decode(privateKeyData)
	if block == nil {
		panic("无法解析PEM编码的私钥")
	}
	
	var err error
	
	// 尝试解析私钥
	switch block.Type {
	case "RSA PRIVATE KEY":
		// PKCS#1格式
		r.privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			panic(fmt.Sprintf("解析PKCS1私钥失败: %s", err))
		}
	case "PRIVATE KEY":
		// PKCS#8格式
		privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			panic(fmt.Sprintf("解析PKCS8私钥失败: %s", err))
		}
		var ok bool
		r.privateKey, ok = privKey.(*rsa.PrivateKey)
		if !ok {
			panic("提供的不是RSA私钥")
		}
	default:
		panic(fmt.Sprintf("不支持的密钥类型: %s", block.Type))
	}
	
	// 同时设置对应的公钥
	if r.privateKey != nil {
		r.publicKey = &r.privateKey.PublicKey
	}
	
	return r
}

// GenerateKeyPair 生成RSA密钥对
func (r *RSAEncryptor) GenerateKeyPair() ([]byte, []byte, error) {
	// 如果未设置密钥大小，使用默认值
	if r.keySize == 0 {
		r.keySize = 2048
	}
	
	// 生成密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, r.keySize)
	if err != nil {
		return nil, nil, errors.Wrap(err, "生成RSA密钥对失败")
	}
	
	// 保存密钥用于后续操作
	r.privateKey = privateKey
	r.publicKey = &privateKey.PublicKey
	
	// 将私钥编码为PEM格式
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	
	// 将公钥编码为PEM格式
	publicKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	
	return publicKeyPEM, privateKeyPEM, nil
}

// NoEncoding 设置无编码
func (r *RSAEncryptor) NoEncoding() IAsymmetric {
	r.encoding = NoEncoding
	r.encodingMode = EncodingNone
	return r
}

// WithUID RSA不需要UID，此方法仅为满足接口要求
func (r *RSAEncryptor) WithUID(uid []byte) IAsymmetric {
	// RSA不使用UID，此方法不做任何事情
	return r
}

// Base64 设置Base64编码
func (r *RSAEncryptor) Base64() IAsymmetric {
	r.encoding = Base64Encoding
	r.encodingMode = EncodingBase64
	return r
}

// Base64Safe 设置安全的Base64编码
func (r *RSAEncryptor) Base64Safe() IAsymmetric {
	r.encoding = Base64Safe
	r.encodingMode = EncodingBase64Safe
	return r
}

// Hex 设置十六进制编码
func (r *RSAEncryptor) Hex() IAsymmetric {
	r.encoding = HexEncoding
	r.encodingMode = EncodingHex
	return r
}

// Encrypt 使用RSA公钥加密数据
func (r *RSAEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	if r.publicKey == nil {
		return nil, errors.New("未设置公钥")
	}
	
	// RSA加密
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, plaintext)
	if err != nil {
		return nil, errors.Wrap(err, "RSA加密失败")
	}
	
	// 编码处理
	return r.encoding.Encode(ciphertext)
}

// Decrypt 使用RSA私钥解密数据
func (r *RSAEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	if r.privateKey == nil {
		return nil, errors.New("未设置私钥")
	}
	
	// 解码处理
	decoded, err := r.encoding.Decode(ciphertext)
	if err != nil {
		return nil, errors.Wrap(err, "解码失败")
	}
	
	// RSA解密
	return rsa.DecryptPKCS1v15(rand.Reader, r.privateKey, decoded)
}

// Sign 使用RSA私钥签名数据
func (r *RSAEncryptor) Sign(data []byte) ([]byte, error) {
	if r.privateKey == nil {
		return nil, errors.New("未设置私钥")
	}
	
	// 计算数据哈希
	hash := sha256.Sum256(data)
	
	// 签名数据
	signature, err := rsa.SignPKCS1v15(rand.Reader, r.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, errors.Wrap(err, "RSA签名失败")
	}
	
	// 编码处理
	return r.encoding.Encode(signature)
}

// Verify 验证RSA签名
func (r *RSAEncryptor) Verify(data []byte, signature []byte) (bool, error) {
	if r.publicKey == nil {
		return false, errors.New("未设置公钥")
	}
	
	// 解码签名
	decoded, err := r.encoding.Decode(signature)
	if err != nil {
		return false, errors.Wrap(err, "解码签名失败")
	}
	
	// 计算数据哈希
	hash := sha256.Sum256(data)
	
	// 验证签名
	err = rsa.VerifyPKCS1v15(r.publicKey, crypto.SHA256, hash[:], decoded)
	if err != nil {
		return false, nil // 签名验证失败，但不是错误
	}
	
	return true, nil
}

// 以下是SM2Encryptor的定义，实现在sm2.go文件中

// SM2Encryptor SM2加密实现
type SM2Encryptor struct {
	AsymmetricBase
	privateKey interface{} // 实际类型在sm2.go中使用sm2.PrivateKey
	publicKey  interface{} // 实际类型在sm2.go中使用sm2.PublicKey
	uid        []byte     // SM2签名需要的用户标识
}