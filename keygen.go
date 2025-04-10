package encrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"io"

	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

// KeyGenerator 密钥生成工具
type KeyGenerator struct {
	encodingMode EncodingMode
}

// NewKeyGenerator 创建新的密钥生成器
func NewKeyGenerator() *KeyGenerator {
	return &KeyGenerator{
		encodingMode: EncodingBase64, // 默认使用Base64编码
	}
}

// NoEncoding 设置不使用编码（返回原始字节）
func (kg *KeyGenerator) NoEncoding() *KeyGenerator {
	kg.encodingMode = EncodingNone
	return kg
}

// Base64 设置使用Base64编码
func (kg *KeyGenerator) Base64() *KeyGenerator {
	kg.encodingMode = EncodingBase64
	return kg
}

// Base64Safe 设置使用安全的Base64编码
func (kg *KeyGenerator) Base64Safe() *KeyGenerator {
	kg.encodingMode = EncodingBase64Safe
	return kg
}

// Hex 设置使用十六进制编码
func (kg *KeyGenerator) Hex() *KeyGenerator {
	kg.encodingMode = EncodingHex
	return kg
}

// encodeBytes 根据设置的编码模式对字节数组进行编码
func (kg *KeyGenerator) encodeBytes(data []byte) string {
	switch kg.encodingMode {
	case EncodingNone:
		return string(data) // 不编码，直接返回
	case EncodingBase64:
		return base64.StdEncoding.EncodeToString(data)
	case EncodingBase64Safe:
		return base64.URLEncoding.EncodeToString(data)
	case EncodingHex:
		return hex.EncodeToString(data)
	default:
		return base64.StdEncoding.EncodeToString(data)
	}
}

// GenerateRandomBytes 生成指定长度的随机字节
func (kg *KeyGenerator) GenerateRandomBytes(length int) (string, error) {
	if length <= 0 {
		return "", errors.New("长度必须大于0")
	}

	bytes := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		return "", errors.Wrap(err, "生成随机字节失败")
	}

	return kg.encodeBytes(bytes), nil
}

// GenerateAESKey 生成AES密钥
// size可以是128（16字节）、192（24字节）或256（32字节）
func (kg *KeyGenerator) GenerateAESKey(bits int) (string, error) {
	// 将比特转换为字节
	bytes := bits / 8

	// 验证密钥长度
	if bytes != 16 && bytes != 24 && bytes != 32 {
		return "", errors.New("AES密钥长度必须是128位(16字节)、192位(24字节)或256位(32字节)")
	}

	return kg.GenerateRandomBytes(bytes)
}

// GenerateSM4Key 生成SM4密钥
// SM4使用128位(16字节)固定长度密钥
func (kg *KeyGenerator) GenerateSM4Key() (string, error) {
	// SM4固定使用128位(16字节)密钥
	return kg.GenerateRandomBytes(16)
}

// GenerateDESKey 生成DES密钥 (8字节/64位)
func (kg *KeyGenerator) GenerateDESKey() (string, error) {
	return kg.GenerateRandomBytes(8)
}

// Generate3DESKey 生成3DES密钥 (24字节/192位)
func (kg *KeyGenerator) Generate3DESKey() (string, error) {
	return kg.GenerateRandomBytes(24)
}

// GenerateIV 生成初始化向量
// blockSize是加密算法的块大小（AES是16，DES是8）
func (kg *KeyGenerator) GenerateIV(blockSize int) (string, error) {
	if blockSize <= 0 {
		return "", errors.New("块大小必须大于0")
	}

	return kg.GenerateRandomBytes(blockSize)
}

// GenerateSalt 生成密码哈希用的盐值
// 推荐长度至少16字节
func (kg *KeyGenerator) GenerateSalt(length int) (string, error) {
	if length < 8 {
		return "", errors.New("盐值长度应至少为8字节")
	}

	return kg.GenerateRandomBytes(length)
}

// GenerateRSAKeyPair 生成RSA密钥对
// bits是密钥位数，常用值有2048和4096
func (kg *KeyGenerator) GenerateRSAKeyPair(bits int) (publicKey string, privateKey string, err error) {
	// 验证密钥长度
	if bits < 1024 || bits > 8192 || bits%8 != 0 {
		return "", "", errors.New("RSA密钥大小必须在1024-8192之间，且为8的倍数")
	}

	// 生成RSA密钥对
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", errors.Wrap(err, "生成RSA密钥对失败")
	}

	// 将私钥编码为PKCS#1 DER格式
	privDER := x509.MarshalPKCS1PrivateKey(privKey)

	// 将公钥编码为PKIX DER格式
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", "", errors.Wrap(err, "编码RSA公钥失败")
	}

	// 返回编码结果
	return kg.encodeBytes(pubDER), kg.encodeBytes(privDER), nil
}

// GenerateSM2KeyPair 生成SM2密钥对
func (kg *KeyGenerator) GenerateSM2KeyPair() (publicKey string, privateKey string, err error) {
	// 生成SM2密钥对
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", errors.Wrap(err, "生成SM2密钥对失败")
	}

	// 将私钥编码为PEM格式
	privatePEM, err := x509.WritePrivateKeyToPem(privKey, nil) // 无密码保护
	if err != nil {
		return "", "", errors.Wrap(err, "编码SM2私钥失败")
	}

	// 将公钥编码为PEM格式
	publicPEM, err := x509.WritePublicKeyToPem(&privKey.PublicKey)
	if err != nil {
		return "", "", errors.Wrap(err, "编码SM2公钥失败")
	}

	// 对于SM2，我们直接返回PEM字符串，因为它已经是文本格式
	switch kg.encodingMode {
	case EncodingNone, EncodingBase64, EncodingBase64Safe, EncodingHex:
		// 所有编码模式下，对于SM2都直接返回PEM文本
		return string(publicPEM), string(privatePEM), nil
	default:
		return string(publicPEM), string(privatePEM), nil
	}
}