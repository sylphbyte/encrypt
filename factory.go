package encrypt

import (
	"crypto/aes"
	"crypto/des"
	"crypto/rand"
	"io"
	
	"github.com/pkg/errors"
)

// NewAES 创建新的AES加密器
func NewAES(key []byte) (ISymmetric, error) {
	// 验证密钥长度
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("AES密钥长度必须是16、24或32字节")
	}
	
	// 从对象池获取实例
	encryptor := EncryptorPools.AES.Get().(*AESEncryptor)
	
	// 重置/设置密钥
	if encryptor.key == nil || len(encryptor.key) != len(key) {
		encryptor.key = make([]byte, len(key))
	}
	copy(encryptor.key, key)
	encryptor.algorithm = AlgorithmAES
	
	// 设置默认值
	encryptor.blockMode = NewCBCMode(nil) // 默认使用CBC模式
	encryptor.padding = DefaultPKCS7Padding
	encryptor.encoding = Base64Encoding
	
	// 生成随机IV
	blockSize := aes.BlockSize
	if encryptor.iv == nil || len(encryptor.iv) != blockSize {
		encryptor.iv = make([]byte, blockSize)
	}
	if _, err := io.ReadFull(rand.Reader, encryptor.iv); err != nil {
		return nil, errors.Wrap(err, "生成随机IV失败")
	}
	
	return encryptor, nil
}

// NewDES 创建新的DES加密器
func NewDES(key []byte) (ISymmetric, error) {
	// 验证密钥长度
	if len(key) != 8 {
		return nil, errors.New("DES密钥长度必须是8字节")
	}
	
	// 从对象池获取实例
	encryptor := EncryptorPools.DES.Get().(*DESEncryptor)
	
	// 重置/设置密钥
	if encryptor.key == nil || len(encryptor.key) != len(key) {
		encryptor.key = make([]byte, len(key))
	}
	copy(encryptor.key, key)
	encryptor.algorithm = AlgorithmDES
	
	// 设置默认值
	encryptor.blockMode = NewCBCMode(nil) // 默认使用CBC模式
	encryptor.padding = DefaultPKCS7Padding
	encryptor.encoding = Base64Encoding
	
	// 生成随机IV
	blockSize := des.BlockSize
	if encryptor.iv == nil || len(encryptor.iv) != blockSize {
		encryptor.iv = make([]byte, blockSize)
	}
	if _, err := io.ReadFull(rand.Reader, encryptor.iv); err != nil {
		return nil, errors.Wrap(err, "生成随机IV失败")
	}
	
	return encryptor, nil
}

// New3DES 创建新的3DES加密器
func New3DES(key []byte) (ISymmetric, error) {
	// 验证密钥长度
	if len(key) != 24 {
		return nil, errors.New("3DES密钥长度必须是24字节")
	}
	
	// 从对象池获取实例
	encryptor := EncryptorPools.TripleDES.Get().(*TripleDESEncryptor)
	
	// 重置/设置密钥
	if encryptor.key == nil || len(encryptor.key) != len(key) {
		encryptor.key = make([]byte, len(key))
	}
	copy(encryptor.key, key)
	encryptor.algorithm = Algorithm3DES
	
	// 设置默认值
	encryptor.blockMode = NewCBCMode(nil) // 默认使用CBC模式
	encryptor.padding = DefaultPKCS7Padding
	encryptor.encoding = Base64Encoding
	
	// 生成随机IV
	blockSize := des.BlockSize
	if encryptor.iv == nil || len(encryptor.iv) != blockSize {
		encryptor.iv = make([]byte, blockSize)
	}
	if _, err := io.ReadFull(rand.Reader, encryptor.iv); err != nil {
		return nil, errors.Wrap(err, "生成随机IV失败")
	}
	
	return encryptor, nil
}

// NewRSA 创建新的RSA加密器
func NewRSA() (IAsymmetric, error) {
	// 从对象池获取实例
	encryptor := EncryptorPools.RSA.Get().(*RSAEncryptor)
	
	// 重置成默认状态
	encryptor.Reset()
	
	return encryptor, nil
}

// NewSM2 创建新的SM2加密器
func NewSM2() (IAsymmetric, error) {
	// 从对象池获取实例
	encryptor := EncryptorPools.SM2.Get().(*SM2Encryptor)
	
	// 重置成默认状态
	encryptor.Reset()
	
	return encryptor, nil
}

// NewSM4 创建新的SM4加密器
func NewSM4(key []byte) (ISymmetric, error) {
	// 验证密钥长度
	if len(key) != 16 {
		return nil, errors.New("SM4密钥长度必须是16字节")
	}
	
	// 从对象池获取实例
	encryptor := EncryptorPools.SM4.Get().(*SM4Encryptor)
	
	// 重置/设置密钥
	if encryptor.key == nil || len(encryptor.key) != len(key) {
		encryptor.key = make([]byte, len(key))
	}
	copy(encryptor.key, key)
	encryptor.algorithm = AlgorithmSM4
	
	// 设置默认值
	encryptor.blockMode = ModeCBC // 默认使用CBC模式
	encryptor.padding = DefaultPKCS7Padding
	encryptor.encoding = Base64Encoding
	encryptor.encodingMode = EncodingBase64
	
	// 生成随机IV
	if encryptor.iv == nil || len(encryptor.iv) != 16 {
		encryptor.iv = make([]byte, 16) // SM4块大小为16字节
	}
	if _, err := io.ReadFull(rand.Reader, encryptor.iv); err != nil {
		return nil, errors.Wrap(err, "生成随机IV失败")
	}
	
	return encryptor, nil
}