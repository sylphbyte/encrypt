package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"io"
	
	"github.com/pkg/errors"
)

// SymmetricBase 对称加密基础结构
// 只包含链式调用所需的成员
type SymmetricBase struct {
	key          []byte
	algorithm    Algorithm
	mode         Mode
	paddingMode  PaddingMode
	encodingMode EncodingMode
	iv           []byte
}

// SymmetricEncryptor 对称加密器，采用组合方式
// 通过组合多个组件实现算法，降低耦合性
type SymmetricEncryptor struct {
	key          []byte
	algorithm    Algorithm
	blockMode    BlockMode
	padding      Padding
	encoding     Encoding
	iv           []byte
}

// Encrypt 加密数据
func (s *SymmetricEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	// 1. 创建加密块
	var block cipher.Block
	var err error
	
	switch s.algorithm {
	case AlgorithmAES:
		block, err = aes.NewCipher(s.key)
	case AlgorithmDES:
		block, err = des.NewCipher(s.key)
	case Algorithm3DES:
		block, err = des.NewTripleDESCipher(s.key)
	default:
		return nil, errors.New("不支持的加密算法")
	}
	
	if err != nil {
		return nil, errors.Wrap(err, "创建密码块失败")
	}
	
	// 2. 准备IV (如果需要)
	if s.blockMode.NeedsIV() {
		blockSize := block.BlockSize()
		if s.iv == nil {
			// 生成随机IV
			s.iv = make([]byte, blockSize)
			if _, err := io.ReadFull(rand.Reader, s.iv); err != nil {
				return nil, errors.Wrap(err, "生成随机IV失败")
			}
		} else if len(s.iv) != blockSize {
			return nil, errors.New("IV长度不正确")
		}
	}
	
	// 3. 填充数据
	paddedData, err := s.padding.Pad(plaintext, block.BlockSize())
	if err != nil {
		return nil, errors.Wrap(err, "填充数据失败")
	}
	
	// 4. 加密数据
	encrypted, err := s.blockMode.Encrypt(block, paddedData)
	if err != nil {
		return nil, errors.Wrap(err, "加密数据失败")
	}
	
	// 5. 编码数据
	return s.encoding.Encode(encrypted)
}

// Decrypt 解密数据
func (s *SymmetricEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	// 1. 解码数据
	decoded, err := s.encoding.Decode(ciphertext)
	if err != nil {
		return nil, errors.Wrap(err, "解码数据失败")
	}
	
	// 2. 创建加密块
	var block cipher.Block
	
	switch s.algorithm {
	case AlgorithmAES:
		block, err = aes.NewCipher(s.key)
	case AlgorithmDES:
		block, err = des.NewCipher(s.key)
	case Algorithm3DES:
		block, err = des.NewTripleDESCipher(s.key)
	default:
		return nil, errors.New("不支持的加密算法")
	}
	
	if err != nil {
		return nil, errors.Wrap(err, "创建密码块失败")
	}
	
	// 3. 解密数据
	decrypted, err := s.blockMode.Decrypt(block, decoded)
	if err != nil {
		return nil, errors.Wrap(err, "解密数据失败")
	}
	
	// 4. 去除填充
	return s.padding.Unpad(decrypted, block.BlockSize())
}

// AESEncryptor AES加密实现
type AESEncryptor struct {
	SymmetricEncryptor
}

// DESEncryptor DES加密实现 
type DESEncryptor struct {
	SymmetricEncryptor
}

// TripleDESEncryptor 3DES加密实现
type TripleDESEncryptor struct {
	SymmetricEncryptor
}