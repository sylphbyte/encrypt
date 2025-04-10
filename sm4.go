package encrypt

import (
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm4"
)

// SM4Encryptor SM4对称加密实现
type SM4Encryptor struct {
	key       []byte
	iv        []byte
	blockMode Mode
	padding   Padding
	algorithm Algorithm

	encoding     Encoding
	encodingMode EncodingMode
}

// Algorithm 获取算法类型
func (s *SM4Encryptor) Algorithm() Algorithm {
	return s.algorithm
}

// GetKey 获取密钥
func (s *SM4Encryptor) GetKey() []byte {
	return s.key
}

// GetIV 获取初始化向量
func (s *SM4Encryptor) GetIV() []byte {
	return s.iv
}

// ECB 设置ECB工作模式
func (s *SM4Encryptor) ECB() ISymmetric {
	s.blockMode = ModeECB
	return s
}

// CBC 设置CBC工作模式
func (s *SM4Encryptor) CBC() ISymmetric {
	s.blockMode = ModeCBC
	return s
}

// CFB 设置CFB工作模式
func (s *SM4Encryptor) CFB() ISymmetric {
	s.blockMode = ModeCFB
	return s
}

// OFB 设置OFB工作模式
func (s *SM4Encryptor) OFB() ISymmetric {
	s.blockMode = ModeOFB
	return s
}

// CTR 设置CTR工作模式
func (s *SM4Encryptor) CTR() ISymmetric {
	s.blockMode = ModeCTR
	return s
}

// GCM 设置GCM工作模式
func (s *SM4Encryptor) GCM() ISymmetric {
	s.blockMode = ModeGCM
	return s
}

// NoPadding 设置无填充模式
func (s *SM4Encryptor) NoPadding() ISymmetric {
	s.padding = DefaultNoPadding
	return s
}

// PKCS7 设置PKCS7填充模式
func (s *SM4Encryptor) PKCS7() ISymmetric {
	s.padding = DefaultPKCS7Padding
	return s
}

// ZeroPadding 设置零填充模式
func (s *SM4Encryptor) ZeroPadding() ISymmetric {
	s.padding = DefaultZeroPadding
	return s
}

// NoEncoding 设置无编码
func (s *SM4Encryptor) NoEncoding() ISymmetric {
	s.encoding = NoEncoding
	s.encodingMode = EncodingNone
	return s
}

// Base64 设置Base64编码
func (s *SM4Encryptor) Base64() ISymmetric {
	s.encoding = Base64Encoding
	s.encodingMode = EncodingBase64
	return s
}

// Base64Safe 设置安全的Base64编码
func (s *SM4Encryptor) Base64Safe() ISymmetric {
	s.encoding = Base64Safe
	s.encodingMode = EncodingBase64Safe
	return s
}

// Hex 设置十六进制编码
func (s *SM4Encryptor) Hex() ISymmetric {
	s.encoding = HexEncoding
	s.encodingMode = EncodingHex
	return s
}

// WithIV 设置初始化向量
func (s *SM4Encryptor) WithIV(iv []byte) ISymmetric {
	if len(iv) != sm4.BlockSize {
		panic("SM4 IV长度必须是16字节")
	}
	s.iv = make([]byte, len(iv))
	copy(s.iv, iv)
	return s
}

// needsPadding 判断指定的模式是否需要填充
func (s *SM4Encryptor) needsPadding() bool {
	// 只有ECB和CBC模式需要填充
	return s.blockMode == ModeECB || s.blockMode == ModeCBC
}

// Encrypt SM4加密
func (s *SM4Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	// 创建SM4块
	block, err := sm4.NewCipher(s.key)
	if err != nil {
		return nil, errors.Wrap(err, "创建SM4块失败")
	}

	// 根据模式决定是否需要填充
	var processedText []byte
	if s.needsPadding() {
		// 对明文进行填充
		processedText, err = s.padding.Pad(plaintext, block.BlockSize())
		if err != nil {
			return nil, errors.Wrap(err, "填充数据失败")
		}
	} else {
		// 流模式不需要填充
		processedText = plaintext
	}

	// 根据不同模式进行加密
	var encrypted []byte
	switch s.blockMode {
	case ModeECB:
		encrypted = make([]byte, len(processedText))
		// SM4-ECB模式加密
		for bs, be := 0, block.BlockSize(); bs < len(processedText); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
			block.Encrypt(encrypted[bs:be], processedText[bs:be])
		}

	case ModeCBC:
		// 确保IV存在
		if s.iv == nil {
			s.iv = make([]byte, block.BlockSize())
			if _, err := io.ReadFull(rand.Reader, s.iv); err != nil {
				return nil, errors.Wrap(err, "生成随机IV失败")
			}
		}

		encrypted = make([]byte, len(processedText))
		// SM4-CBC模式加密
		mode := cipher.NewCBCEncrypter(block, s.iv)
		mode.CryptBlocks(encrypted, processedText)

	case ModeCFB:
		// 确保IV存在
		if s.iv == nil {
			s.iv = make([]byte, block.BlockSize())
			if _, err := io.ReadFull(rand.Reader, s.iv); err != nil {
				return nil, errors.Wrap(err, "生成随机IV失败")
			}
		}

		encrypted = make([]byte, len(processedText))
		// SM4-CFB模式加密
		mode := cipher.NewCFBEncrypter(block, s.iv)
		mode.XORKeyStream(encrypted, processedText)

	case ModeOFB:
		// 确保IV存在
		if s.iv == nil {
			s.iv = make([]byte, block.BlockSize())
			if _, err := io.ReadFull(rand.Reader, s.iv); err != nil {
				return nil, errors.Wrap(err, "生成随机IV失败")
			}
		}

		encrypted = make([]byte, len(processedText))
		// SM4-OFB模式加密
		mode := cipher.NewOFB(block, s.iv)
		mode.XORKeyStream(encrypted, processedText)

	case ModeCTR:
		// 确保IV存在
		if s.iv == nil {
			s.iv = make([]byte, block.BlockSize())
			if _, err := io.ReadFull(rand.Reader, s.iv); err != nil {
				return nil, errors.Wrap(err, "生成随机IV失败")
			}
		}

		encrypted = make([]byte, len(processedText))
		// SM4-CTR模式加密
		mode := cipher.NewCTR(block, s.iv)
		mode.XORKeyStream(encrypted, processedText)

	case ModeGCM:
		// GCM模式通常不需要额外填充
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, errors.Wrap(err, "创建GCM模式失败")
		}

		// 生成随机nonce（与IV类似）
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, errors.Wrap(err, "生成GCM nonce失败")
		}

		// 对原始明文进行加密（不是填充后的）
		encrypted = gcm.Seal(nonce, nonce, processedText, nil)

	default:
		return nil, errors.New("不支持的工作模式")
	}

	// 对加密结果进行编码
	return s.encoding.Encode(encrypted)
}

// Decrypt SM4解密
func (s *SM4Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	// 解码处理
	decoded, err := s.encoding.Decode(ciphertext)
	if err != nil {
		return nil, errors.Wrap(err, "解码失败")
	}

	// 创建SM4块
	block, err := sm4.NewCipher(s.key)
	if err != nil {
		return nil, errors.Wrap(err, "创建SM4块失败")
	}

	// 根据不同模式进行解密
	var decrypted []byte
	switch s.blockMode {
	case ModeECB:
		decrypted = make([]byte, len(decoded))
		// SM4-ECB模式解密
		for bs, be := 0, block.BlockSize(); bs < len(decoded); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
			block.Decrypt(decrypted[bs:be], decoded[bs:be])
		}

		// 移除填充
		return s.padding.Unpad(decrypted, block.BlockSize())

	case ModeCBC:
		// 检查IV
		if s.iv == nil || len(s.iv) != block.BlockSize() {
			return nil, errors.New("CBC模式需要正确的IV")
		}

		decrypted = make([]byte, len(decoded))
		// SM4-CBC模式解密
		mode := cipher.NewCBCDecrypter(block, s.iv)
		mode.CryptBlocks(decrypted, decoded)

		// 移除填充
		return s.padding.Unpad(decrypted, block.BlockSize())

	case ModeCFB:
		// 检查IV
		if s.iv == nil || len(s.iv) != block.BlockSize() {
			return nil, errors.New("CFB模式需要正确的IV")
		}

		decrypted = make([]byte, len(decoded))
		// SM4-CFB模式解密
		mode := cipher.NewCFBDecrypter(block, s.iv)
		mode.XORKeyStream(decrypted, decoded)

		// 流模式不需要去除填充
		return decrypted, nil

	case ModeOFB:
		// 检查IV
		if s.iv == nil || len(s.iv) != block.BlockSize() {
			return nil, errors.New("OFB模式需要正确的IV")
		}

		decrypted = make([]byte, len(decoded))
		// SM4-OFB模式解密
		mode := cipher.NewOFB(block, s.iv)
		mode.XORKeyStream(decrypted, decoded)

		// 流模式不需要去除填充
		return decrypted, nil

	case ModeCTR:
		// 检查IV
		if s.iv == nil || len(s.iv) != block.BlockSize() {
			return nil, errors.New("CTR模式需要正确的IV")
		}

		decrypted = make([]byte, len(decoded))
		// SM4-CTR模式解密
		mode := cipher.NewCTR(block, s.iv)
		mode.XORKeyStream(decrypted, decoded)

		// 流模式不需要去除填充
		return decrypted, nil

	case ModeGCM:
		// GCM模式
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, errors.Wrap(err, "创建GCM模式失败")
		}

		// 提取nonce
		nonceSize := gcm.NonceSize()
		if len(decoded) < nonceSize {
			return nil, errors.New("密文长度小于nance长度")
		}

		nonce, ciphertext := decoded[:nonceSize], decoded[nonceSize:]
		// GCM模式直接返回解密结果，不需要处理填充
		return gcm.Open(nil, nonce, ciphertext, nil)

	default:
		return nil, errors.New("不支持的工作模式")
	}
}