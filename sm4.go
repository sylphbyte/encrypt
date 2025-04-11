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

	// 从对象池获取填充缓冲区
	var processedText []byte
	blockSize := block.BlockSize()
	
	if s.needsPadding() {
		// 对明文进行填充
		padSize := blockSize - (len(plaintext) % blockSize)
		if padSize == 0 {
			padSize = blockSize
		}
		
		// 从对象池获取缓冲区并直接用于填充
		buf := GetBuffer(len(plaintext) + padSize)
		
		// 调用pad方法前先复制原始数据
		copy(buf, plaintext)
		
		// 使用s.padding进行填充操作
		// 注意：这里假设填充操作会创建新的内存空间
		processedText, err = s.padding.Pad(plaintext, blockSize)
		
		// 无论成功失败都要归还缓冲区
		PutBuffer(buf)
		
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
		// 从对象池获取加密结果缓冲区
		resultBuf := GetBuffer(len(processedText))
		
		// SM4-ECB模式加密
		for bs, be := 0, blockSize; bs < len(processedText); bs, be = bs+blockSize, be+blockSize {
			block.Encrypt(resultBuf[bs:be], processedText[bs:be])
		}
		
		// 创建结果数组并复制加密数据
		encrypted = make([]byte, len(processedText))
		copy(encrypted, resultBuf)
		
		// 归还缓冲区
		PutBuffer(resultBuf)

	case ModeCBC:
		// 确保IV存在
		if s.iv == nil {
			// 从对象池获取IV缓冲区
			ivBuf := GetBuffer(blockSize)
			if _, err := io.ReadFull(rand.Reader, ivBuf); err != nil {
				PutBuffer(ivBuf) // 出错时归还缓冲区
				return nil, errors.Wrap(err, "生成随机IV失败")
			}
			
			// 从缓冲区创建新的IV并存储
			s.iv = make([]byte, blockSize)
			copy(s.iv, ivBuf)
			
			// 归还IV缓冲区
			PutBuffer(ivBuf)
		}

		// 从对象池获取加密结果缓冲区
		resultBuf := GetBuffer(len(processedText))
		
		// SM4-CBC模式加密
		mode := cipher.NewCBCEncrypter(block, s.iv)
		mode.CryptBlocks(resultBuf, processedText)
		
		// 创建结果数组并复制加密数据
		encrypted = make([]byte, len(processedText))
		copy(encrypted, resultBuf)
		
		// 归还缓冲区
		PutBuffer(resultBuf)

	case ModeCFB:
		// 确保IV存在
		if s.iv == nil {
			// 从对象池获取IV缓冲区
			ivBuf := GetBuffer(blockSize)
			if _, err := io.ReadFull(rand.Reader, ivBuf); err != nil {
				PutBuffer(ivBuf) // 出错时归还缓冲区
				return nil, errors.Wrap(err, "生成随机IV失败")
			}
			
			// 从缓冲区创建新的IV并存储
			s.iv = make([]byte, blockSize)
			copy(s.iv, ivBuf)
			
			// 归还IV缓冲区
			PutBuffer(ivBuf)
		}

		// 从对象池获取加密结果缓冲区
		resultBuf := GetBuffer(len(processedText))
		
		// SM4-CFB模式加密
		mode := cipher.NewCFBEncrypter(block, s.iv)
		mode.XORKeyStream(resultBuf, processedText)
		
		// 创建结果数组并复制加密数据
		encrypted = make([]byte, len(processedText))
		copy(encrypted, resultBuf)
		
		// 归还缓冲区
		PutBuffer(resultBuf)

	case ModeOFB:
		// 确保IV存在
		if s.iv == nil {
			// 从对象池获取IV缓冲区
			ivBuf := GetBuffer(blockSize)
			if _, err := io.ReadFull(rand.Reader, ivBuf); err != nil {
				PutBuffer(ivBuf) // 出错时归还缓冲区
				return nil, errors.Wrap(err, "生成随机IV失败")
			}
			
			// 从缓冲区创建新的IV并存储
			s.iv = make([]byte, blockSize)
			copy(s.iv, ivBuf)
			
			// 归还IV缓冲区
			PutBuffer(ivBuf)
		}

		// 从对象池获取加密结果缓冲区
		resultBuf := GetBuffer(len(processedText))
		
		// SM4-OFB模式加密
		mode := cipher.NewOFB(block, s.iv)
		mode.XORKeyStream(resultBuf, processedText)
		
		// 创建结果数组并复制加密数据
		encrypted = make([]byte, len(processedText))
		copy(encrypted, resultBuf)
		
		// 归还缓冲区
		PutBuffer(resultBuf)

	case ModeCTR:
		// 确保IV存在
		if s.iv == nil {
			// 从对象池获取IV缓冲区
			ivBuf := GetBuffer(blockSize)
			if _, err := io.ReadFull(rand.Reader, ivBuf); err != nil {
				PutBuffer(ivBuf) // 出错时归还缓冲区
				return nil, errors.Wrap(err, "生成随机IV失败")
			}
			
			// 从缓冲区创建新的IV并存储
			s.iv = make([]byte, blockSize)
			copy(s.iv, ivBuf)
			
			// 归还IV缓冲区
			PutBuffer(ivBuf)
		}

		// 从对象池获取加密结果缓冲区
		resultBuf := GetBuffer(len(processedText))
		
		// SM4-CTR模式加密
		mode := cipher.NewCTR(block, s.iv)
		mode.XORKeyStream(resultBuf, processedText)
		
		// 创建结果数组并复制加密数据
		encrypted = make([]byte, len(processedText))
		copy(encrypted, resultBuf)
		
		// 归还缓冲区
		PutBuffer(resultBuf)

	case ModeGCM:
		// GCM模式通常不需要额外填充
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, errors.Wrap(err, "创建GCM模式失败")
		}

		// 从对象池获取nonce缓冲区
		nonceSize := gcm.NonceSize()
		nonceBuf := GetBuffer(nonceSize)
		if _, err := io.ReadFull(rand.Reader, nonceBuf); err != nil {
			PutBuffer(nonceBuf) // 出错时归还缓冲区
			return nil, errors.Wrap(err, "生成GCM nonce失败")
		}

		// 创建一个新的nonce副本用于长期存储
		nonce := make([]byte, nonceSize)
		copy(nonce, nonceBuf)
		
		// 从对象池获取加密结果缓冲区 (GCM会在原文基础上加上认证标签)
		// 通常GCM认证标签是16字节
		resultBuf := GetBuffer(len(processedText) + 16 + nonceSize)
		
		// 复制nonce到结果缓冲区的开头
		copy(resultBuf, nonce)
		
		// 对原始明文进行加密（不是填充后的）
		// Seal的dst参数应该正好是nonce之后的位置
		ciphertext := gcm.Seal(resultBuf[:nonceSize], nonce, processedText, nil)
		
		// 创建最终结果数组
		encrypted = make([]byte, len(ciphertext))
		copy(encrypted, ciphertext)
		
		// 归还缓冲区
		PutBuffer(nonceBuf)
		PutBuffer(resultBuf)

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

	// 定义共用的块大小
	blockSize := block.BlockSize()
	
	// 根据不同模式进行解密
	var decrypted []byte
	switch s.blockMode {
	case ModeECB:
		// 从对象池获取解密结果缓冲区
		resultBuf := GetBuffer(len(decoded))
		
		// SM4-ECB模式解密
		for bs, be := 0, blockSize; bs < len(decoded); bs, be = bs+blockSize, be+blockSize {
			block.Decrypt(resultBuf[bs:be], decoded[bs:be])
		}

		// 移除填充前的临时结果
		tempResult, err := s.padding.Unpad(resultBuf, blockSize)
		
		// 创建最终结果数组
		decrypted = make([]byte, len(tempResult))
		copy(decrypted, tempResult)
		
		// 归还缓冲区
		PutBuffer(resultBuf)
		
		if err != nil {
			return nil, errors.Wrap(err, "移除填充失败")
		}
		
		return decrypted, nil

	case ModeCBC:
		// 检查IV
		if s.iv == nil || len(s.iv) != blockSize {
			return nil, errors.New("CBC模式需要正确的IV")
		}

		// 从对象池获取解密结果缓冲区
		resultBuf := GetBuffer(len(decoded))
		
		// SM4-CBC模式解密
		mode := cipher.NewCBCDecrypter(block, s.iv)
		mode.CryptBlocks(resultBuf, decoded)

		// 移除填充前的临时结果
		tempResult, err := s.padding.Unpad(resultBuf, blockSize)
		
		// 创建最终结果数组
		decrypted = make([]byte, len(tempResult))
		copy(decrypted, tempResult)
		
		// 归还缓冲区
		PutBuffer(resultBuf)
		
		if err != nil {
			return nil, errors.Wrap(err, "移除填充失败")
		}
		
		return decrypted, nil

	case ModeCFB:
		// 检查IV
		if s.iv == nil || len(s.iv) != blockSize {
			return nil, errors.New("CFB模式需要正确的IV")
		}

		// 从对象池获取解密结果缓冲区
		resultBuf := GetBuffer(len(decoded))
		
		// SM4-CFB模式解密
		mode := cipher.NewCFBDecrypter(block, s.iv)
		mode.XORKeyStream(resultBuf, decoded)

		// 创建最终结果数组
		decrypted = make([]byte, len(resultBuf))
		copy(decrypted, resultBuf)
		
		// 归还缓冲区
		PutBuffer(resultBuf)

		// 流模式不需要去除填充
		return decrypted, nil

	case ModeOFB:
		// 检查IV
		if s.iv == nil || len(s.iv) != blockSize {
			return nil, errors.New("OFB模式需要正确的IV")
		}

		// 从对象池获取解密结果缓冲区
		resultBuf := GetBuffer(len(decoded))
		
		// SM4-OFB模式解密
		mode := cipher.NewOFB(block, s.iv)
		mode.XORKeyStream(resultBuf, decoded)

		// 创建最终结果数组
		decrypted = make([]byte, len(resultBuf))
		copy(decrypted, resultBuf)
		
		// 归还缓冲区
		PutBuffer(resultBuf)

		// 流模式不需要去除填充
		return decrypted, nil

	case ModeCTR:
		// 检查IV
		if s.iv == nil || len(s.iv) != blockSize {
			return nil, errors.New("CTR模式需要正确的IV")
		}

		// 从对象池获取解密结果缓冲区
		resultBuf := GetBuffer(len(decoded))
		
		// SM4-CTR模式解密
		mode := cipher.NewCTR(block, s.iv)
		mode.XORKeyStream(resultBuf, decoded)

		// 创建最终结果数组
		decrypted = make([]byte, len(resultBuf))
		copy(decrypted, resultBuf)
		
		// 归还缓冲区
		PutBuffer(resultBuf)

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
			return nil, errors.New("密文长度小于nonce长度")
		}

		// 安全地处理nonce和密文
		nonce := make([]byte, nonceSize)
		copy(nonce, decoded[:nonceSize])
		
		// 分离ciphertext
		gcmCiphertext := make([]byte, len(decoded) - nonceSize)
		copy(gcmCiphertext, decoded[nonceSize:])
		
		// GCM模式解密
		result, err := gcm.Open(nil, nonce, gcmCiphertext, nil)
		if err != nil {
			return nil, errors.Wrap(err, "GCM解密失败，可能是数据被篡改")
		}
		
		// GCM模式直接返回解密结果，不需要处理填充
		return result, nil

	default:
		return nil, errors.New("不支持的工作模式")
	}
}