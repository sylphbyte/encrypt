package encrypt

import (
	"os"

	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm3"
)

// SM3Hasher SM3哈希算法实现
type SM3Hasher struct {
	encoding     Encoding
	encodingMode EncodingMode
}

// NewSM3 创建新的SM3哈希器
func NewSM3() *SM3Hasher {
	return &SM3Hasher{
		encoding:     Base64Encoding,
		encodingMode: EncodingBase64,
	}
}

// NoEncoding 设置无编码
func (s *SM3Hasher) NoEncoding() *SM3Hasher {
	s.encoding = NoEncoding
	s.encodingMode = EncodingNone
	return s
}

// Base64 设置Base64编码
func (s *SM3Hasher) Base64() *SM3Hasher {
	s.encoding = Base64Encoding
	s.encodingMode = EncodingBase64
	return s
}

// Base64Safe 设置安全的Base64编码
func (s *SM3Hasher) Base64Safe() *SM3Hasher {
	s.encoding = Base64Safe
	s.encodingMode = EncodingBase64Safe
	return s
}

// Hex 设置十六进制编码
func (s *SM3Hasher) Hex() *SM3Hasher {
	s.encoding = HexEncoding
	s.encodingMode = EncodingHex
	return s
}

// Sum 计算数据的SM3哈希值
func (s *SM3Hasher) Sum(data []byte) (string, error) {
	// 计算SM3哈希值
	hash := sm3.Sm3Sum(data)
	
	// 编码结果
	encodedBytes, err := s.encoding.Encode(hash)
	if err != nil {
		return "", errors.Wrap(err, "编码哈希值失败")
	}
	
	return string(encodedBytes), nil
}

// File 计算文件的SM3哈希值
func (s *SM3Hasher) File(filepath string) (string, error) {
	// 读取文件内容
	data, err := os.ReadFile(filepath)
	if err != nil {
		return "", errors.Wrap(err, "读取文件失败")
	}
	
	// 使用Sum方法计算哈希值
	return s.Sum(data)
}