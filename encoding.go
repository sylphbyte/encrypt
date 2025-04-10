package encrypt

import (
	"encoding/base64"
	"encoding/hex"
	
	"github.com/pkg/errors"
)

// Encoding 编码接口定义
type Encoding interface {
	// Encode 将数据进行编码
	Encode(data []byte) ([]byte, error)
	// Decode 将数据进行解码
	Decode(data []byte) ([]byte, error)
}

// NoEncodingImpl 不进行编码处理
type NoEncodingImpl struct{}

// Encode 不进行编码，直接返回原始数据
func (n *NoEncodingImpl) Encode(data []byte) ([]byte, error) {
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

// Decode 不进行解码，直接返回原始数据
func (n *NoEncodingImpl) Decode(data []byte) ([]byte, error) {
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

// Base64Impl Base64编码实现
type Base64Impl struct{}

// Encode 使用标准Base64编码
func (b *Base64Impl) Encode(data []byte) ([]byte, error) {
	result := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(result, data)
	return result, nil
}

// Decode 使用标准Base64解码
func (b *Base64Impl) Decode(data []byte) ([]byte, error) {
	result := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(result, data)
	if err != nil {
		return nil, errors.Wrap(err, "Base64解码失败")
	}
	return result[:n], nil
}

// Base64SafeImpl 安全的Base64编码实现
type Base64SafeImpl struct{}

// Encode 使用URL安全的Base64编码
func (b *Base64SafeImpl) Encode(data []byte) ([]byte, error) {
	result := make([]byte, base64.URLEncoding.EncodedLen(len(data)))
	base64.URLEncoding.Encode(result, data)
	return result, nil
}

// Decode 使用URL安全的Base64解码
func (b *Base64SafeImpl) Decode(data []byte) ([]byte, error) {
	result := make([]byte, base64.URLEncoding.DecodedLen(len(data)))
	n, err := base64.URLEncoding.Decode(result, data)
	if err != nil {
		return nil, errors.Wrap(err, "安全Base64解码失败")
	}
	return result[:n], nil
}

// HexImpl 十六进制编码实现
type HexImpl struct{}

// Encode 使用十六进制编码
func (h *HexImpl) Encode(data []byte) ([]byte, error) {
	result := make([]byte, hex.EncodedLen(len(data)))
	hex.Encode(result, data)
	return result, nil
}

// Decode 使用十六进制解码
func (h *HexImpl) Decode(data []byte) ([]byte, error) {
	result := make([]byte, hex.DecodedLen(len(data)))
	n, err := hex.Decode(result, data)
	if err != nil {
		return nil, errors.Wrap(err, "十六进制解码失败")
	}
	return result[:n], nil
}

// 全局编码器实例
var (
	NoEncoding    = &NoEncodingImpl{}
	Base64Encoding = &Base64Impl{}
	Base64Safe     = &Base64SafeImpl{}
	HexEncoding    = &HexImpl{}
)