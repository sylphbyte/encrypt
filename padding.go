package encrypt

import (
	"bytes"
	"errors"
)

// Padding 填充算法接口
type Padding interface {
	// Pad 对数据进行填充
	Pad(data []byte, blockSize int) ([]byte, error)
	// Unpad 去除填充数据
	Unpad(data []byte, blockSize int) ([]byte, error)
}

// NoPadding 无填充实现
type NoPadding struct{}

// Pad 不进行填充，需要验证数据长度是块大小的整数倍
func (n *NoPadding) Pad(data []byte, blockSize int) ([]byte, error) {
	if len(data)%blockSize != 0 {
		return nil, errors.New("数据长度必须是块大小的整数倍")
	}
	return data, nil
}

// Unpad 不需要去除填充
func (n *NoPadding) Unpad(data []byte, blockSize int) ([]byte, error) {
	return data, nil
}

// PKCS7Padding PKCS#7填充实现
type PKCS7Padding struct{}

// Pad 使用PKCS#7标准进行填充
func (p *PKCS7Padding) Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("块大小必须大于0")
	}
	if blockSize > 256 {
		return nil, errors.New("块大小不能超过256")
	}
	
	padding := blockSize - (len(data) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...), nil
}

// Unpad 移除PKCS#7填充
func (p *PKCS7Padding) Unpad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("块大小必须大于0")
	}
	if blockSize > 256 {
		return nil, errors.New("块大小不能超过256")
	}
	if len(data) == 0 {
		return nil, errors.New("数据长度为0")
	}
	if len(data)%blockSize != 0 {
		return nil, errors.New("数据长度不是块大小的整数倍")
	}
	
	padding := int(data[len(data)-1])
	if padding > blockSize || padding == 0 {
		return nil, errors.New("非法填充数据")
	}
	
	// 验证填充是否有效
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("填充数据不一致")
		}
	}
	
	return data[:len(data)-padding], nil
}

// ZeroPadding 零填充实现
type ZeroPadding struct{}

// Pad 使用零进行填充
func (z *ZeroPadding) Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("块大小必须大于0")
	}
	
	padding := blockSize - (len(data) % blockSize)
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(data, padtext...), nil
}

// Unpad 移除零填充
func (z *ZeroPadding) Unpad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("块大小必须大于0")
	}
	if len(data) == 0 {
		return nil, errors.New("数据长度为0")
	}
	if len(data)%blockSize != 0 {
		return nil, errors.New("数据长度不是块大小的整数倍")
	}
	
	// 从末尾开始寻找非零字节
	index := len(data) - 1
	for ; index >= 0 && data[index] == 0; index-- {
	}
	
	// 具有最终字节的索引（包含该字节）
	return data[:index+1], nil
}

// 全局填充器实例
var (
	DefaultNoPadding     = &NoPadding{}
	DefaultPKCS7Padding  = &PKCS7Padding{}
	DefaultZeroPadding   = &ZeroPadding{}
)

// GetPadding 根据填充模式获取填充实现
func GetPadding(mode PaddingMode) Padding {
	switch mode {
	case PaddingNone:
		return DefaultNoPadding
	case PaddingPKCS7:
		return DefaultPKCS7Padding
	case PaddingZero:
		return DefaultZeroPadding
	default:
		return nil
	}
}