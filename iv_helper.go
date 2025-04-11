package encrypt

import (
	"crypto/cipher"
	"crypto/rand"
	"io"
	
	"github.com/pkg/errors"
)

// InitBlockMode 初始化一个具有正确IV的块加密模式
// 如果给定的模式不需要IV，则直接返回
// 如果需要IV但没有设置，则会生成随机IV
func InitBlockMode(blockMode BlockMode, block cipher.Block) (BlockMode, error) {
	// 如果模式不需要IV，直接返回
	if !blockMode.NeedsIV() {
		return blockMode, nil
	}
	
	// 检查模式类型，如果已经设置了IV且长度正确，也直接返回
	switch mode := blockMode.(type) {
	case *CBCMode:
		if mode.iv != nil && len(mode.iv) == block.BlockSize() {
			return mode, nil
		}
		return generateIVForMode(mode, block)
		
	case *CFBMode:
		if mode.iv != nil && len(mode.iv) == block.BlockSize() {
			return mode, nil
		}
		return generateIVForMode(mode, block)
		
	case *OFBMode:
		if mode.iv != nil && len(mode.iv) == block.BlockSize() {
			return mode, nil
		}
		return generateIVForMode(mode, block)
		
	case *CTRMode:
		if mode.iv != nil && len(mode.iv) == block.BlockSize() {
			return mode, nil
		}
		return generateIVForMode(mode, block)
		
	default:
		// 对于未知模式，假设它不需要特殊处理
		return blockMode, nil
	}
}

// generateIVForMode 为指定的模式生成随机IV
func generateIVForMode(blockMode BlockMode, block cipher.Block) (BlockMode, error) {
	blockSize := block.BlockSize()
	iv := make([]byte, blockSize)
	
	// 生成随机IV
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.Wrap(err, "生成随机IV失败")
	}
	
	// 根据模式类型设置IV
	switch mode := blockMode.(type) {
	case *CBCMode:
		mode.iv = iv
		return mode, nil
		
	case *CFBMode:
		mode.iv = iv
		return mode, nil
		
	case *OFBMode:
		mode.iv = iv
		return mode, nil
		
	case *CTRMode:
		mode.iv = iv
		return mode, nil
		
	default:
		// 不应该到达这里，因为之前已经检查过模式类型
		return blockMode, nil
	}
}