package encrypt

import (
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/pkg/errors"
)

// BlockMode 块加密模式接口
type BlockMode interface {
	// Encrypt 对数据进行加密
	Encrypt(block cipher.Block, data []byte) ([]byte, error)
	// Decrypt 对数据进行解密
	Decrypt(block cipher.Block, data []byte) ([]byte, error)
	// NeedsIV 是否需要初始化向量
	NeedsIV() bool
	// BlockSize 返回块大小
	BlockSize() int
}

// ECBMode ECB模式实现 (不推荐用于生产环境，安全性低)
type ECBMode struct{}

func (e *ECBMode) Encrypt(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	encrypted := make([]byte, len(data))

	for i := 0; i < len(data); i += blockSize {
		block.Encrypt(encrypted[i:i+blockSize], data[i:i+blockSize])
	}

	return encrypted, nil
}

func (e *ECBMode) Decrypt(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	if len(data)%blockSize != 0 {
		return nil, errors.New("密文长度不是块大小的整数倍")
	}

	decrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += blockSize {
		block.Decrypt(decrypted[i:i+blockSize], data[i:i+blockSize])
	}

	return decrypted, nil
}

func (e *ECBMode) NeedsIV() bool {
	return false
}

func (e *ECBMode) BlockSize() int {
	return 0 // 依赖于使用的块加密算法
}

// CBCMode CBC模式实现
type CBCMode struct {
	iv             []byte
	keepIVSeparate bool // 新增标志，表示是否保持IV独立而不添加到密文中
}

func (c *CBCMode) Encrypt(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()

	// 验证IV
	if len(c.iv) != blockSize {
		return nil, errors.New("IV长度必须等于块大小")
	}

	// 从对象池获取加密结果缓冲区
	encrypted := GetBuffer(len(data))
	defer PutBuffer(encrypted) // 确保在函数结束前归还缓冲区

	// 创建加密器
	encrypter := cipher.NewCBCEncrypter(block, c.iv)
	encrypter.CryptBlocks(encrypted, data)

	// 当keepIVSeparate为true时，不添加IV到密文前面
	if c.keepIVSeparate {
		// 创建最终结果（不包含IV）
		finalResult := make([]byte, len(data))
		copy(finalResult, encrypted)
		return finalResult, nil
	}

	// 从对象池获取结果缓冲区
	resultSize := blockSize + len(data)
	result := GetBuffer(resultSize)

	// 将IV添加到密文前面
	copy(result[:blockSize], c.iv)
	copy(result[blockSize:], encrypted)

	// 创建最终结果（必须生成新的切片，因为result会被归还）
	finalResult := make([]byte, resultSize)
	copy(finalResult, result)

	// 归还result缓冲区
	PutBuffer(result)

	return finalResult, nil
}

func (c *CBCMode) Decrypt(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()

	// 如果IV是分离的，直接使用提供的IV进行解密
	if c.keepIVSeparate {
		// 验证密文长度
		if len(data)%blockSize != 0 {
			return nil, errors.New("密文长度不是块大小的整数倍")
		}

		// 从对象池获取解密结果缓冲区
		decrypted := GetBuffer(len(data))

		// 创建解密器
		decrypter := cipher.NewCBCDecrypter(block, c.iv)
		decrypter.CryptBlocks(decrypted, data)

		// 创建最终结果
		finalResult := make([]byte, len(data))
		copy(finalResult, decrypted)

		// 归还缓冲区
		PutBuffer(decrypted)

		return finalResult, nil
	}

	// 提取IV
	if len(data) < blockSize {
		return nil, errors.New("密文太短，无法提取IV")
	}

	// 从对象池获取IV缓冲区
	ivBuf := GetBuffer(blockSize)
	copy(ivBuf, data[:blockSize])

	cipherData := data[blockSize:]

	// 验证密文长度
	if len(cipherData)%blockSize != 0 {
		PutBuffer(ivBuf) // 出错时归还缓冲区
		return nil, errors.New("密文长度不是块大小的整数倍")
	}

	// 从对象池获取解密结果缓冲区
	decrypted := GetBuffer(len(cipherData))

	// 创建解密器
	decrypter := cipher.NewCBCDecrypter(block, ivBuf)
	decrypter.CryptBlocks(decrypted, cipherData)

	// 创建最终结果（必须生成新的切片，因为decrypted会被归还）
	finalResult := make([]byte, len(cipherData))
	copy(finalResult, decrypted)

	// 归还缓冲区
	PutBuffer(ivBuf)
	PutBuffer(decrypted)

	return finalResult, nil
}

func (c *CBCMode) NeedsIV() bool {
	return true
}

func (c *CBCMode) BlockSize() int {
	return len(c.iv)
}

// CFBMode CFB模式实现
type CFBMode struct {
	iv             []byte
	keepIVSeparate bool // 标志，表示是否保持IV独立而不添加到密文中
}

func (c *CFBMode) Encrypt(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	if len(c.iv) != blockSize {
		return nil, errors.New("IV长度必须等于块大小")
	}

	// 从对象池获取加密结果缓冲区
	encrypted := GetBuffer(len(data))
	defer PutBuffer(encrypted) // 确保在函数结束前归还缓冲区

	// 创建加密器
	stream := cipher.NewCFBEncrypter(block, c.iv)
	stream.XORKeyStream(encrypted, data)

	// 当keepIVSeparate为true时，不添加IV到密文前面
	if c.keepIVSeparate {
		// 创建最终结果（不包含IV）
		finalResult := make([]byte, len(data))
		copy(finalResult, encrypted)
		return finalResult, nil
	}

	// 从对象池获取结果缓冲区
	resultSize := blockSize + len(data)
	result := GetBuffer(resultSize)

	// 将IV和加密数据复制到结果缓冲区
	copy(result[:blockSize], c.iv)
	copy(result[blockSize:], encrypted)

	// 创建最终结果（必须生成新的切片，因为result会被归还）
	finalResult := make([]byte, resultSize)
	copy(finalResult, result)

	// 归还result缓冲区
	PutBuffer(result)

	return finalResult, nil
}

func (c *CFBMode) Decrypt(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()

	// 如果IV是分离的，直接使用提供的IV进行解密
	if c.keepIVSeparate {
		// 从对象池获取解密结果缓冲区
		decrypted := GetBuffer(len(data))

		// 创建解密器
		stream := cipher.NewCFBDecrypter(block, c.iv)
		stream.XORKeyStream(decrypted, data)

		// 创建最终结果
		finalResult := make([]byte, len(data))
		copy(finalResult, decrypted)

		// 归还缓冲区
		PutBuffer(decrypted)

		return finalResult, nil
	}

	if len(data) < blockSize {
		return nil, errors.New("密文太短，无法提取IV")
	}

	// 从对象池获取IV缓冲区
	ivBuf := GetBuffer(blockSize)
	copy(ivBuf, data[:blockSize])

	ciphertext := data[blockSize:]

	// 从对象池获取解密结果缓冲区
	decrypted := GetBuffer(len(ciphertext))

	// 创建解密器
	stream := cipher.NewCFBDecrypter(block, ivBuf)
	stream.XORKeyStream(decrypted, ciphertext)

	// 创建最终结果
	finalResult := make([]byte, len(ciphertext))
	copy(finalResult, decrypted)

	// 归还缓冲区
	PutBuffer(ivBuf)
	PutBuffer(decrypted)

	return finalResult, nil
}

func (c *CFBMode) NeedsIV() bool {
	return true
}

func (c *CFBMode) BlockSize() int {
	return len(c.iv)
}

// OFBMode OFB模式实现
type OFBMode struct {
	iv             []byte
	keepIVSeparate bool // 标志，表示是否保持IV独立而不添加到密文中
}

func (o *OFBMode) Encrypt(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	if len(o.iv) != blockSize {
		return nil, errors.New("IV长度必须等于块大小")
	}

	// 从对象池获取加密结果缓冲区
	encrypted := GetBuffer(len(data))
	defer PutBuffer(encrypted) // 确保在函数结束前归还缓冲区

	// 创建加密器
	stream := cipher.NewOFB(block, o.iv)
	stream.XORKeyStream(encrypted, data)

	// 当keepIVSeparate为true时，不添加IV到密文前面
	if o.keepIVSeparate {
		// 创建最终结果（不包含IV）
		finalResult := make([]byte, len(data))
		copy(finalResult, encrypted)
		return finalResult, nil
	}

	// 从对象池获取结果缓冲区
	resultSize := blockSize + len(data)
	result := GetBuffer(resultSize)

	// 将IV和加密数据复制到结果缓冲区
	copy(result[:blockSize], o.iv)
	copy(result[blockSize:], encrypted)

	// 创建最终结果（必须生成新的切片，因为result会被归还）
	finalResult := make([]byte, resultSize)
	copy(finalResult, result)

	// 归还result缓冲区
	PutBuffer(result)

	return finalResult, nil
}

func (o *OFBMode) Decrypt(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()

	// 如果IV是分离的，直接使用提供的IV进行解密
	if o.keepIVSeparate {
		// 从对象池获取解密结果缓冲区
		decrypted := GetBuffer(len(data))

		// 创建解密器
		stream := cipher.NewOFB(block, o.iv)
		stream.XORKeyStream(decrypted, data)

		// 创建最终结果
		finalResult := make([]byte, len(data))
		copy(finalResult, decrypted)

		// 归还缓冲区
		PutBuffer(decrypted)

		return finalResult, nil
	}

	if len(data) < blockSize {
		return nil, errors.New("密文太短，无法提取IV")
	}

	// 从对象池获取IV缓冲区
	ivBuf := GetBuffer(blockSize)
	copy(ivBuf, data[:blockSize])

	ciphertext := data[blockSize:]

	// 从对象池获取解密结果缓冲区
	decrypted := GetBuffer(len(ciphertext))

	// 创建解密器
	stream := cipher.NewOFB(block, ivBuf)
	stream.XORKeyStream(decrypted, ciphertext)

	// 创建最终结果
	finalResult := make([]byte, len(ciphertext))
	copy(finalResult, decrypted)

	// 归还缓冲区
	PutBuffer(ivBuf)
	PutBuffer(decrypted)

	return finalResult, nil
}

func (o *OFBMode) NeedsIV() bool {
	return true
}

func (o *OFBMode) BlockSize() int {
	return len(o.iv)
}

// CTRMode CTR模式实现
type CTRMode struct {
	iv             []byte
	keepIVSeparate bool // 标志，表示是否保持IV独立而不添加到密文中
}

func (c *CTRMode) Encrypt(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	if len(c.iv) != blockSize {
		return nil, errors.New("IV长度必须等于块大小")
	}

	// 从对象池获取加密结果缓冲区
	encrypted := GetBuffer(len(data))
	defer PutBuffer(encrypted) // 确保在函数结束前归还缓冲区

	// 创建加密器
	stream := cipher.NewCTR(block, c.iv)
	stream.XORKeyStream(encrypted, data)

	// 当keepIVSeparate为true时，不添加IV到密文前面
	if c.keepIVSeparate {
		// 创建最终结果（不包含IV）
		finalResult := make([]byte, len(data))
		copy(finalResult, encrypted)
		return finalResult, nil
	}

	// 从对象池获取结果缓冲区
	resultSize := blockSize + len(data)
	result := GetBuffer(resultSize)

	// 将IV和加密数据复制到结果缓冲区
	copy(result[:blockSize], c.iv)
	copy(result[blockSize:], encrypted)

	// 创建最终结果（必须生成新的切片，因为result会被归还）
	finalResult := make([]byte, resultSize)
	copy(finalResult, result)

	// 归还result缓冲区
	PutBuffer(result)

	return finalResult, nil
}

func (c *CTRMode) Decrypt(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()

	// 如果IV是分离的，直接使用提供的IV进行解密
	if c.keepIVSeparate {
		// 从对象池获取解密结果缓冲区
		decrypted := GetBuffer(len(data))

		// 创建解密器
		stream := cipher.NewCTR(block, c.iv)
		stream.XORKeyStream(decrypted, data)

		// 创建最终结果
		finalResult := make([]byte, len(data))
		copy(finalResult, decrypted)

		// 归还缓冲区
		PutBuffer(decrypted)

		return finalResult, nil
	}

	if len(data) < blockSize {
		return nil, errors.New("密文太短，无法提取IV")
	}

	// 从对象池获取IV缓冲区
	ivBuf := GetBuffer(blockSize)
	copy(ivBuf, data[:blockSize])

	ciphertext := data[blockSize:]

	// 从对象池获取解密结果缓冲区
	decrypted := GetBuffer(len(ciphertext))

	// 创建解密器
	stream := cipher.NewCTR(block, ivBuf)
	stream.XORKeyStream(decrypted, ciphertext)

	// 创建最终结果
	finalResult := make([]byte, len(ciphertext))
	copy(finalResult, decrypted)

	// 归还缓冲区
	PutBuffer(ivBuf)
	PutBuffer(decrypted)

	return finalResult, nil
}

func (c *CTRMode) NeedsIV() bool {
	return true
}

func (c *CTRMode) BlockSize() int {
	return len(c.iv)
}

// GCMMode GCM模式实现
type GCMMode struct {
	nonce []byte
}

func (g *GCMMode) Encrypt(block cipher.Block, data []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "创建GCM模式失败")
	}

	// 从对象池获取nonce缓冲区
	nonceSize := gcm.NonceSize()
	nonceBuf := GetBuffer(nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonceBuf); err != nil {
		PutBuffer(nonceBuf) // 出错时释放缓冲区
		return nil, errors.Wrap(err, "生成随机nonce失败")
	}

	// 创建一个永久副本
	g.nonce = make([]byte, nonceSize)
	copy(g.nonce, nonceBuf)

	// 从对象池获取结果缓冲区（GCM的Seal方法可以原地加密）
	// 预留足够空间给认证标签 (通常是16字节)
	resultSize := nonceSize + len(data) + 16
	result := GetBuffer(resultSize)

	// 先复制nonce到缓冲区开头
	copy(result[:nonceSize], nonceBuf)

	// 使用Seal方法进行原地加密，直接进入了result缓冲区
	ciphertext := gcm.Seal(result[:nonceSize], nonceBuf, data, nil)

	// 释放nonce缓冲区
	PutBuffer(nonceBuf)

	// 创建最终结果
	finalResult := make([]byte, len(ciphertext))
	copy(finalResult, ciphertext)

	// 释放结果缓冲区
	PutBuffer(result)

	return finalResult, nil
}

func (g *GCMMode) Decrypt(block cipher.Block, data []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "创建GCM模式失败")
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("密文太短，无法提取nonce")
	}

	// 从对象池获取nonce缓冲区
	nonceBuf := GetBuffer(nonceSize)
	copy(nonceBuf, data[:nonceSize])

	// 分离ciphertext
	ciphertext := data[nonceSize:]

	// 从对象池获取结果缓冲区
	// GCM解密后大小会比原始密文小16字节(认证标签)
	resultBuf := GetBuffer(len(ciphertext) - 16)

	// 解密并进行完整性验证
	plaintext, err := gcm.Open(resultBuf[:0], nonceBuf, ciphertext, nil)
	if err != nil {
		// 出错时释放缓冲区
		PutBuffer(nonceBuf)
		PutBuffer(resultBuf)
		return nil, errors.Wrap(err, "GCM解密失败，可能是数据被篡改")
	}

	// 创建最终结果
	finalResult := make([]byte, len(plaintext))
	copy(finalResult, plaintext)

	// 释放缓冲区
	PutBuffer(nonceBuf)
	PutBuffer(resultBuf)

	return finalResult, nil
}

func (g *GCMMode) NeedsIV() bool {
	return false // GCM使用nonce而不是IV
}

func (g *GCMMode) BlockSize() int {
	return len(g.nonce)
}

// 创建模式实例的工厂函数

// NewECBMode 创建ECB模式
func NewECBMode() BlockMode {
	return &ECBMode{}
}

// NewCBCMode 创建CBC模式
func NewCBCMode(iv []byte) BlockMode {
	return &CBCMode{
		iv:             iv,
		keepIVSeparate: false, // 默认情况下将IV添加到密文中
	}
}

// NewCFBMode 创建CFB模式
func NewCFBMode(iv []byte) BlockMode {
	return &CFBMode{
		iv:             iv,
		keepIVSeparate: false, // 默认情况下将IV添加到密文中
	}
}

// NewOFBMode 创建OFB模式
func NewOFBMode(iv []byte) BlockMode {
	return &OFBMode{
		iv:             iv,
		keepIVSeparate: false, // 默认情况下将IV添加到密文中
	}
}

// NewCTRMode 创建CTR模式
func NewCTRMode(iv []byte) BlockMode {
	return &CTRMode{
		iv:             iv,
		keepIVSeparate: false, // 默认情况下将IV添加到密文中
	}
}

// NewGCMMode 创建GCM模式
func NewGCMMode() BlockMode {
	return &GCMMode{}
}
