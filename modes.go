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
	iv []byte
}

func (c *CBCMode) Encrypt(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	
	// 验证IV
	if len(c.iv) != blockSize {
		return nil, errors.New("IV长度必须等于块大小")
	}
	
	// 创建加密器
	encrypted := make([]byte, len(data))
	encrypter := cipher.NewCBCEncrypter(block, c.iv)
	encrypter.CryptBlocks(encrypted, data)
	
	// 将IV添加到密文前面
	return append(c.iv, encrypted...), nil
}

func (c *CBCMode) Decrypt(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	
	// 提取IV
	if len(data) < blockSize {
		return nil, errors.New("密文太短，无法提取IV")
	}
	
	iv := data[:blockSize]
	cipherData := data[blockSize:]
	
	// 验证密文长度
	if len(cipherData)%blockSize != 0 {
		return nil, errors.New("密文长度不是块大小的整数倍")
	}
	
	// 创建解密器
	decrypted := make([]byte, len(cipherData))
	decrypter := cipher.NewCBCDecrypter(block, iv)
	decrypter.CryptBlocks(decrypted, cipherData)
	
	return decrypted, nil
}

func (c *CBCMode) NeedsIV() bool {
	return true
}

func (c *CBCMode) BlockSize() int {
	return len(c.iv)
}

// CFBMode CFB模式实现
type CFBMode struct {
	iv []byte
}

func (c *CFBMode) Encrypt(block cipher.Block, data []byte) ([]byte, error) {
	if len(c.iv) != block.BlockSize() {
		return nil, errors.New("IV长度必须等于块大小")
	}
	
	encrypted := make([]byte, len(data))
	stream := cipher.NewCFBEncrypter(block, c.iv)
	stream.XORKeyStream(encrypted, data)
	
	return append(c.iv, encrypted...), nil
}

func (c *CFBMode) Decrypt(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	if len(data) < blockSize {
		return nil, errors.New("密文太短，无法提取IV")
	}
	
	iv := data[:blockSize]
	ciphertext := data[blockSize:]
	
	decrypted := make([]byte, len(ciphertext))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(decrypted, ciphertext)
	
	return decrypted, nil
}

func (c *CFBMode) NeedsIV() bool {
	return true
}

func (c *CFBMode) BlockSize() int {
	return len(c.iv)
}

// OFBMode OFB模式实现
type OFBMode struct {
	iv []byte
}

func (o *OFBMode) Encrypt(block cipher.Block, data []byte) ([]byte, error) {
	if len(o.iv) != block.BlockSize() {
		return nil, errors.New("IV长度必须等于块大小")
	}
	
	encrypted := make([]byte, len(data))
	stream := cipher.NewOFB(block, o.iv)
	stream.XORKeyStream(encrypted, data)
	
	return append(o.iv, encrypted...), nil
}

func (o *OFBMode) Decrypt(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	if len(data) < blockSize {
		return nil, errors.New("密文太短，无法提取IV")
	}
	
	iv := data[:blockSize]
	ciphertext := data[blockSize:]
	
	decrypted := make([]byte, len(ciphertext))
	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(decrypted, ciphertext)
	
	return decrypted, nil
}

func (o *OFBMode) NeedsIV() bool {
	return true
}

func (o *OFBMode) BlockSize() int {
	return len(o.iv)
}

// CTRMode CTR模式实现
type CTRMode struct {
	iv []byte
}

func (c *CTRMode) Encrypt(block cipher.Block, data []byte) ([]byte, error) {
	if len(c.iv) != block.BlockSize() {
		return nil, errors.New("IV长度必须等于块大小")
	}
	
	encrypted := make([]byte, len(data))
	stream := cipher.NewCTR(block, c.iv)
	stream.XORKeyStream(encrypted, data)
	
	return append(c.iv, encrypted...), nil
}

func (c *CTRMode) Decrypt(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	if len(data) < blockSize {
		return nil, errors.New("密文太短，无法提取IV")
	}
	
	iv := data[:blockSize]
	ciphertext := data[blockSize:]
	
	decrypted := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(decrypted, ciphertext)
	
	return decrypted, nil
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
	
	// 生成随机nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.Wrap(err, "生成随机nonce失败")
	}
	g.nonce = nonce
	
	// GCM加密
	return gcm.Seal(nonce, nonce, data, nil), nil
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
	
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
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
	return &CBCMode{iv: iv}
}

// NewCFBMode 创建CFB模式
func NewCFBMode(iv []byte) BlockMode {
	return &CFBMode{iv: iv}
}

// NewOFBMode 创建OFB模式
func NewOFBMode(iv []byte) BlockMode {
	return &OFBMode{iv: iv}
}

// NewCTRMode 创建CTR模式
func NewCTRMode(iv []byte) BlockMode {
	return &CTRMode{iv: iv}
}

// NewGCMMode 创建GCM模式
func NewGCMMode() BlockMode {
	return &GCMMode{}
}