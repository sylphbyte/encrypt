package encrypt

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm3"
)

// HashAlgorithm 哈希算法类型
type HashAlgorithm int

// 哈希算法常量定义
const (
	HashSHA1 HashAlgorithm = iota + 1
	HashSHA256
	HashSHA512
	HashSM3 // 国密哈希算法
)

// PBKDF2Deriver 密钥派生器
type PBKDF2Deriver struct {
	hashAlgo HashAlgorithm
	encoding Encoding
	encodingMode EncodingMode
}

// NewPBKDF2 创建新的PBKDF2密钥派生器
func NewPBKDF2() *PBKDF2Deriver {
	return &PBKDF2Deriver{
		hashAlgo: HashSHA256, // 默认使用SHA-256
		encoding: Base64Encoding,
		encodingMode: EncodingBase64,
	}
}

// SHA1 使用SHA-1哈希算法
func (p *PBKDF2Deriver) SHA1() *PBKDF2Deriver {
	p.hashAlgo = HashSHA1
	return p
}

// SHA256 使用SHA-256哈希算法
func (p *PBKDF2Deriver) SHA256() *PBKDF2Deriver {
	p.hashAlgo = HashSHA256
	return p
}

// SHA512 使用SHA-512哈希算法
func (p *PBKDF2Deriver) SHA512() *PBKDF2Deriver {
	p.hashAlgo = HashSHA512
	return p
}

// SM3 使用SM3国密哈希算法
func (p *PBKDF2Deriver) SM3() *PBKDF2Deriver {
	p.hashAlgo = HashSM3
	return p
}

// NoEncoding 设置无编码
func (p *PBKDF2Deriver) NoEncoding() *PBKDF2Deriver {
	p.encoding = NoEncoding
	p.encodingMode = EncodingNone
	return p
}

// Base64 设置Base64编码
func (p *PBKDF2Deriver) Base64() *PBKDF2Deriver {
	p.encoding = Base64Encoding
	p.encodingMode = EncodingBase64
	return p
}

// Base64Safe 设置安全的Base64编码
func (p *PBKDF2Deriver) Base64Safe() *PBKDF2Deriver {
	p.encoding = Base64Safe
	p.encodingMode = EncodingBase64Safe
	return p
}

// Hex 设置十六进制编码
func (p *PBKDF2Deriver) Hex() *PBKDF2Deriver {
	p.encoding = HexEncoding
	p.encodingMode = EncodingHex
	return p
}

// getHashFunc 获取对应的哈希函数
func (p *PBKDF2Deriver) getHashFunc() func() hash.Hash {
	switch p.hashAlgo {
	case HashSHA1:
		return sha1.New
	case HashSHA256:
		return sha256.New
	case HashSHA512:
		return sha512.New
	case HashSM3:
		return sm3.New
	default:
		return sha256.New // 默认使用SHA-256
	}
}

// DeriveKey 从密码派生密钥
// password: 用户密码
// salt: 盐值
// iterations: 迭代次数（建议至少10000次）
// keyLength: 生成密钥长度（字节数）
func (p *PBKDF2Deriver) DeriveKey(password, salt []byte, iterations int, keyLength int) (string, error) {
	if iterations < 1000 {
		return "", errors.New("迭代次数太少，安全性不足，建议至少10000次")
	}
	
	if keyLength <= 0 {
		return "", errors.New("密钥长度必须大于0")
	}
	
	if len(password) == 0 {
		return "", errors.New("密码不能为空")
	}
	
	if len(salt) == 0 {
		return "", errors.New("盐值不能为空")
	}
	
	// 获取哈希函数
	hashFunc := p.getHashFunc()
	
	// 执行PBKDF2算法
	key := pbkdf2(password, salt, iterations, keyLength, hashFunc)
	
	// 编码结果
	encodedBytes, err := p.encoding.Encode(key)
	if err != nil {
		return "", errors.Wrap(err, "编码密钥失败")
	}
	return string(encodedBytes), nil
}

// pbkdf2 是PBKDF2算法的实现
func pbkdf2(password, salt []byte, iterations, keyLen int, h func() hash.Hash) []byte {
	// DK = PBKDF2(PRF, Password, Salt, c, dkLen)
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	
	// 计算需要多少个block
	blocks := (keyLen + hashLen - 1) / hashLen
	
	// 结果buffer
	result := make([]byte, 0, blocks*hashLen)
	
	// 对每个block进行计算 T_i = F(Password, Salt, c, i)
	for i := 1; i <= blocks; i++ {
		block := pbkdf2F(prf, salt, iterations, i)
		result = append(result, block...)
	}
	
	// 截取到所需的长度
	return result[:keyLen]
}

// pbkdf2F 实现了 F(Password, Salt, c, i) = U_1 ^ U_2 ^ ... ^ U_c
// 其中 U_1 = PRF(Password, Salt || INT_32_BE(i))
// U_2 = PRF(Password, U_1)
// ...
// U_c = PRF(Password, U_{c-1})
func pbkdf2F(prf hash.Hash, salt []byte, iterations, blockIndex int) []byte {
	// U_1 = PRF(Password, Salt || INT_32_BE(i))
	prf.Reset()
	prf.Write(salt)
	
	// 添加block index (i) 的big-endian编码
	prf.Write([]byte{byte(blockIndex >> 24), byte(blockIndex >> 16), byte(blockIndex >> 8), byte(blockIndex)})
	
	// 计算第一个U值
	u := prf.Sum(nil)
	result := make([]byte, len(u))
	copy(result, u)
	
	// 计算后续的U值并进行XOR
	for i := 2; i <= iterations; i++ {
		prf.Reset()
		prf.Write(u)
		u = prf.Sum(nil)
		
		// 异或操作：result = result ^ u
		for j := 0; j < len(u); j++ {
			result[j] ^= u[j]
		}
	}
	
	return result
}