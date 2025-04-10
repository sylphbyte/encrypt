package encrypt

// Algorithm 加密算法类型
type Algorithm int

// Mode 加密模式
type Mode int

// PaddingMode 填充模式
type PaddingMode int

// EncodingMode 编码模式
type EncodingMode int

// 算法常量定义
const (
	AlgorithmAES Algorithm = iota + 1
	AlgorithmDES
	Algorithm3DES
	AlgorithmSM4
	AlgorithmRSA
	AlgorithmECC
	AlgorithmSM2
)

// 模式常量定义
const (
	ModeECB Mode = iota + 1
	ModeCBC
	ModeCFB
	ModeOFB
	ModeCTR
	ModeGCM
)

// 填充模式常量定义
const (
	PaddingNone PaddingMode = iota
	PaddingPKCS7
	PaddingZero
)

// 编码模式常量定义
const (
	EncodingNone EncodingMode = iota
	EncodingBase64
	EncodingBase64Safe
	EncodingHex
)

// ISymmetric 对称加密接口
type ISymmetric interface {
	// 访问器方法
	Algorithm() Algorithm
	GetKey() []byte
	GetIV() []byte
	
	// 加密模式设置
	ECB() ISymmetric
	CBC() ISymmetric
	CFB() ISymmetric
	OFB() ISymmetric
	CTR() ISymmetric
	GCM() ISymmetric
	
	// 填充模式设置
	NoPadding() ISymmetric
	PKCS7() ISymmetric
	ZeroPadding() ISymmetric
	
	// 编码模式设置
	NoEncoding() ISymmetric
	Base64() ISymmetric
	Base64Safe() ISymmetric
	Hex() ISymmetric
	
	// 参数设置
	WithIV(iv []byte) ISymmetric
	
	// 核心操作
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// IAsymmetric 非对称加密接口
type IAsymmetric interface {
	// 访问器方法
	Algorithm() Algorithm
	
	// 编码模式设置
	NoEncoding() IAsymmetric
	Base64() IAsymmetric
	Base64Safe() IAsymmetric
	Hex() IAsymmetric
	
	// 密钥管理
	WithKeySize(size int) IAsymmetric // 只对RSA有效
	WithPublicKey(publicKey []byte) IAsymmetric
	WithPrivateKey(privateKey []byte) IAsymmetric
	GenerateKeyPair() (public []byte, private []byte, err error)
	
	// SM2特有方法
	WithUID(uid []byte) IAsymmetric // 只对SM2有效，设置签名用的用户ID
	
	// 核心操作
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	Sign(data []byte) ([]byte, error)
	Verify(data []byte, signature []byte) (bool, error)
}