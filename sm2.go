package encrypt

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
	// math/big 在tjfoc库中间接使用
	
	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

// Algorithm 获取算法类型
func (s *SM2Encryptor) Algorithm() Algorithm {
	return s.algorithm
}

// WithKeySize SM2不需要设置密钥大小，保留此方法是为了符合接口
func (s *SM2Encryptor) WithKeySize(size int) IAsymmetric {
	// SM2使用固定的密钥大小，不需要特别设置
	return s
}

// WithUID 设置SM2签名用的用户ID，默认为1234567812345678
func (s *SM2Encryptor) WithUID(uid []byte) IAsymmetric {
	s.uid = uid
	return s
}

// WithPublicKey 设置公钥
func (s *SM2Encryptor) WithPublicKey(publicKeyData []byte) IAsymmetric {
	// 尝试解析PEM格式的公钥
	block, _ := pem.Decode(publicKeyData)
	if block == nil {
		panic("无法解析PEM编码的SM2公钥")
	}

	pubKey, err := x509.ReadPublicKeyFromPem(publicKeyData)
	if err != nil {
		panic(fmt.Sprintf("解析SM2公钥失败: %s", err))
	}
	
	s.publicKey = pubKey
	return s
}

// WithPrivateKey 设置私钥
func (s *SM2Encryptor) WithPrivateKey(privateKeyData []byte) IAsymmetric {
	// 尝试解析PEM格式的私钥
	privKey, err := x509.ReadPrivateKeyFromPem(privateKeyData, nil) // 无密码保护
	if err != nil {
		panic(fmt.Sprintf("解析SM2私钥失败: %s", err))
	}
	
	s.privateKey = privKey
	// 同时设置对应的公钥
	s.publicKey = &privKey.PublicKey
	
	return s
}

// GenerateKeyPair 生成SM2密钥对
func (s *SM2Encryptor) GenerateKeyPair() ([]byte, []byte, error) {
	// 生成SM2密钥对
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "生成SM2密钥对失败")
	}
	
	// 保存密钥用于后续操作
	s.privateKey = privateKey
	s.publicKey = &privateKey.PublicKey
	
	// 将私钥编码为PEM格式
	privatePEM, err := x509.WritePrivateKeyToPem(privateKey, nil) // 无密码保护
	if err != nil {
		return nil, nil, errors.Wrap(err, "编码SM2私钥失败")
	}
	
	// 将公钥编码为PEM格式
	publicPEM, err := x509.WritePublicKeyToPem(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "编码SM2公钥失败")
	}
	
	return publicPEM, privatePEM, nil
}

// NoEncoding 设置无编码
func (s *SM2Encryptor) NoEncoding() IAsymmetric {
	s.encoding = NoEncoding
	s.encodingMode = EncodingNone
	return s
}

// Base64 设置Base64编码
func (s *SM2Encryptor) Base64() IAsymmetric {
	s.encoding = Base64Encoding
	s.encodingMode = EncodingBase64
	return s
}

// Base64Safe 设置安全的Base64编码
func (s *SM2Encryptor) Base64Safe() IAsymmetric {
	s.encoding = Base64Safe
	s.encodingMode = EncodingBase64Safe
	return s
}

// Hex 设置十六进制编码
func (s *SM2Encryptor) Hex() IAsymmetric {
	s.encoding = HexEncoding
	s.encodingMode = EncodingHex
	return s
}

// Encrypt SM2加密
func (s *SM2Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	if s.publicKey == nil {
		return nil, errors.New("未设置公钥")
	}
	
	// 类型断言
	pubKey, ok := s.publicKey.(*sm2.PublicKey)
	if !ok {
		return nil, errors.New("公钥类型不正确")
	}
	
	// SM2加密
	ciphertext, err := pubKey.EncryptAsn1(plaintext, rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "SM2加密失败")
	}
	
	// 编码处理
	return s.encoding.Encode(ciphertext)
}

// Decrypt SM2解密
func (s *SM2Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	if s.privateKey == nil {
		return nil, errors.New("未设置私钥")
	}
	
	// 类型断言
	privKey, ok := s.privateKey.(*sm2.PrivateKey)
	if !ok {
		return nil, errors.New("私钥类型不正确")
	}
	
	// 解码处理
	decoded, err := s.encoding.Decode(ciphertext)
	if err != nil {
		return nil, errors.Wrap(err, "解码失败")
	}
	
	// SM2解密
	return privKey.DecryptAsn1(decoded)
}

// Sign SM2签名
func (s *SM2Encryptor) Sign(data []byte) ([]byte, error) {
	if s.privateKey == nil {
		return nil, errors.New("未设置私钥")
	}
	
	// 类型断言
	privKey, ok := s.privateKey.(*sm2.PrivateKey)
	if !ok {
		return nil, errors.New("私钥类型不正确")
	}
	
	// 使用默认用户ID或自定义用户ID
	uid := s.uid
	if uid == nil {
		uid = []byte("1234567812345678") // 默认UID
	}
	
	// 计算摘要
	r, s0, err := sm2.Sm2Sign(privKey, data, uid, rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "SM2签名失败")
	}
	
	// 将r,s转换为签名数据
	signature, err := sm2.SignDigitToSignData(r, s0)
	if err != nil {
		return nil, errors.Wrap(err, "转换签名数据失败")
	}
	
	// 编码处理
	return s.encoding.Encode(signature)
}

// Verify SM2验证签名
func (s *SM2Encryptor) Verify(data []byte, signature []byte) (bool, error) {
	if s.publicKey == nil {
		return false, errors.New("未设置公钥")
	}
	
	// 类型断言
	pubKey, ok := s.publicKey.(*sm2.PublicKey)
	if !ok {
		return false, errors.New("公钥类型不正确")
	}
	
	// 解码签名
	decoded, err := s.encoding.Decode(signature)
	if err != nil {
		return false, errors.Wrap(err, "解码签名失败")
	}
	
	// 将签名数据转换为r,s
	r, s0, err := sm2.SignDataToSignDigit(decoded)
	if err != nil {
		return false, errors.Wrap(err, "解析签名格式失败")
	}
	
	// 使用默认用户ID或自定义用户ID
	uid := s.uid
	if uid == nil {
		uid = []byte("1234567812345678") // 默认UID
	}
	
	// 验证签名
	valid := sm2.Sm2Verify(pubKey, data, uid, r, s0)
	return valid, nil
}