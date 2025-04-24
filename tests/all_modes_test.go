package tests

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/sylphbyte/encrypt"
)

func TestAllModesWithIV(t *testing.T) {
	// 测试数据
	key := []byte("Cbjs1fYZmKvVah2V")
	iv := []byte("KdEfCOYVZ04Pr10n")
	plaintext := []byte("123456")

	// 对所有模式进行测试
	testModes := []struct {
		name   string
		getEnc func() encrypt.ISymmetric
	}{
		{
			name: "CBC模式",
			getEnc: func() encrypt.ISymmetric {
				return encrypt.MustNewAES(key).CBC().WithIV(iv)
			},
		},
		{
			name: "CFB模式",
			getEnc: func() encrypt.ISymmetric {
				return encrypt.MustNewAES(key).CFB().WithIV(iv)
			},
		},
		{
			name: "OFB模式",
			getEnc: func() encrypt.ISymmetric {
				return encrypt.MustNewAES(key).OFB().WithIV(iv)
			},
		},
		{
			name: "CTR模式",
			getEnc: func() encrypt.ISymmetric {
				return encrypt.MustNewAES(key).CTR().WithIV(iv)
			},
		},
	}

	for _, mode := range testModes {
		t.Run(mode.name, func(t *testing.T) {
			// 使用PKCS7填充和Base64编码
			enc := mode.getEnc().PKCS7().Base64()

			// 加密
			ciphertext, err := enc.Encrypt(plaintext)
			require.NoError(t, err, "加密时不应返回错误")

			t.Logf("%s 加密结果: %s", mode.name, string(ciphertext))

			// 验证加密结果为固定长度 (不包含IV)
			// Base64编码后的16字节密文长度应该是24字符 (对于PKCS7填充后的8字节数据块)
			require.Equal(t, 24, len(ciphertext),
				"加密结果长度应该固定，不应包含IV (Base64编码后)")

			// 解密
			decrypted, err := enc.Decrypt(ciphertext)
			require.NoError(t, err, "解密时不应返回错误")

			// 验证解密结果与原始数据相同
			require.Equal(t, string(plaintext), string(decrypted),
				"解密后应该得到原始明文")

			// 两次加密结果应一致 (因为IV是固定的)
			ciphertext2, err := enc.Encrypt(plaintext)
			require.NoError(t, err)
			require.Equal(t, string(ciphertext), string(ciphertext2),
				"使用相同IV时，两次加密结果应相同")
		})
	}
}
