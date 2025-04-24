package tests

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/sylphbyte/encrypt"
)

func TestAESEncryptWithIV(t *testing.T) {
	// 测试用例：与用户提供的示例匹配
	key := []byte("Cbjs1fYZmKvVah2V")
	iv := []byte("KdEfCOYVZ04Pr10n")
	plaintext := []byte("123456")

	// 预期结果
	expectedResult := "30p6tjs9RPW6jKnyMvkWQg=="

	// 使用CBC模式和指定IV加密
	result, err := encrypt.MustNewAES(key).CBC().WithIV(iv).PKCS7().Base64().Encrypt(plaintext)

	// 断言
	require.NoError(t, err)
	require.Equal(t, expectedResult, string(result), "加密结果应与预期匹配")

	// 测试解密功能是否也正常
	decrypted, err := encrypt.MustNewAES(key).CBC().WithIV(iv).PKCS7().Base64().Decrypt(result)
	require.NoError(t, err)
	require.Equal(t, string(plaintext), string(decrypted), "解密后应该得到原始明文")
}
