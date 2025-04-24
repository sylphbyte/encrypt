package tests

import (
	"fmt"
	"testing"

	"github.com/sylphbyte/encrypt"
)

func TestExample(t *testing.T) {
	// 用户需求示例
	key := []byte("Cbjs1fYZmKvVah2V")
	iv := []byte("KdEfCOYVZ04Pr10n")

	// 加密
	bytes, err := encrypt.MustNewAES(key).CBC().WithIV(iv).PKCS7().Base64().Encrypt([]byte("123456"))
	if err != nil {
		t.Fatal(err)
	}

	// 输出加密结果
	fmt.Printf("加密结果: %s\n", string(bytes))

	// 检查结果是否与期望值匹配
	expectedResult := "30p6tjs9RPW6jKnyMvkWQg=="
	if string(bytes) != expectedResult {
		t.Fatalf("加密结果不匹配, 期望: %s, 实际: %s", expectedResult, string(bytes))
	}

	// 解密验证
	decrypted, err := encrypt.MustNewAES(key).CBC().WithIV(iv).PKCS7().Base64().Decrypt(bytes)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("解密结果: %s\n", string(decrypted))

	if string(decrypted) != "123456" {
		t.Fatalf("解密结果不匹配, 期望: %s, 实际: %s", "123456", string(decrypted))
	}
}
