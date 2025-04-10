package tests

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/sylphbyte/encrypt"
)

// TestKeyGenerator 测试密钥生成器功能
func TestKeyGenerator(t *testing.T) {
	// 创建密钥生成器
	kg := encrypt.NewKeyGenerator()

	// 1. 测试随机字节生成
	t.Run("RandomBytes", func(t *testing.T) {
		lengths := []int{8, 16, 24, 32, 64}
		for _, length := range lengths {
			randBytes, err := kg.GenerateRandomBytes(length)
			if err != nil {
				t.Fatalf("生成%d字节随机数据失败: %v", length, err)
			}

			// 验证长度（Base64编码后长度会变）
			decoded, err := base64.StdEncoding.DecodeString(randBytes)
			if err != nil {
				t.Fatalf("解码失败: %v", err)
			}

			if len(decoded) != length {
				t.Errorf("预期生成%d字节,但实际得到%d字节", length, len(decoded))
			}
		}
	})

	// 2. 测试AES密钥生成
	t.Run("AESKey", func(t *testing.T) {
		// 测试有效的密钥大小
		validSizes := []int{128, 192, 256}
		for _, size := range validSizes {
			key, err := kg.GenerateAESKey(size)
			if err != nil {
				t.Fatalf("生成%d位AES密钥失败: %v", size, err)
			}

			// 验证长度
			decoded, _ := base64.StdEncoding.DecodeString(key)
			expectedBytes := size / 8
			if len(decoded) != expectedBytes {
				t.Errorf("预期生成%d字节AES密钥,但实际得到%d字节", expectedBytes, len(decoded))
			}
		}

		// 测试无效的密钥大小
		invalidSizes := []int{64, 100, 512}
		for _, size := range invalidSizes {
			_, err := kg.GenerateAESKey(size)
			if err == nil {
				t.Errorf("使用无效大小%d应当返回错误,但没有", size)
			}
		}
	})

	// 3. 测试DES密钥生成
	t.Run("DESKey", func(t *testing.T) {
		key, err := kg.GenerateDESKey()
		if err != nil {
			t.Fatalf("生成DES密钥失败: %v", err)
		}

		// 验证长度
		decoded, _ := base64.StdEncoding.DecodeString(key)
		if len(decoded) != 8 {
			t.Errorf("预期生成8字节DES密钥,但实际得到%d字节", len(decoded))
		}
	})

	// 4. 测试3DES密钥生成
	t.Run("3DESKey", func(t *testing.T) {
		key, err := kg.Generate3DESKey()
		if err != nil {
			t.Fatalf("生成3DES密钥失败: %v", err)
		}

		// 验证长度
		decoded, _ := base64.StdEncoding.DecodeString(key)
		if len(decoded) != 24 {
			t.Errorf("预期生成24字节3DES密钥,但实际得到%d字节", len(decoded))
		}
	})

	// 5. 测试IV生成
	t.Run("IV", func(t *testing.T) {
		blockSizes := []int{8, 16} // DES=8, AES=16
		for _, size := range blockSizes {
			iv, err := kg.GenerateIV(size)
			if err != nil {
				t.Fatalf("生成%d字节IV失败: %v", size, err)
			}

			// 验证长度
			decoded, _ := base64.StdEncoding.DecodeString(iv)
			if len(decoded) != size {
				t.Errorf("预期生成%d字节IV,但实际得到%d字节", size, len(decoded))
			}
		}
	})

	// 6. 测试盐值生成
	t.Run("Salt", func(t *testing.T) {
		lengths := []int{16, 32}
		for _, length := range lengths {
			salt, err := kg.GenerateSalt(length)
			if err != nil {
				t.Fatalf("生成%d字节盐值失败: %v", length, err)
			}

			// 验证长度
			decoded, _ := base64.StdEncoding.DecodeString(salt)
			if len(decoded) != length {
				t.Errorf("预期生成%d字节盐值,但实际得到%d字节", length, len(decoded))
			}
		}

		// 测试无效长度
		_, err := kg.GenerateSalt(4) // 太短
		if err == nil {
			t.Errorf("使用太短的盐值长度应当返回错误,但没有")
		}
	})

	// 7. 测试RSA密钥对生成
	t.Run("RSAKeyPair", func(t *testing.T) {
		// 使用短点的密钥以加快测试速度
		pubKey, privKey, err := kg.GenerateRSAKeyPair(1024)
		if err != nil {
			t.Fatalf("生成RSA密钥对失败: %v", err)
		}

		if pubKey == "" || privKey == "" {
			t.Fatalf("生成的RSA密钥对不应为空")
		}

		// 无法简单测试密钥格式,但我们可以确保它们编码正确
		_, err = base64.StdEncoding.DecodeString(pubKey)
		if err != nil {
			t.Errorf("RSA公钥编码格式无效: %v", err)
		}

		_, err = base64.StdEncoding.DecodeString(privKey)
		if err != nil {
			t.Errorf("RSA私钥编码格式无效: %v", err)
		}
	})

	// 8. 测试SM2密钥对生成
	t.Run("SM2KeyPair", func(t *testing.T) {
		pubKey, privKey, err := kg.GenerateSM2KeyPair()
		if err != nil {
			t.Fatalf("生成SM2密钥对失败: %v", err)
		}

		if pubKey == "" || privKey == "" {
			t.Fatalf("生成的SM2密钥对不应为空")
		}

		// SM2密钥是PEM格式,应该包含特定标记
		if !strings.Contains(pubKey, "PUBLIC KEY") {
			t.Errorf("SM2公钥格式无效,应为PEM格式")
		}

		if !strings.Contains(privKey, "PRIVATE KEY") {
			t.Errorf("SM2私钥格式无效,应为PEM格式")
		}
	})

	// 9. 测试不同编码方式
	t.Run("Encodings", func(t *testing.T) {
		// 创建一个16字节的随机数据,用不同编码方式输出
		sampleData := make([]byte, 16)
		for i := range sampleData {
			sampleData[i] = byte(i)
		}

		// 测试Hex编码
		hexKG := encrypt.NewKeyGenerator().Hex()
		hexOutput, err := hexKG.GenerateRandomBytes(16)
		if err != nil {
			t.Fatalf("Hex编码生成随机字节失败: %v", err)
		}

		// 验证是十六进制格式
		_, err = hex.DecodeString(hexOutput)
		if err != nil {
			t.Errorf("输出不是有效的十六进制格式: %v", err)
		}

		// 测试Base64安全编码
		base64SafeKG := encrypt.NewKeyGenerator().Base64Safe()
		base64SafeOutput, err := base64SafeKG.GenerateRandomBytes(16)
		if err != nil {
			t.Fatalf("Base64Safe编码生成随机字节失败: %v", err)
		}

		// 验证是Base64URL格式(不包含+和/)
		if strings.Contains(base64SafeOutput, "+") || strings.Contains(base64SafeOutput, "/") {
			t.Errorf("Base64Safe输出不应包含+或/字符")
		}

		// 测试无编码
		noEncodingKG := encrypt.NewKeyGenerator().NoEncoding()
		noEncodingOutput, err := noEncodingKG.GenerateRandomBytes(16)
		if err != nil {
			t.Fatalf("NoEncoding生成随机字节失败: %v", err)
		}

		// 验证长度是否正确(无编码直接返回字节,所以字符串长度应该正好是16)
		if len(noEncodingOutput) != 16 {
			t.Errorf("无编码输出长度应为16,实际为%d", len(noEncodingOutput))
		}
	})
}