package tests

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	"github.com/sylphbyte/encrypt"
)

// TestSM3Features 测试SM3哈希算法功能
func TestSM3Features(t *testing.T) {
	// 1. 测试字符串哈希
	t.Run("字符串哈希", func(t *testing.T) {
		data := []byte("测试SM3国密哈希算法")
		hasher := encrypt.NewSM3()
		
		// 使用不同编码测试
		hashFuncs := []struct {
			name      string
			hasher    func() *encrypt.SM3Hasher
			validator func(string) bool
		}{
			{"Base64", func() *encrypt.SM3Hasher { 
				return hasher.Base64() 
			}, func(s string) bool {
				_, err := base64.StdEncoding.DecodeString(s)
				return err == nil
			}},
			{"Base64Safe", func() *encrypt.SM3Hasher { 
				return hasher.Base64Safe() 
			}, func(s string) bool {
				_, err := base64.URLEncoding.DecodeString(s)
				return err == nil
			}},
			{"Hex", func() *encrypt.SM3Hasher { 
				return hasher.Hex() 
			}, func(s string) bool {
				_, err := hex.DecodeString(s)
				return err == nil && len(s) == 64 // SM3哈希值为32字节，十六进制编码后为64个字符
			}},
			{"NoEncoding", func() *encrypt.SM3Hasher { 
				return hasher.NoEncoding() 
			}, func(s string) bool {
				return len(s) == 32 // SM3哈希值为32字节
			}},
		}
		
		for _, test := range hashFuncs {
			t.Run(test.name, func(t *testing.T) {
				h := test.hasher()
				hashValue, err := h.Sum(data)
				if err != nil {
					t.Fatalf("%s计算哈希失败: %v", test.name, err)
				}
				
				// 验证编码格式
				if !test.validator(hashValue) {
					t.Errorf("%s编码格式验证失败", test.name)
				}
				
				t.Logf("%s哈希值: %s", test.name, hashValue)
			})
		}
		
		// 一致性测试
		t.Run("一致性测试", func(t *testing.T) {
			h := encrypt.NewSM3().Hex() // 使用Hex方便直接比较
			
			hash1, err := h.Sum(data)
			if err != nil {
				t.Fatalf("第一次计算哈希失败: %v", err)
			}
			
			hash2, err := h.Sum(data)
			if err != nil {
				t.Fatalf("第二次计算哈希失败: %v", err)
			}
			
			if hash1 != hash2 {
				t.Errorf("两次计算结果不一致:\n%s\n%s", hash1, hash2)
			}
		})
	})
	
	// 2. 测试文件哈希
	t.Run("文件哈希", func(t *testing.T) {
		// 创建临时测试文件
		testFileName := "testfile_for_sm3.txt"
		testData := []byte("这是一个用于测试SM3文件哈希的测试文件，包含中文和特殊字符：!@#$%^&*()")
		
		err := os.WriteFile(testFileName, testData, 0644)
		if err != nil {
			t.Fatalf("创建测试文件失败: %v", err)
		}
		defer os.Remove(testFileName) // 测试完成后清理
		
		// 计算文件哈希
		hasher := encrypt.NewSM3().Hex()
		hashValue, err := hasher.File(testFileName)
		if err != nil {
			t.Fatalf("计算文件哈希失败: %v", err)
		}
		
		// 验证哈希格式
		if len(hashValue) != 64 { // SM3哈希值为32字节，十六进制编码后为64个字符
			t.Errorf("哈希值长度不正确: %d", len(hashValue))
		}
		
		// 验证与直接计算数据哈希的一致性
		dataHash, err := hasher.Sum(testData)
		if err != nil {
			t.Fatalf("计算数据哈希失败: %v", err)
		}
		
		if hashValue != dataHash {
			t.Errorf("文件哈希与数据哈希不一致:\n文件: %s\n数据: %s", hashValue, dataHash)
		}
		
		t.Logf("文件哈希值: %s", hashValue)
	})
	
	// 3. 测试空数据
	t.Run("空数据", func(t *testing.T) {
		hasher := encrypt.NewSM3().Hex()
		hashValue, err := hasher.Sum([]byte{})
		if err != nil {
			t.Fatalf("计算空数据哈希失败: %v", err)
		}
		
		t.Logf("空数据哈希值: %s", hashValue)
	})
}