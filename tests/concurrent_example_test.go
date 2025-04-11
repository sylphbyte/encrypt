package tests

import (
	"fmt"
	"sync"
	"testing"

	"github.com/sylphbyte/encrypt"
)

// TestConcurrentEncryptionExample 测试并发加密的实际应用场景
func TestConcurrentEncryptionExample(t *testing.T) {
	// 初始化并发对象池
	encrypt.InitConcurrentPools()

	// 测试不同长度的测试数据
	plaintexts := [][]byte{
		[]byte("这是一个短文本"),
		[]byte("这是一个中等长度的文本，用来测试加密性能"),
		[]byte("这是一个长文本，包含多行内容。\n第二行内容。\n第三行内容。\n用来测试加密性能和内存使用情况。"),
	}

	// 不同算法的密钥
	aesKey := []byte("0123456789abcdef") // 16字节AES密钥
	desKey := []byte("abcdef12")         // 8字节DES密钥
	sm4Key := []byte("0123456789abcdef") // 16字节SM4密钥

	// 并行加密所有测试数据
	var wg sync.WaitGroup
	
	// 创建3个协程，每组使用不同算法
	goroutines := 3
	
	// 统计成功和失败的操作数
	success := make([]int, goroutines)
	failed := make([]int, goroutines)
	
	// 启动并发协程
	for r := 0; r < goroutines; r++ {
		wg.Add(1)
		go func(routineID int) {
			defer wg.Done()
			
			algoName := "未知"
			switch routineID % 3 {
			case 0:
				algoName = "AES"
			case 1:
				algoName = "DES"
			case 2:
				algoName = "SM4"
			}
			
			// 对每个文本执行加密/解密操作
			for i := 0; i < 100; i++ {
				// 选择不同的测试文本
				plaintext := plaintexts[i%len(plaintexts)]
				
				var encryptor encrypt.ISymmetric
				var err error
				
				// 根据协程组选择不同的算法
				switch routineID % 3 {
				case 0: // AES
					encryptor, err = encrypt.NewConcurrentAES(aesKey)
				case 1: // DES
					encryptor, err = encrypt.NewConcurrentDES(desKey)
				case 2: // SM4
					encryptor, err = encrypt.NewConcurrentSM4(sm4Key)
				}
				
				if err != nil {
					t.Logf("协程 %d-%s: 创建加密器失败: %v", routineID, algoName, err)
					failed[routineID]++
					continue
				}
				
				// 加密
				ciphertext, err := encryptor.CBC().PKCS7().Base64().Encrypt(plaintext)
				if err != nil {
					t.Logf("协程 %d-%s: 加密失败: %v", routineID, algoName, err)
					failed[routineID]++
					// 释放加密器
					encryptor.Release()
					continue
				}
				
				// 解密
				decrypted, err := encryptor.Decrypt(ciphertext)
				if err != nil {
					t.Logf("协程 %d-%s: 解密失败: %v", routineID, algoName, err)
					failed[routineID]++
					// 释放加密器
					encryptor.Release()
					continue
				}
				
				// 验证解密结果
				if string(decrypted) != string(plaintext) {
					t.Logf("协程 %d-%s: 解密结果不匹配，原文长度=%d, 解密后长度=%d", 
						routineID, algoName, len(plaintext), len(decrypted))
					failed[routineID]++
				} else {
					success[routineID]++
				}
				
				// 释放加密器
				encryptor.Release()
			}
		}(r)
	}
	
	// 等待所有协程完成
	wg.Wait()
	
	// 输出测试统计数据
	total := 0
	for i := 0; i < goroutines; i++ {
		algoName := "未知"
		switch i % 3 {
		case 0:
			algoName = "AES"
		case 1:
			algoName = "DES"
		case 2:
			algoName = "SM4"
		}
		t.Logf("协程 %d(%s): 成功=%d, 失败=%d", i, algoName, success[i], failed[i])
		total += success[i]
	}
	
	// 获取池统计数据
	metrics := encrypt.GetPoolMetrics()
	t.Logf("池统计信息: %+v", metrics)
	
	// 执行简单断言以验证测试成功
	if total < goroutines*50 { // 至少应该有50%的测试成功
		t.Errorf("测试成功率太低: %d/%d", total, goroutines*100)
	}
}

// TestConcurrentBufferPoolExample 测试并发字节缓冲区池的应用场景
func TestConcurrentBufferPoolExample(t *testing.T) {
	// 初始化并发对象池
	encrypt.InitConcurrentPools()
	
	// 定义不同大小的数据块
	sizes := []int{1024, 4096, 16384, 65536}
	
	// 并发测试
	var wg sync.WaitGroup
	goroutines := 20
	operations := 1000
	
	// 记录测试结果
	allocs := 0
	reuses := 0
	
	// 使用互斥锁保护统计变量
	mutex := &sync.Mutex{}
	
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			// 每个协程执行多次缓冲区获取和释放
			for j := 0; j < operations; j++ {
				// 选择一个大小
				size := sizes[(id+j)%len(sizes)]
				
				// 从池中获取缓冲区
				buf := encrypt.GetConcurrentBuffer(size)
				
				// 确保缓冲区大小正确
				if len(buf) != size {
					t.Errorf("协程 %d: 缓冲区大小错误, 期望 %d, 实际 %d", id, size, len(buf))
				}
				
				// 记录有多少数据是创建的而非复用的
				if cap(buf) == size {
					// 设置一个标记，标识这个是新创建的
					mutex.Lock()
					allocs++
					mutex.Unlock()
				} else {
					mutex.Lock()
					reuses++
					mutex.Unlock()
				}
				
				// 使用缓冲区，写入一些数据
				for k := 0; k < len(buf); k += 256 {
					endIndex := k + 256
					if endIndex > len(buf) {
						endIndex = len(buf)
					}
					for m := k; m < endIndex; m++ {
						buf[m] = byte(m % 256)
					}
				}
				
				// 归还缓冲区
				encrypt.PutConcurrentBuffer(buf)
			}
		}(i)
	}
	
	// 等待所有协程完成
	wg.Wait()
	
	// 输出统计信息
	t.Logf("统计信息: 新分配=%d, 复用=%d, 复用率=%.2f%%", 
		allocs, reuses, float64(reuses)/float64(allocs+reuses)*100)
	
	// 获取池统计数据
	metrics := encrypt.GetPoolMetrics()
	t.Logf("池统计信息: %+v", metrics["Buffer"])
	
	// 断言没有泄漏的活跃对象
	if metrics["Buffer"]["active"] != 0 {
		t.Errorf("存在泄漏的缓冲区: %d", metrics["Buffer"]["active"])
	}
}

// ExampleConcurrentPools 并发安全对象池的使用示例
func ExampleConcurrentPools() {
	// 初始化并发对象池
	encrypt.InitConcurrentPools()
	
	// 创建并发安全的AES加密器
	aesKey := []byte("0123456789abcdef") // 16字节AES密钥
	aes, _ := encrypt.NewConcurrentAES(aesKey)
	
	// 加密数据
	plaintext := []byte("这是一个简单的测试消息")
	ciphertext, _ := aes.CBC().PKCS7().Base64().Encrypt(plaintext)
	
	// 解密数据
	decrypted, _ := aes.Decrypt(ciphertext)
	
	// 打印结果
	fmt.Printf("加密结果: %s\n", ciphertext)
	fmt.Printf("解密结果: %s\n", decrypted)
	
	// 释放加密器
	aes.Release()
	
	// Output:
}