# Encrypt 加密库

`encrypt`是一个功能丰富、高性能且并发安全的Go语言加密库，支持多种加密算法和加密模式，提供内存池和并发池优化，同时保持易用的API设计。

## 主要特性

- **多种加密算法支持**：AES、DES、3DES、SM4、RSA、SM2
- **丰富的加密模式**：ECB、CBC、CFB、OFB、CTR、GCM
- **内存池优化**：减少内存分配，提高性能
- **并发安全**：线程安全的对象池和缓冲区
- **链式调用API**：简洁优雅的调用方式
- **灵活的工厂方法**：标准版本和Must版本可选

## 安装

```bash
go get github.com/sylphbyte/encrypt@v1.0.3
```

## 基本用法

### 对称加密示例 (AES)

```go
package main

import (
	"fmt"
	
	"github.com/sylphbyte/encrypt"
)

func main() {
	// 准备数据和密钥
	plaintext := []byte("Hello, Encrypt!")
	key := []byte("0123456789ABCDEF") // 16字节AES密钥
	
	// 方式1：标准工厂方法（需要错误处理）
	aes, err := encrypt.NewAES(key)
	if err != nil {
		fmt.Printf("创建AES加密器失败: %v\n", err)
		return
	}
	
	// 设置加密模式 - 默认CBC，可变更
	aes.CBC()
	
	// 加密
	ciphertext, err := aes.Encrypt(plaintext)
	if err != nil {
		fmt.Printf("加密失败: %v\n", err)
		return
	}
	
	// 解密
	decrypted, err := aes.Decrypt(ciphertext)
	if err != nil {
		fmt.Printf("解密失败: %v\n", err)
		return
	}
	
	fmt.Printf("原文: %s\n", plaintext)
	fmt.Printf("密文: %s\n", ciphertext)
	fmt.Printf("解密: %s\n", decrypted)
	
	// 使用完毕后释放资源回对象池
	aes.Release()
	
	// 方式2：Must版本工厂方法（参数错误时直接panic）
	// 适合初始化阶段使用，密钥参数确定的场景
	aes2 := encrypt.MustNewAES(key)
	aes2.CBC()
	
	// 使用完毕后释放资源
	aes2.Release()
}
```

### 并发安全版本示例

```go
package main

import (
	"fmt"
	"sync"
	
	"github.com/sylphbyte/encrypt"
)

func main() {
	// 准备数据和密钥
	plaintext := []byte("Hello, Concurrent Encrypt!")
	key := []byte("0123456789ABCDEF") // 16字节AES密钥
	
	// 初始化并发池（也可以不显式调用，首次使用时会自动初始化）
	encrypt.InitConcurrentPools()
	
	// 创建并发安全的AES加密器
	aes := encrypt.MustNewConcurrentAES(key)
	aes.CBC()
	
	// 并发使用
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			// 加密
			ciphertext, err := aes.Encrypt(plaintext)
			if err != nil {
				fmt.Printf("协程%d加密失败: %v\n", id, err)
				return
			}
			
			// 解密
			decrypted, err := aes.Decrypt(ciphertext)
			if err != nil {
				fmt.Printf("协程%d解密失败: %v\n", id, err)
				return
			}
			
			fmt.Printf("协程%d成功, 结果: %s\n", id, decrypted)
		}(i)
	}
	
	wg.Wait()
	
	// 查看池使用统计
	metrics := encrypt.GetPoolMetrics()
	fmt.Printf("池统计信息: %v\n", metrics)
	
	// 使用完毕后释放资源
	aes.Release()
}
```

## 支持的加密算法

### 对称加密

| 算法 | 标准工厂方法 | Must版本工厂方法 | 并发安全工厂方法 | Must版本并发安全工厂方法 |
|------|------------|---------------|---------------|--------------------|
| AES  | `NewAES(key []byte)` | `MustNewAES(key []byte)` | `NewConcurrentAES(key []byte)` | `MustNewConcurrentAES(key []byte)` |
| DES  | `NewDES(key []byte)` | `MustNewDES(key []byte)` | `NewConcurrentDES(key []byte)` | `MustNewConcurrentDES(key []byte)` |
| 3DES | `New3DES(key []byte)` | `MustNew3DES(key []byte)` | `NewConcurrent3DES(key []byte)` | `MustNewConcurrent3DES(key []byte)` |
| SM4  | `NewSM4(key []byte)` | `MustNewSM4(key []byte)` | `NewConcurrentSM4(key []byte)` | `MustNewConcurrentSM4(key []byte)` |

### 非对称加密

| 算法 | 标准工厂方法 | Must版本工厂方法 | 并发安全工厂方法 | Must版本并发安全工厂方法 |
|------|------------|---------------|---------------|--------------------|
| RSA  | `NewRSA()` | `MustNewRSA()` | `NewConcurrentRSA()` | `MustNewConcurrentRSA()` |
| SM2  | `NewSM2()` | `MustNewSM2()` | `NewConcurrentSM2()` | `MustNewConcurrentSM2()` |

## 支持的加密模式

对称加密算法支持以下加密模式：

- **ECB** - 电子密码本模式（不推荐用于生产环境）
- **CBC** - 密码分组链接模式
- **CFB** - 密码反馈模式
- **OFB** - 输出反馈模式
- **CTR** - 计数器模式
- **GCM** - 伽罗华计数器模式（仅AES支持）

链式调用示例：

```go
// 创建AES加密器并设置CTR模式
aes := encrypt.MustNewAES(key).CTR()
```

## 高级特性

### 并发安全对象池

并发安全对象池提供了高性能、内存安全的对象复用机制：

```go
// 初始化对象池（可选，默认第一次使用时自动初始化）
encrypt.InitConcurrentPools()

// 获取并发安全的缓冲区
buf := encrypt.GetConcurrentBuffer(1024)

// 使用完后归还缓冲区
encrypt.PutConcurrentBuffer(buf)

// 获取池使用统计信息
metrics := encrypt.GetPoolMetrics()
fmt.Printf("池统计信息: %v\n", metrics)
```

### 标准工厂方法 vs Must版本工厂方法

- **标准工厂方法**：返回错误，适合运行时生成密钥场景
- **Must版本工厂方法**：参数错误时直接panic，适合初始化阶段使用

```go
// 标准工厂方法 - 需要错误处理
aes, err := encrypt.NewAES(dynamicKey)  
if err != nil {
    // 处理错误
}

// Must版本 - 参数错误时直接panic
aes := encrypt.MustNewAES(fixedKey)  // 初始化阶段使用
```

## 最佳实践

1. **选择合适的工厂方法**
   - 初始化阶段、密钥确定时：使用`MustNewXXX`方法
   - 运行时动态生成密钥：使用`NewXXX`方法并处理错误

2. **合理使用并发安全版本**
   - 高并发场景：使用`NewConcurrentXXX`或`MustNewConcurrentXXX`
   - 低并发场景：普通版本足够

3. **正确释放资源**
   - 使用完加密器后调用`Release()`将对象归还给池
   - 使用完缓冲区后调用`PutConcurrentBuffer()`或`ReleaseConcurrentBuffer()`

4. **注意IV初始化**
   - 实际加密前设置好加密模式（如`.CBC()`）
   - 库会自动初始化合适的IV

## 错误处理

库使用`github.com/pkg/errors`进行错误处理，提供详细错误信息和堆栈跟踪。常见错误：

- 密钥长度不正确
- IV长度与块大小不匹配
- 加密/解密过程中的错误

示例：

```go
aes, err := encrypt.NewAES(key)
if err != nil {
    // 输出详细错误信息
    fmt.Printf("错误: %+v\n", err)
    return
}
```

## 许可证

MIT