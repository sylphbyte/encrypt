# Sylph 加密库

一个功能全面的Go语言加密库，提供对称和非对称加密算法，包括AES、DES、3DES、RSA和SM2国密算法。设计理念是提供简洁、链式的API，便于快速集成和使用。

## 特性

- **对称加密**：支持AES、DES、3DES和SM4国密算法
- **非对称加密**：支持RSA和SM2国密算法
- **哈希算法**：支持SM3国密哈希算法
- **密钥派生**：支持PBKDF2密钥派生，包括SM3哈希支持
- **多种模式**：支持ECB、CBC、CFB、OFB、CTR、GCM等工作模式
- **灵活填充**：支持PKCS7、Zero等填充方式
- **多种编码**：支持Base64、Hex等编码格式
- **密钥生成**：内置工具生成各类密钥和IV
- **链式API**：简洁优雅的调用方式

## 安装

```bash
go get github.com/sylphbyte/encrypt
```

## 基本使用

### 对称加密示例

#### AES 加密

```go
package main

import (
	"fmt"

	"github.com/sylphbyte/encrypt"
)

func main() {
	// 创建AES加密器
	key := []byte("0123456789abcdef") // 16字节的AES-128密钥
	aes, err := encrypt.NewAES(key)
	if err != nil {
		panic(err)
	}

	// 设置加密选项（链式调用）
	aes = aes.CBC().PKCS7().Base64()

	// 加密数据
	plaintext := []byte("需要加密的数据")
	ciphertext, err := aes.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	fmt.Println("加密结果:", ciphertext)

	// 解密数据
	decrypted, err := aes.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println("解密结果:", string(decrypted))
}
```

#### DES 加密

```go
// 创建DES加密器
key := []byte("01234567") // 8字节的DES密钥
des, err := encrypt.NewDES(key)
if err != nil {
	panic(err)
}

// 设置加密选项
des = des.CBC().PKCS7().Hex()

// 加密和解密操作与AES类似
```

#### SM4 国密算法加密

```go
package main

import (
	"fmt"

	"github.com/sylphbyte/encrypt"
)

func main() {
	// 创建SM4加密器
	key := []byte("0123456789abcdef") // 16字节的SM4密钥
	sm4, err := encrypt.NewSM4(key)
	if err != nil {
		panic(err)
	}

	// 设置加密选项（链式调用）
	sm4 = sm4.CBC().PKCS7().Base64()

	// 加密数据
	plaintext := []byte("需要加密的数据")
	ciphertext, err := sm4.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	fmt.Println("加密结果:", ciphertext)

	// 解密数据
	decrypted, err := sm4.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println("解密结果:", string(decrypted))

	// SM4支持多种模式
	// 使用GCM模式（无需填充，自带认证）
	sm4GCM := sm4.GCM().Base64Safe()
	ciphertext2, err := sm4GCM.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	fmt.Println("GCM模式加密结果:", ciphertext2)
}
```

### 非对称加密示例

#### RSA 加密和签名

```go
package main

import (
	"fmt"

	"github.com/sylphbyte/encrypt"
)

func main() {
	// 创建RSA加密器
	rsa, err := encrypt.NewRSA()
	if err != nil {
		panic(err)
	}

	// 设置密钥大小并生成密钥对
	rsa = rsa.WithKeySize(2048).Base64()
	pubKey, privKey, err := rsa.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	// 使用公钥加密
	plaintext := []byte("RSA加密测试数据")
	ciphertext, err := rsa.WithPublicKey(pubKey).Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	// 使用私钥解密
	decrypted, err := rsa.WithPrivateKey(privKey).Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println("解密结果:", string(decrypted))

	// 使用私钥签名
	signature, err := rsa.Sign(plaintext)
	if err != nil {
		panic(err)
	}

	// 使用公钥验证签名
	valid, err := rsa.WithPublicKey(pubKey).Verify(plaintext, signature)
	if err != nil {
		panic(err)
	}

	fmt.Println("签名验证:", valid)
}
```

#### SM2 国密算法加密和签名

```go
package main

import (
	"fmt"

	"github.com/sylphbyte/encrypt"
)

func main() {
	// 创建SM2加密器
	sm2, err := encrypt.NewSM2()
	if err != nil {
		panic(err)
	}

	// 生成密钥对
	sm2 = sm2.Base64()
	pubKey, privKey, err := sm2.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	// 使用公钥加密
	plaintext := []byte("SM2加密测试数据")
	ciphertext, err := sm2.WithPublicKey(pubKey).Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	// 使用私钥解密
	decrypted, err := sm2.WithPrivateKey(privKey).Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println("解密结果:", string(decrypted))

	// 自定义用户ID（可选）
	customUID := []byte("custom-uid-12345678")
	sm2WithUID := sm2.WithPrivateKey(privKey).WithPublicKey(pubKey).WithUID(customUID)

	// 使用私钥签名
	signature, err := sm2WithUID.Sign(plaintext)
	if err != nil {
		panic(err)
	}

	// 使用公钥验证签名（必须使用相同的UID）
	valid, err := sm2WithUID.Verify(plaintext, signature)
	if err != nil {
		panic(err)
	}

	fmt.Println("签名验证:", valid)
}
```

### 密钥生成工具使用

```go
package main

import (
	"fmt"

	"github.com/sylphbyte/encrypt"
)

func main() {
	// 创建密钥生成器
	kg := encrypt.NewKeyGenerator()

	// 生成对称加密密钥
	aesKey128, _ := kg.GenerateAESKey(128) // 16字节
	aesKey256, _ := kg.GenerateAESKey(256) // 32字节
	desKey, _ := kg.GenerateDESKey()      // 8字节
	des3Key, _ := kg.Generate3DESKey()     // 24字节
	sm4Key, _ := kg.GenerateSM4Key()       // 16字节

	fmt.Println("AES-128密钥:", aesKey128)
	fmt.Println("AES-256密钥:", aesKey256)
	fmt.Println("DES密钥:", desKey)
	fmt.Println("3DES密钥:", des3Key)
	fmt.Println("SM4密钥:", sm4Key)

	// 生成初始化向量
	aesIV, _ := kg.GenerateIV(16) // AES/SM4的块大小为16字节
	desIV, _ := kg.GenerateIV(8)  // DES的块大小为8字节

	fmt.Println("AES/SM4 IV:", aesIV)
	fmt.Println("DES IV:", desIV)

	// 生成盐值（用于密码哈希等）
	salt, _ := kg.GenerateSalt(16)
	fmt.Println("Salt:", salt)

	// 更改编码格式
	hexKG := kg.Hex() // 使用十六进制编码
	hexKey, _ := hexKG.GenerateAESKey(128)
	fmt.Println("十六进制AES密钥:", hexKey)

	// 生成RSA密钥对
	rsaPub, rsaPriv, _ := kg.GenerateRSAKeyPair(2048)
	fmt.Println("RSA公钥:", rsaPub)
	fmt.Println("RSA私钥:", rsaPriv)

	// 生成SM2密钥对
	sm2Pub, sm2Priv, _ := kg.GenerateSM2KeyPair()
	fmt.Println("SM2公钥:", sm2Pub)
	fmt.Println("SM2私钥:", sm2Priv)
}
```

### PBKDF2密钥派生

```go
package main

import (
	"fmt"

	"github.com/sylphbyte/encrypt"
)

func main() {
	// 创建PBKDF2派生器
	deriver := encrypt.NewPBKDF2()

	// 设置使用SM3国密算法进行哈希（默认使用SHA256）
	deriver = deriver.SM3().Hex()

	// 从密码派生一个密钥
	password := []byte("用户密码")
	salt := []byte("随机盐值12345")
	iterations := 10000       // 迭代次数，推荐至少10000次
	keyLength := 32           // 生成32字节(256位)的密钥

	key, err := deriver.DeriveKey(password, salt, iterations, keyLength)
	if err != nil {
		panic(err)
	}

	fmt.Println("派生的密钥:", key)

	// 使用派生的密钥创建AES加密器
	// 注意：要改用NoEncoding获取原始字节
	deriverRaw := encrypt.NewPBKDF2().NoEncoding()
	keyBytes, _ := deriverRaw.DeriveKey(password, salt, iterations, keyLength)

	aes, _ := encrypt.NewAES([]byte(keyBytes))
	// 现在可以使用这个AES加密器进行加密和解密
	ciphertext, _ := aes.CBC().PKCS7().Base64().Encrypt([]byte("使用密码派生的密钥加密的数据"))
	fmt.Println("加密结果:", ciphertext)
}
```

### SM3哈希算法

```go
package main

import (
	"fmt"

	"github.com/sylphbyte/encrypt"
)

func main() {
	// 创建SM3哈希器
	hasher := encrypt.NewSM3()

	// 计算字符串哈希值（默认Base64编码）
	data := []byte("需要计算哈希的数据")
	hashValue, err := hasher.Sum(data)
	if err != nil {
		panic(err)
	}

	fmt.Println("SM3哈希值(Base64):", hashValue)

	// 使用十六进制编码
	hexHasher := hasher.Hex()
	hexHash, _ := hexHasher.Sum(data)
	fmt.Println("SM3哈希值(Hex):", hexHash)

	// 计算文件哈希值
	filePath := "/path/to/file.txt"
	fileHash, err := hexHasher.File(filePath)
	if err != nil {
		panic(err)
	}

	fmt.Println("文件SM3哈希值:", fileHash)
}
```

## 高级用法

### 自定义初始化向量（IV）

```go
// 创建AES加密器
key := []byte("0123456789abcdef")
aes, _ := encrypt.NewAES(key)

// 设置自定义IV
customIV := []byte("abcdefghijklmnop") // 必须是16字节
aes = aes.CBC().PKCS7().WithIV(customIV)

// 执行加密和解密
```

### 组合不同的工作模式、填充和编码

```go
// 组合1：使用CTR模式，无填充，Base64编码
aes = aes.CTR().NoPadding().Base64()

// 组合2：使用ECB模式，Zero填充，十六进制编码
aes = aes.ECB().ZeroPadding().Hex()

// 组合3：使用OFB模式，PKCS7填充，无编码
aes = aes.OFB().PKCS7().NoEncoding()
```

## 工作模式支持

| 加密算法 | ECB | CBC | CFB | OFB | CTR | GCM |
|---------|-----|-----|-----|-----|-----|-----|
| AES     | ✓   | ✓   | ✓   | ✓   | ✓   | ✓   |
| DES     | ✓   | ✓   | ✓   | ✓   | ✓   | ✗   |
| 3DES    | ✓   | ✓   | ✓   | ✓   | ✓   | ✗   |
| SM4     | ✓   | ✓   | ✓   | ✓   | ✓   | ✓   |

## 填充方式支持

- **PKCS7**: 填充到块大小的整数倍，填充值为缺少的字节数
- **Zero**: 使用0值填充
- **NoPadding**: 无填充，要求原始数据必须是块大小的整数倍

## 编码格式支持

- **Base64**: 标准Base64编码
- **Base64Safe**: URL安全的Base64编码（替换'+'为'-', '/'为'_'）
- **Hex**: 十六进制编码
- **NoEncoding**: 无编码，返回原始字节

## 哈希算法支持

| 哈希算法 | 输出长度 | 说明 |
|---------|---------|------|
| SHA1    | 20字节   | 通过PBKDF2支持 |
| SHA256  | 32字节   | 通过PBKDF2支持 |
| SHA512  | 64字节   | 通过PBKDF2支持 |
| SM3     | 32字节   | 国密哈希算法，直接支持及通过PBKDF2支持 |

## 算法安全建议

- 生产环境中避免使用ECB模式，推荐CBC、GCM等模式
- 对称加密推荐使用AES-256或SM4
- 非对称加密RSA密钥长度至少2048位
- PBKDF2迭代次数建议至少10000次
- 所有密钥、IV和盐值应该使用安全的随机数生成器生成

## 许可证

本项目采用MIT许可证。详情请参阅LICENSE文件。