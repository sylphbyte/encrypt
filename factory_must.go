package encrypt

// 提供带Must前缀的工厂方法，用于简化调用
// 这些方法在参数错误时会直接panic，适合在初始化阶段使用

// MustNewAES 创建新的AES加密器，出错时直接panic
func MustNewAES(key []byte) ISymmetric {
	encryptor, err := NewAES(key)
	if err != nil {
		panic(err)
	}
	return encryptor
}

// MustNewDES 创建新的DES加密器，出错时直接panic
func MustNewDES(key []byte) ISymmetric {
	encryptor, err := NewDES(key)
	if err != nil {
		panic(err)
	}
	return encryptor
}

// MustNew3DES 创建新的3DES加密器，出错时直接panic
func MustNew3DES(key []byte) ISymmetric {
	encryptor, err := New3DES(key)
	if err != nil {
		panic(err)
	}
	return encryptor
}

// MustNewSM4 创建新的SM4加密器，出错时直接panic
func MustNewSM4(key []byte) ISymmetric {
	encryptor, err := NewSM4(key)
	if err != nil {
		panic(err)
	}
	return encryptor
}

// MustNewRSA 创建新的RSA加密器，出错时直接panic
func MustNewRSA() IAsymmetric {
	encryptor, err := NewRSA()
	if err != nil {
		panic(err)
	}
	return encryptor
}

// MustNewSM2 创建新的SM2加密器，出错时直接panic
func MustNewSM2() IAsymmetric {
	encryptor, err := NewSM2()
	if err != nil {
		panic(err)
	}
	return encryptor
}

// MustNewConcurrentAES 创建新的线程安全AES加密器，出错时直接panic
func MustNewConcurrentAES(key []byte) ISymmetric {
	encryptor, err := NewConcurrentAES(key)
	if err != nil {
		panic(err)
	}
	return encryptor
}

// MustNewConcurrentDES 创建新的线程安全DES加密器，出错时直接panic
func MustNewConcurrentDES(key []byte) ISymmetric {
	encryptor, err := NewConcurrentDES(key)
	if err != nil {
		panic(err)
	}
	return encryptor
}

// MustNewConcurrent3DES 创建新的线程安全3DES加密器，出错时直接panic
func MustNewConcurrent3DES(key []byte) ISymmetric {
	encryptor, err := NewConcurrent3DES(key)
	if err != nil {
		panic(err)
	}
	return encryptor
}

// MustNewConcurrentSM4 创建新的线程安全SM4加密器，出错时直接panic
func MustNewConcurrentSM4(key []byte) ISymmetric {
	encryptor, err := NewConcurrentSM4(key)
	if err != nil {
		panic(err)
	}
	return encryptor
}

// MustNewConcurrentRSA 创建新的线程安全RSA加密器，出错时直接panic
func MustNewConcurrentRSA() IAsymmetric {
	encryptor, err := NewConcurrentRSA()
	if err != nil {
		panic(err)
	}
	return encryptor
}

// MustNewConcurrentSM2 创建新的线程安全SM2加密器，出错时直接panic
func MustNewConcurrentSM2() IAsymmetric {
	encryptor, err := NewConcurrentSM2()
	if err != nil {
		panic(err)
	}
	return encryptor
}