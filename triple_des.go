package encrypt

// TripleDESEncryptor 3DES加密实现的完整方法

// Algorithm 获取算法类型
func (t *TripleDESEncryptor) Algorithm() Algorithm {
	return t.algorithm
}

// GetKey 获取密钥
func (t *TripleDESEncryptor) GetKey() []byte {
	keyCopy := make([]byte, len(t.key))
	copy(keyCopy, t.key)
	return keyCopy
}

// GetIV 获取初始化向量
func (t *TripleDESEncryptor) GetIV() []byte {
	if t.iv == nil {
		return nil
	}
	
	ivCopy := make([]byte, len(t.iv))
	copy(ivCopy, t.iv)
	return ivCopy
}

// ECB 设置ECB模式
func (t *TripleDESEncryptor) ECB() ISymmetric {
	t.blockMode = NewECBMode()
	return t
}

// CBC 设置CBC模式
func (t *TripleDESEncryptor) CBC() ISymmetric {
	t.blockMode = NewCBCMode(t.iv)
	return t
}

// CFB 设置CFB模式
func (t *TripleDESEncryptor) CFB() ISymmetric {
	t.blockMode = NewCFBMode(t.iv)
	return t
}

// OFB 设置OFB模式
func (t *TripleDESEncryptor) OFB() ISymmetric {
	t.blockMode = NewOFBMode(t.iv)
	return t
}

// CTR 设置CTR模式
func (t *TripleDESEncryptor) CTR() ISymmetric {
	t.blockMode = NewCTRMode(t.iv)
	return t
}

// GCM 设置GCM模式
func (t *TripleDESEncryptor) GCM() ISymmetric {
	t.blockMode = NewGCMMode()
	return t
}

// NoPadding 设置无填充
func (t *TripleDESEncryptor) NoPadding() ISymmetric {
	t.padding = DefaultNoPadding
	return t
}

// PKCS7 设置PKCS7填充
func (t *TripleDESEncryptor) PKCS7() ISymmetric {
	t.padding = DefaultPKCS7Padding
	return t
}

// ZeroPadding 设置零填充
func (t *TripleDESEncryptor) ZeroPadding() ISymmetric {
	t.padding = DefaultZeroPadding
	return t
}

// NoEncoding 设置无编码
func (t *TripleDESEncryptor) NoEncoding() ISymmetric {
	t.encoding = NoEncoding
	return t
}

// Base64 设置Base64编码
func (t *TripleDESEncryptor) Base64() ISymmetric {
	t.encoding = Base64Encoding
	return t
}

// Base64Safe 设置安全的Base64编码
func (t *TripleDESEncryptor) Base64Safe() ISymmetric {
	t.encoding = Base64Safe
	return t
}

// Hex 设置十六进制编码
func (t *TripleDESEncryptor) Hex() ISymmetric {
	t.encoding = HexEncoding
	return t
}

// WithIV 设置初始化向量
func (t *TripleDESEncryptor) WithIV(iv []byte) ISymmetric {
	t.iv = iv
	// 更新已设置的模式中的IV
	if t.blockMode != nil && t.blockMode.NeedsIV() {
		switch mode := t.blockMode.(type) {
		case *CBCMode:
			mode.iv = iv
		case *CFBMode:
			mode.iv = iv
		case *OFBMode:
			mode.iv = iv
		case *CTRMode:
			mode.iv = iv
		}
	}
	return t
}