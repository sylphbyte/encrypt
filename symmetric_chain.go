package encrypt

// 以下是链式调用方法实现

// ECB 设置ECB模式
func (a *AESEncryptor) ECB() ISymmetric {
	a.blockMode = NewECBMode()
	return a
}

// CBC 设置CBC模式
func (a *AESEncryptor) CBC() ISymmetric {
	a.blockMode = NewCBCMode(a.iv)
	return a
}

// CFB 设置CFB模式
func (a *AESEncryptor) CFB() ISymmetric {
	a.blockMode = NewCFBMode(a.iv)
	return a
}

// OFB 设置OFB模式
func (a *AESEncryptor) OFB() ISymmetric {
	a.blockMode = NewOFBMode(a.iv)
	return a
}

// CTR 设置CTR模式
func (a *AESEncryptor) CTR() ISymmetric {
	a.blockMode = NewCTRMode(a.iv)
	return a
}

// GCM 设置GCM模式
func (a *AESEncryptor) GCM() ISymmetric {
	a.blockMode = NewGCMMode()
	return a
}

// NoPadding 设置无填充
func (a *AESEncryptor) NoPadding() ISymmetric {
	a.padding = DefaultNoPadding
	return a
}

// PKCS7 设置PKCS7填充
func (a *AESEncryptor) PKCS7() ISymmetric {
	a.padding = DefaultPKCS7Padding
	return a
}

// ZeroPadding 设置零填充
func (a *AESEncryptor) ZeroPadding() ISymmetric {
	a.padding = DefaultZeroPadding
	return a
}

// NoEncoding 设置无编码
func (a *AESEncryptor) NoEncoding() ISymmetric {
	a.encoding = NoEncoding
	return a
}

// Base64 设置Base64编码
func (a *AESEncryptor) Base64() ISymmetric {
	a.encoding = Base64Encoding
	return a
}

// Base64Safe 设置安全的Base64编码
func (a *AESEncryptor) Base64Safe() ISymmetric {
	a.encoding = Base64Safe
	return a
}

// Hex 设置十六进制编码
func (a *AESEncryptor) Hex() ISymmetric {
	a.encoding = HexEncoding
	return a
}

// WithIV 设置初始化向量
func (a *AESEncryptor) WithIV(iv []byte) ISymmetric {
	a.iv = iv
	// 更新已设置的模式中的IV
	if a.blockMode != nil && a.blockMode.NeedsIV() {
		switch mode := a.blockMode.(type) {
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
	return a
}

// GetIV 获取初始化向量
func (a *AESEncryptor) GetIV() []byte {
	if a.iv == nil {
		return nil
	}
	
	ivCopy := make([]byte, len(a.iv))
	copy(ivCopy, a.iv)
	return ivCopy
}

// Algorithm 获取算法类型
func (a *AESEncryptor) Algorithm() Algorithm {
	return a.algorithm
}

// GetKey 获取密钥
func (a *AESEncryptor) GetKey() []byte {
	keyCopy := make([]byte, len(a.key))
	copy(keyCopy, a.key)
	return keyCopy
}

// DESEncryptor的链式调用方法 - 与AES类似

// ECB 设置ECB模式
func (d *DESEncryptor) ECB() ISymmetric {
	d.blockMode = NewECBMode()
	return d
}

// CBC 设置CBC模式
func (d *DESEncryptor) CBC() ISymmetric {
	d.blockMode = NewCBCMode(d.iv)
	return d
}

// CFB 设置CFB模式
func (d *DESEncryptor) CFB() ISymmetric {
	d.blockMode = NewCFBMode(d.iv)
	return d
}

// OFB 设置OFB模式
func (d *DESEncryptor) OFB() ISymmetric {
	d.blockMode = NewOFBMode(d.iv)
	return d
}

// CTR 设置CTR模式
func (d *DESEncryptor) CTR() ISymmetric {
	d.blockMode = NewCTRMode(d.iv)
	return d
}

// GCM 设置GCM模式
func (d *DESEncryptor) GCM() ISymmetric {
	d.blockMode = NewGCMMode()
	return d
}

// NoPadding 设置无填充
func (d *DESEncryptor) NoPadding() ISymmetric {
	d.padding = DefaultNoPadding
	return d
}

// PKCS7 设置PKCS7填充
func (d *DESEncryptor) PKCS7() ISymmetric {
	d.padding = DefaultPKCS7Padding
	return d
}

// ZeroPadding 设置零填充
func (d *DESEncryptor) ZeroPadding() ISymmetric {
	d.padding = DefaultZeroPadding
	return d
}

// NoEncoding 设置无编码
func (d *DESEncryptor) NoEncoding() ISymmetric {
	d.encoding = NoEncoding
	return d
}

// Base64 设置Base64编码
func (d *DESEncryptor) Base64() ISymmetric {
	d.encoding = Base64Encoding
	return d
}

// Base64Safe 设置安全的Base64编码
func (d *DESEncryptor) Base64Safe() ISymmetric {
	d.encoding = Base64Safe
	return d
}

// Hex 设置十六进制编码
func (d *DESEncryptor) Hex() ISymmetric {
	d.encoding = HexEncoding
	return d
}

// WithIV 设置初始化向量
func (d *DESEncryptor) WithIV(iv []byte) ISymmetric {
	d.iv = iv
	// 更新已设置的模式中的IV
	if d.blockMode != nil && d.blockMode.NeedsIV() {
		switch mode := d.blockMode.(type) {
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
	return d
}

// GetIV 获取初始化向量
func (d *DESEncryptor) GetIV() []byte {
	if d.iv == nil {
		return nil
	}
	
	ivCopy := make([]byte, len(d.iv))
	copy(ivCopy, d.iv)
	return ivCopy
}

// Algorithm 获取算法类型
func (d *DESEncryptor) Algorithm() Algorithm {
	return d.algorithm
}

// GetKey 获取密钥
func (d *DESEncryptor) GetKey() []byte {
	keyCopy := make([]byte, len(d.key))
	copy(keyCopy, d.key)
	return keyCopy
}

// TripleDESEncryptor的链式调用方法已经移到triple_des.go文件中实现