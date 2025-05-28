package secret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

type AesSecret struct {
}

func (a *AesSecret) Encrypt(secretKey string, value string) (string, error) {
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", fmt.Errorf("创建AES加密块失败: %w", err)
	}

	// 生成随机IV
	iv, err := generateIV(block)
	if err != nil {
		return "", fmt.Errorf("生成随机IV失败: %w", err)
	}

	// PKCS7填充
	paddedText := pkcs7Padding([]byte(value), block.BlockSize())

	// 加密
	ciphertext := make([]byte, len(paddedText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedText)

	// 返回 Base64 编码的结果（包含 IV 和密文）
	encrypted := append(iv, ciphertext...)
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (a *AesSecret) Decrypt(secretKey string, secretValue string) (string, error) {
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", fmt.Errorf("创建AES加密块失败: %w", err)
	}

	// Base64 解码
	encryptedBytes, err := base64.StdEncoding.DecodeString(secretValue)
	if err != nil {
		return "", fmt.Errorf("Base64解码失败: %w", err)
	}
	// 分离IV和密文
	blockSize := block.BlockSize()
	if len(encryptedBytes) < blockSize {
		return "", fmt.Errorf("密文长度不足")
	}
	iv := encryptedBytes[:blockSize]
	ciphertext := encryptedBytes[blockSize:]

	// 解密
	decrypted := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, ciphertext)

	// PKCS7解填充
	decrypted, err = pkcs7Unpadding(decrypted)
	if err != nil {
		return "", fmt.Errorf("解填充失败: %w", err)
	}
	return string(decrypted), nil
}

// PKCS7 填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// PKCS7 解填充
func pkcs7Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("解密后的数据为空")
	}
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, fmt.Errorf("解填充失败，填充字节数超过数据长度")
	}
	return data[:(length - unpadding)], nil
}

// 生成随机IV
func generateIV(block cipher.Block) ([]byte, error) {
	iv := make([]byte, block.BlockSize())
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}
	return iv, nil
}
