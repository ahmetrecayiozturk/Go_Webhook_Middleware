package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Cipher, veritabanında saklanan secret ve target_headers alanlarını AES-256-GCM ile şifreler/çözer.
type Cipher struct {
	// Bu  AES-256-GCM şifreleme algoritmasını kullanabilmek için 32 byte uzunluğunda bir anahtar gereklidir.
	// Bu anahtar, veritabanında saklanan secret ve target_headers alanlarını şifrelemek ve çözmek için kullanılır.
	// Cipher struct'ı, bu anahtarı ve AES-256-GCM şifreleme algoritmasını kullanarak verileri güvenli bir şekilde şifreler ve çözer.
	aead cipher.AEAD
}

// NewCipher, 64 karakterlik hex (32 byte = AES-256) master key ile yeni bir Cipher oluşturur.
func NewCipher(hexKey string) (*Cipher, error) {
	// Gelen hex key'i byte array'e çevir
	key, err := hex.DecodeString(hexKey)
	// Hata gelirse patlat
	if err != nil {
		return nil, fmt.Errorf("invalid hex key: %w", err)
	}

	// Key 32'lik değilse patlat
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}

	// AES cipher block oluştur,  bu şudur ki: AES (Advanced Encryption Standard), simetrik bir şifreleme algoritmasıdır ve verileri bloklar halinde şifreler.
	// AES-256, 256 bit (32 byte) uzunluğunda bir anahtar kullanır ve bu nedenle oldukça güvenlidir.
	// AES cipher block, verileri şifrelemek ve çözmek için kullanılan temel yapı taşlarından biridir.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	// AES-GCM oluştur, bu şudur ki: AES-GCM, AES şifreleme algoritmasının bir modudur ve Galois/Counter Mode (GCM) olarak adlandırılır.
	// GCM, hem veri bütünlüğünü hem de gizliliği sağlar. Yani, şifrelenmiş verinin değiştirilmediğini doğrulamak için bir doğrulama etiketi (authentication tag) ekler.
	// Bu sayede, verinin hem gizliliği korunur hem de bütünlüğü sağlanır.
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Cipher struct'ını döndür
	return &Cipher{aead: aead}, nil
}

func (c *Cipher) Encrypt(plaintext string) (string, error) {
	// Eğer plaintext boşsa, boş string döndür
	if plaintext == "" {
		return "", nil
	}
	// AES-GCM şifreleme algoritması, her şifreleme işlemi için benzersiz bir nonce (number used once) gerektirir.
	nonce := make([]byte, c.aead.NonceSize())
	// Nonce'yi rastgele dolduruyoruz, bu sayede aynı plaintext her seferinde farklı bir ciphertext'e dönüşür.
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	// Ciphertext'i oluşturuyoruz, Seal fonksiyonu, verilen plaintext'i şifreler ve nonce ile birlikte birleştirir.
	ciphertext := c.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	// Burada da şunu yapıyoruz, Ciphertext'i base64 formatına çeviriyoruz, çünkü base64, ikili verileri (binary data) metin formatına dönüştürmek için yaygın olarak kullanılan bir yöntemdir.
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (c *Cipher) Decrypt(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	// Raw veriyi base64 formatından çöz, çünkü şifrelenmiş veri base64 formatında saklanıyor.
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}
	// Nonce boyutunu al, çünkü AES-GCM şifreleme algoritması, her şifreleme işlemi için benzersiz bir nonce gerektirir ve bu nonce, şifrelenmiş verinin başında saklanır.
	nonceSize := c.aead.NonceSize()
	// Eğer raw verinin boyutu nonce boyutundan küçükse, bu geçersiz bir şifrelenmiş veri demektir.
	if len(raw) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	// Nonce ve ciphertext'i ayır, çünkü şifrelenmiş veri, nonce ve ciphertext'in birleşiminden oluşur.
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}
	return string(plaintext), nil
}
