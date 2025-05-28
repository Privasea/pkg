package secret

type Secret interface {
	Encrypt(secretKey string, value string) (string, error)
	Decrypt(secretKey string, secretValue string) (string, error)
}
