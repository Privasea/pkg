package secret

func NewCipher(algorithm string) Secret {
	switch algorithm {
	case "AES":
		return &AesSecret{}
	default:
		return nil
	}
}
