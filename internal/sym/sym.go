package sym

type SymmetricEncrypter interface {
	Encrypt([]byte) []byte
	Decrypt([]byte) []byte
}
