package auth

import "golang.org/x/crypto/bcrypt"

func checkHash(hashed, plain string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
}

// GenerateHash wrapper to bcrypt.GenerateFromPassword
func GenerateHash(data string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(data), 0)
	return string(h[:]), err
}
