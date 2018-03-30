package secret

import (
	"crypto/rand"
	"errors"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

type pair struct {
	salt []byte
	hash []byte
}

var (
	passwordMap = make(map[string]pair)
	passwordMux = sync.RWMutex{}
)

// Register registers key with password in secret table.
func Register(key, password string) error {
	salt, err := genSalt()
	if err != nil {
		return err
	}
	hash, err := hashPassword(salt, []byte(password))
	if err != nil {
		return err
	}
	setPassword(key, pair{
		salt: salt,
		hash: hash,
	})
	return nil
}

var errNoMatch = errors.New("Given key and password does not match.")

// HasMatch returns no error if key and password are matching in secret table.
func HasMatch(key, password string) error {
	p, ok := func() (pair, bool) {
		passwordMux.RLock()
		defer passwordMux.RUnlock()
		p, ok := passwordMap[key]
		return p, ok
	}()
	if !ok {
		return errNoMatch
	}
	salted := saltPassword(p.salt, []byte(password))
	err := bcrypt.CompareHashAndPassword(p.hash, salted)
	return err
}

func setPassword(key string, p pair) {
	passwordMux.Lock()
	defer passwordMux.Unlock()
	passwordMap[key] = p
}

func hashPassword(salt, password []byte) ([]byte, error) {
	salted := saltPassword(salt, password)
	return bcrypt.GenerateFromPassword(salted, 12)
}

func saltPassword(salt, password []byte) []byte {
	salted := make([]byte, len(salt)+len(password))
	salted = append(salted, salt...)
	salted = append(salted, password...)
	return salted
}

func genSalt() ([]byte, error) {
	b := make([]byte, 18)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
