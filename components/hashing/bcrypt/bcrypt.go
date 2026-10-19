package bcrypt

import (
	"errors"
	"fmt"

	"github.com/markusnieminen1/goauth/components/hashing"
	"github.com/markusnieminen1/goauth/setup"
	"golang.org/x/crypto/bcrypt"
)

type Hasher struct {
	cost int
}

type Option func(*Hasher)

func WithCost(cost int) Option {
	return func(h *Hasher) { h.cost = cost }
}

func New(opts ...Option) (*Hasher, error) {

	h := &Hasher{cost: setup.BCRYPT_Cost}

	for _, opt := range opts {
		opt(h)
	}

	if h.cost < bcrypt.MinCost || h.cost > bcrypt.MaxCost {
		return nil, fmt.Errorf("bcrypt: cost %d is outside %d..%d", h.cost, bcrypt.MinCost, bcrypt.MaxCost)
	}

	return h, nil
}

func (h *Hasher) Hash(plain string) (string, error) {

	hash, err := bcrypt.GenerateFromPassword([]byte(plain), h.cost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func (h *Hasher) Verify(plain, hash string) (bool, error) {

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
	if err == nil {
		return true, nil
	}

	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}

	return false, err
}

var _ hashing.PasswordHasher = (*Hasher)(nil)
