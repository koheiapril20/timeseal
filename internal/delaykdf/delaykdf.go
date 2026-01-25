package delaykdf

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/argon2"
)

const (
	DefaultMemoryKiB   = 262144 // 256 MB
	DefaultTimeCost    = 2
	DefaultParallelism = 1
	KeySize            = 32
	SaltSize           = 16
)

type Params struct {
	MemoryKiB   uint32
	TimeCost    uint32
	Parallelism uint8
	Rounds      uint32
}

func DefaultParams(rounds uint32) Params {
	return Params{
		MemoryKiB:   DefaultMemoryKiB,
		TimeCost:    DefaultTimeCost,
		Parallelism: DefaultParallelism,
		Rounds:      rounds,
	}
}

type ProgressFunc func(current, total uint32)

func Derive(seed []byte, params Params) ([]byte, error) {
	return DeriveWithProgress(seed, params, nil)
}

func DeriveWithProgress(seed []byte, params Params, progress ProgressFunc) ([]byte, error) {
	if len(seed) == 0 {
		return nil, errors.New("delaykdf: seed cannot be empty")
	}
	if params.Rounds == 0 {
		return nil, errors.New("delaykdf: rounds must be greater than 0")
	}
	if params.MemoryKiB == 0 {
		params.MemoryKiB = DefaultMemoryKiB
	}
	if params.TimeCost == 0 {
		params.TimeCost = DefaultTimeCost
	}
	if params.Parallelism == 0 {
		params.Parallelism = DefaultParallelism
	}

	key := make([]byte, len(seed))
	copy(key, seed)

	salt := make([]byte, SaltSize)

	for i := uint32(0); i < params.Rounds; i++ {
		// Use first 16 bytes of current key as salt for next iteration
		copy(salt, key[:SaltSize])

		key = argon2.IDKey(
			key,
			salt,
			params.TimeCost,
			params.MemoryKiB,
			params.Parallelism,
			KeySize,
		)

		if progress != nil {
			progress(i+1, params.Rounds)
		}
	}

	return key, nil
}

func GenerateSeed() ([]byte, error) {
	seed := make([]byte, KeySize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return seed, nil
}
