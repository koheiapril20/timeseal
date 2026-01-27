package delaykdf

import (
	"context"
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

// State represents the current state of a DelayKDF computation.
// Can be saved and restored for pause/resume functionality.
type State struct {
	Params       Params
	CurrentRound uint32
	CurrentKey   []byte
}

// NewState creates an initial state from seed and params.
func NewState(seed []byte, params Params) *State {
	key := make([]byte, len(seed))
	copy(key, seed)
	return &State{
		Params:       params,
		CurrentRound: 0,
		CurrentKey:   key,
	}
}

// IsComplete returns true if the computation is finished.
func (s *State) IsComplete() bool {
	return s.CurrentRound >= s.Params.Rounds
}

// Progress returns the completion percentage (0-100).
func (s *State) Progress() float64 {
	return float64(s.CurrentRound) / float64(s.Params.Rounds) * 100
}

type ProgressFunc func(current, total uint32)

// ErrInterrupted is returned when computation is interrupted by context cancellation.
var ErrInterrupted = errors.New("delaykdf: computation interrupted")

func Derive(seed []byte, params Params) ([]byte, error) {
	return DeriveWithProgress(seed, params, nil)
}

func DeriveWithProgress(seed []byte, params Params, progress ProgressFunc) ([]byte, error) {
	state := NewState(seed, params)
	return DeriveWithContext(context.Background(), state, progress)
}

// DeriveWithContext runs the DelayKDF computation with context support for cancellation.
// If the context is cancelled, it returns ErrInterrupted and the state can be used to resume.
func DeriveWithContext(ctx context.Context, state *State, progress ProgressFunc) ([]byte, error) {
	if len(state.CurrentKey) == 0 {
		return nil, errors.New("delaykdf: state key cannot be empty")
	}
	if state.Params.Rounds == 0 {
		return nil, errors.New("delaykdf: rounds must be greater than 0")
	}
	if state.Params.MemoryKiB == 0 {
		state.Params.MemoryKiB = DefaultMemoryKiB
	}
	if state.Params.TimeCost == 0 {
		state.Params.TimeCost = DefaultTimeCost
	}
	if state.Params.Parallelism == 0 {
		state.Params.Parallelism = DefaultParallelism
	}

	salt := make([]byte, SaltSize)

	for state.CurrentRound < state.Params.Rounds {
		// Check for cancellation before each round
		select {
		case <-ctx.Done():
			return nil, ErrInterrupted
		default:
		}

		// Use first 16 bytes of current key as salt for next iteration
		copy(salt, state.CurrentKey[:SaltSize])

		state.CurrentKey = argon2.IDKey(
			state.CurrentKey,
			salt,
			state.Params.TimeCost,
			state.Params.MemoryKiB,
			state.Params.Parallelism,
			KeySize,
		)

		state.CurrentRound++

		if progress != nil {
			progress(state.CurrentRound, state.Params.Rounds)
		}
	}

	return state.CurrentKey, nil
}

func GenerateSeed() ([]byte, error) {
	seed := make([]byte, KeySize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return seed, nil
}
