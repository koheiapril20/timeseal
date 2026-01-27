package checkpoint

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"

	"github.com/koheiapril20/timeseal/internal/delaykdf"
)

const (
	TypeSeal   = "seal"
	TypeUnlock = "unlock"
)

// Checkpoint represents a saved computation state.
type Checkpoint struct {
	Type    string `json:"type"`
	Version int    `json:"version"`

	// DelayKDF state
	CurrentRound uint32 `json:"current_round"`
	TotalRounds  uint32 `json:"total_rounds"`
	CurrentKeyB64 string `json:"current_key_b64"`

	// Seal-specific fields
	SeedB64     string `json:"seed_b64,omitempty"`
	DataKeyB64  string `json:"data_key_b64,omitempty"`
	Difficulty  uint32 `json:"difficulty,omitempty"`
	InputFile   string `json:"input_file,omitempty"`
	OutputFile  string `json:"output_file,omitempty"`

	// Unlock-specific fields
	BundlePath  string `json:"bundle_path,omitempty"`

	// Params
	Params ParamsData `json:"params"`
}

type ParamsData struct {
	MemoryKiB   uint32 `json:"memory_kib"`
	TimeCost    uint32 `json:"time_cost"`
	Parallelism uint8  `json:"parallelism"`
}

// SealCheckpoint creates a checkpoint for a seal operation.
func SealCheckpoint(state *delaykdf.State, seed, dataKey []byte, inputFile, outputFile string) *Checkpoint {
	return &Checkpoint{
		Type:          TypeSeal,
		Version:       1,
		CurrentRound:  state.CurrentRound,
		TotalRounds:   state.Params.Rounds,
		CurrentKeyB64: base64.StdEncoding.EncodeToString(state.CurrentKey),
		SeedB64:       base64.StdEncoding.EncodeToString(seed),
		DataKeyB64:    base64.StdEncoding.EncodeToString(dataKey),
		Difficulty:    state.Params.Rounds,
		InputFile:     inputFile,
		OutputFile:    outputFile,
		Params: ParamsData{
			MemoryKiB:   state.Params.MemoryKiB,
			TimeCost:    state.Params.TimeCost,
			Parallelism: state.Params.Parallelism,
		},
	}
}

// UnlockCheckpoint creates a checkpoint for an unlock operation.
func UnlockCheckpoint(state *delaykdf.State, bundlePath, outputFile string) *Checkpoint {
	return &Checkpoint{
		Type:          TypeUnlock,
		Version:       1,
		CurrentRound:  state.CurrentRound,
		TotalRounds:   state.Params.Rounds,
		CurrentKeyB64: base64.StdEncoding.EncodeToString(state.CurrentKey),
		BundlePath:    bundlePath,
		OutputFile:    outputFile,
		Params: ParamsData{
			MemoryKiB:   state.Params.MemoryKiB,
			TimeCost:    state.Params.TimeCost,
			Parallelism: state.Params.Parallelism,
		},
	}
}

// Save writes the checkpoint to a file.
func (c *Checkpoint) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// Load reads a checkpoint from a file.
func Load(path string) (*Checkpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Checkpoint
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ToState converts the checkpoint back to a delaykdf.State.
func (c *Checkpoint) ToState() (*delaykdf.State, error) {
	currentKey, err := base64.StdEncoding.DecodeString(c.CurrentKeyB64)
	if err != nil {
		return nil, errors.New("invalid checkpoint: cannot decode current key")
	}
	return &delaykdf.State{
		Params: delaykdf.Params{
			MemoryKiB:   c.Params.MemoryKiB,
			TimeCost:    c.Params.TimeCost,
			Parallelism: c.Params.Parallelism,
			Rounds:      c.TotalRounds,
		},
		CurrentRound: c.CurrentRound,
		CurrentKey:   currentKey,
	}, nil
}

// GetSeed returns the seed for seal checkpoints.
func (c *Checkpoint) GetSeed() ([]byte, error) {
	return base64.StdEncoding.DecodeString(c.SeedB64)
}

// GetDataKey returns the data key for seal checkpoints.
func (c *Checkpoint) GetDataKey() ([]byte, error) {
	return base64.StdEncoding.DecodeString(c.DataKeyB64)
}

// Delete removes the checkpoint file.
func Delete(path string) error {
	return os.Remove(path)
}

// Exists checks if a checkpoint file exists.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
