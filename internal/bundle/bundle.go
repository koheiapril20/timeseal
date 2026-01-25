package bundle

import (
	"encoding/base64"
	"encoding/json"
	"io"
)

const (
	FormatName      = "timeseal-bundle"
	Version         = 1
	KDFName         = "delaykdf-argon2id-chained"
	AEADName        = "chacha20poly1305"
	InlineThreshold = 64 * 1024 // 64 KiB

	PayloadModeInline   = "inline"
	PayloadModeExternal = "external"
)

type Bundle struct {
	Format      string       `json:"format"`
	Version     int          `json:"version"`
	Challenge   Challenge    `json:"challenge"`
	KeyWrap     KeyWrap      `json:"key_wrap"`
	Payload     PayloadMeta  `json:"payload"`
	Calibration *Calibration `json:"calibration,omitempty"`
}

type Challenge struct {
	KDF        string       `json:"kdf"`
	SeedB64    string       `json:"seed_b64"`
	Difficulty uint32       `json:"difficulty"`
	Params     DelayParams  `json:"params"`
}

type DelayParams struct {
	Argon2MemKiB uint32 `json:"argon2_mem_kib"`
	TimeCost     uint32 `json:"time_cost"`
	Parallelism  uint8  `json:"parallelism"`
	Rounds       uint32 `json:"rounds"`
}

type KeyWrap struct {
	AEAD     string `json:"aead"`
	NonceB64 string `json:"nonce_b64"`
	CTB64    string `json:"ct_b64"`
}

type PayloadMeta struct {
	Mode    string `json:"mode"`
	DataB64 string `json:"data_b64,omitempty"`
	HashB64 string `json:"hash_b64,omitempty"`
	Size    int64  `json:"size,omitempty"`
}

type Calibration struct {
	Bench               BenchInfo `json:"bench"`
	SuggestedDifficulty uint32    `json:"suggested_difficulty"`
	TargetHint          string    `json:"target_hint"`
}

type BenchInfo struct {
	Difficulty    uint32  `json:"difficulty"`
	MedianSeconds float64 `json:"median_seconds"`
}

func New(seed []byte, difficulty uint32, params DelayParams) *Bundle {
	return &Bundle{
		Format:  FormatName,
		Version: Version,
		Challenge: Challenge{
			KDF:        KDFName,
			SeedB64:    base64.StdEncoding.EncodeToString(seed),
			Difficulty: difficulty,
			Params:     params,
		},
		KeyWrap: KeyWrap{
			AEAD: AEADName,
		},
	}
}

func (b *Bundle) SetKeyWrap(nonce, ciphertext []byte) {
	b.KeyWrap.NonceB64 = base64.StdEncoding.EncodeToString(nonce)
	b.KeyWrap.CTB64 = base64.StdEncoding.EncodeToString(ciphertext)
}

func (b *Bundle) SetInlinePayload(data []byte) {
	b.Payload = PayloadMeta{
		Mode:    PayloadModeInline,
		DataB64: base64.StdEncoding.EncodeToString(data),
	}
}

func (b *Bundle) SetExternalPayload(hash []byte, size int64) {
	b.Payload = PayloadMeta{
		Mode:    PayloadModeExternal,
		HashB64: base64.StdEncoding.EncodeToString(hash),
		Size:    size,
	}
}

func (b *Bundle) GetSeed() ([]byte, error) {
	return base64.StdEncoding.DecodeString(b.Challenge.SeedB64)
}

func (b *Bundle) GetKeyWrapNonce() ([]byte, error) {
	return base64.StdEncoding.DecodeString(b.KeyWrap.NonceB64)
}

func (b *Bundle) GetKeyWrapCiphertext() ([]byte, error) {
	return base64.StdEncoding.DecodeString(b.KeyWrap.CTB64)
}

func (b *Bundle) GetInlinePayload() ([]byte, error) {
	return base64.StdEncoding.DecodeString(b.Payload.DataB64)
}

func (b *Bundle) GetPayloadHash() ([]byte, error) {
	return base64.StdEncoding.DecodeString(b.Payload.HashB64)
}

func (b *Bundle) IsInline() bool {
	return b.Payload.Mode == PayloadModeInline
}

func (b *Bundle) Write(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(b)
}

func Parse(r io.Reader) (*Bundle, error) {
	var b Bundle
	if err := json.NewDecoder(r).Decode(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

func ParseBytes(data []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}
