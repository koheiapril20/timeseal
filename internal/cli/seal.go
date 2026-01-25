package cli

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/koheiapril20/timeseal/internal/bundle"
	"github.com/koheiapril20/timeseal/internal/crypto"
	"github.com/koheiapril20/timeseal/internal/delaykdf"
	"github.com/spf13/cobra"
)

var sealCmd = &cobra.Command{
	Use:   "seal [input]",
	Short: "Seal data using a delay-based lock",
	Long:  `Encrypts data with a key that requires sequential computation to derive.`,
	Args:  cobra.MaximumNArgs(1),
	RunE:  runSeal,
}

var (
	sealDifficulty uint32
	sealOutput     string
)

func init() {
	sealCmd.Flags().Uint32Var(&sealDifficulty, "difficulty", 0, "Difficulty (number of rounds)")
	sealCmd.Flags().StringVarP(&sealOutput, "output", "o", "", "Output file (default: stdout)")
	sealCmd.MarkFlagRequired("difficulty")
}

func runSeal(cmd *cobra.Command, args []string) error {
	// Read input
	var input io.Reader
	inputName := "stdin"
	if len(args) > 0 && args[0] != "-" {
		f, err := os.Open(args[0])
		if err != nil {
			return fmt.Errorf("failed to open input: %w", err)
		}
		defer f.Close()
		input = f
		inputName = args[0]
	} else {
		input = os.Stdin
	}

	data, err := io.ReadAll(input)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Input: %s (%d bytes)\n", inputName, len(data))

	// Generate seed for DelayKDF
	seed, err := delaykdf.GenerateSeed()
	if err != nil {
		return fmt.Errorf("failed to generate seed: %w", err)
	}

	// Generate data encryption key
	dataKey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate data key: %w", err)
	}

	// Derive wrapping key using DelayKDF
	fmt.Fprintf(os.Stderr, "Deriving wrapping key (difficulty=%d)...\n", sealDifficulty)
	params := delaykdf.DefaultParams(sealDifficulty)
	wrappingKey, err := delaykdf.DeriveWithProgress(seed, params, func(current, total uint32) {
		if total <= 100 || current%(total/100) == 0 || current == total {
			pct := float64(current) / float64(total) * 100
			fmt.Fprintf(os.Stderr, "\r  Progress: %.1f%% (%d/%d)", pct, current, total)
		}
	})
	if err != nil {
		return fmt.Errorf("delaykdf failed: %w", err)
	}
	fmt.Fprintln(os.Stderr)

	// Wrap data key with wrapping key
	wrapNonce, wrappedKey, err := crypto.Encrypt(wrappingKey, dataKey)
	if err != nil {
		return fmt.Errorf("failed to wrap data key: %w", err)
	}

	// Encrypt payload with data key
	payloadNonce, encryptedPayload, err := crypto.Encrypt(dataKey, data)
	if err != nil {
		return fmt.Errorf("failed to encrypt payload: %w", err)
	}

	// Create bundle
	b := bundle.New(seed, sealDifficulty, bundle.DelayParams{
		Argon2MemKiB: params.MemoryKiB,
		TimeCost:     params.TimeCost,
		Parallelism:  params.Parallelism,
		Rounds:       params.Rounds,
	})
	b.SetKeyWrap(wrapNonce, wrappedKey)

	// Determine output
	var bundleOut io.Writer
	var bundlePath string
	if sealOutput != "" {
		bundlePath = sealOutput
	}

	// Decide inline vs external
	fullPayload := append(payloadNonce, encryptedPayload...)

	if len(data) <= bundle.InlineThreshold {
		// Inline mode
		b.SetInlinePayload(fullPayload)
		fmt.Fprintf(os.Stderr, "Mode: inline\n")
	} else {
		// External mode
		hash := sha256.Sum256(fullPayload)
		b.SetExternalPayload(hash[:], int64(len(fullPayload)))
		fmt.Fprintf(os.Stderr, "Mode: external\n")

		// Write payload file
		payloadPath := bundlePath + ".payload"
		if bundlePath == "" {
			return fmt.Errorf("external payload requires --output flag")
		}
		if err := os.WriteFile(payloadPath, fullPayload, 0600); err != nil {
			return fmt.Errorf("failed to write payload: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Payload: %s (%d bytes)\n", payloadPath, len(fullPayload))
	}

	// Write bundle
	if bundlePath != "" {
		f, err := os.Create(bundlePath)
		if err != nil {
			return fmt.Errorf("failed to create output: %w", err)
		}
		defer f.Close()
		bundleOut = f
	} else {
		bundleOut = os.Stdout
	}

	if err := b.Write(bundleOut); err != nil {
		return fmt.Errorf("failed to write bundle: %w", err)
	}

	if bundlePath != "" {
		fmt.Fprintf(os.Stderr, "Bundle: %s\n", bundlePath)
	}
	fmt.Fprintf(os.Stderr, "Sealed successfully.\n")

	return nil
}

func getPayloadPath(bundlePath string) string {
	return bundlePath + ".payload"
}

func getBundleDir(bundlePath string) string {
	return filepath.Dir(bundlePath)
}
