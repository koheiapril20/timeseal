package cli

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/koheiapril20/timeseal/internal/bundle"
	"github.com/koheiapril20/timeseal/internal/crypto"
	"github.com/koheiapril20/timeseal/internal/delaykdf"
	"github.com/spf13/cobra"
)

var unlockCmd = &cobra.Command{
	Use:   "unlock <bundle>",
	Short: "Recover sealed data after completing computation",
	Long:  `Derives the key through sequential computation and decrypts the data.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runUnlock,
}

var (
	unlockPayload string
	unlockOutput  string
)

func init() {
	unlockCmd.Flags().StringVar(&unlockPayload, "payload", "", "Path to external payload file")
	unlockCmd.Flags().StringVarP(&unlockOutput, "output", "o", "", "Output file (default: stdout)")
}

func runUnlock(cmd *cobra.Command, args []string) error {
	bundlePath := args[0]

	// Read bundle
	bundleData, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to read bundle: %w", err)
	}

	b, err := bundle.ParseBytes(bundleData)
	if err != nil {
		return fmt.Errorf("failed to parse bundle: %w", err)
	}

	// Validate bundle
	if b.Format != bundle.FormatName {
		return fmt.Errorf("invalid bundle format: %s", b.Format)
	}
	if b.Version != bundle.Version {
		return fmt.Errorf("unsupported bundle version: %d", b.Version)
	}

	fmt.Fprintf(os.Stderr, "Bundle: %s\n", bundlePath)
	fmt.Fprintf(os.Stderr, "Difficulty: %d\n", b.Challenge.Difficulty)

	// Get encrypted payload
	var encryptedPayload []byte
	if b.IsInline() {
		encryptedPayload, err = b.GetInlinePayload()
		if err != nil {
			return fmt.Errorf("failed to get inline payload: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Mode: inline\n")
	} else {
		// External payload
		payloadPath := unlockPayload
		if payloadPath == "" {
			payloadPath = bundlePath + ".payload"
		}
		encryptedPayload, err = os.ReadFile(payloadPath)
		if err != nil {
			return fmt.Errorf("failed to read payload: %w", err)
		}

		// Verify payload integrity
		expectedHash, err := b.GetPayloadHash()
		if err != nil {
			return fmt.Errorf("failed to get payload hash: %w", err)
		}
		actualHash := sha256.Sum256(encryptedPayload)
		if !bytes.Equal(expectedHash, actualHash[:]) {
			return fmt.Errorf("payload integrity check failed")
		}
		fmt.Fprintf(os.Stderr, "Mode: external (payload verified)\n")
	}

	// Extract nonce from encrypted payload (first 12 bytes)
	if len(encryptedPayload) < crypto.NonceSize {
		return fmt.Errorf("invalid payload: too short")
	}
	payloadNonce := encryptedPayload[:crypto.NonceSize]
	payloadCiphertext := encryptedPayload[crypto.NonceSize:]

	// Derive wrapping key
	seed, err := b.GetSeed()
	if err != nil {
		return fmt.Errorf("failed to get seed: %w", err)
	}

	params := delaykdf.Params{
		MemoryKiB:   b.Challenge.Params.Argon2MemKiB,
		TimeCost:    b.Challenge.Params.TimeCost,
		Parallelism: b.Challenge.Params.Parallelism,
		Rounds:      b.Challenge.Params.Rounds,
	}

	fmt.Fprintf(os.Stderr, "Deriving key (this may take a while)...\n")
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

	// Unwrap data key
	wrapNonce, err := b.GetKeyWrapNonce()
	if err != nil {
		return fmt.Errorf("failed to get key wrap nonce: %w", err)
	}
	wrappedKey, err := b.GetKeyWrapCiphertext()
	if err != nil {
		return fmt.Errorf("failed to get wrapped key: %w", err)
	}

	dataKey, err := crypto.Decrypt(wrappingKey, wrapNonce, wrappedKey)
	if err != nil {
		return fmt.Errorf("failed to unwrap data key: %w", err)
	}

	// Decrypt payload
	plaintext, err := crypto.Decrypt(dataKey, payloadNonce, payloadCiphertext)
	if err != nil {
		return fmt.Errorf("failed to decrypt payload: %w", err)
	}

	// Write output
	var out io.Writer
	if unlockOutput != "" {
		f, err := os.Create(unlockOutput)
		if err != nil {
			return fmt.Errorf("failed to create output: %w", err)
		}
		defer f.Close()
		out = f
	} else {
		out = os.Stdout
	}

	if _, err := out.Write(plaintext); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	if unlockOutput != "" {
		fmt.Fprintf(os.Stderr, "Output: %s (%d bytes)\n", unlockOutput, len(plaintext))
	}
	fmt.Fprintf(os.Stderr, "Unlocked successfully.\n")

	return nil
}
