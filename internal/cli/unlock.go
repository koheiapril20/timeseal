package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/koheiapril20/timeseal/internal/bundle"
	"github.com/koheiapril20/timeseal/internal/checkpoint"
	"github.com/koheiapril20/timeseal/internal/crypto"
	"github.com/koheiapril20/timeseal/internal/delaykdf"
	"github.com/spf13/cobra"
)

var unlockCmd = &cobra.Command{
	Use:   "unlock <bundle>",
	Short: "Recover sealed data after completing computation",
	Long: `Derives the key through sequential computation and decrypts the data.

Supports pause/resume: Press Ctrl+C to save progress to a checkpoint file.
Use --resume to continue from a saved checkpoint.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runUnlock,
}

var (
	unlockPayload string
	unlockOutput  string
	unlockResume  string
)

func init() {
	unlockCmd.Flags().StringVar(&unlockPayload, "payload", "", "Path to external payload file")
	unlockCmd.Flags().StringVarP(&unlockOutput, "output", "o", "", "Output file (default: stdout)")
	unlockCmd.Flags().StringVar(&unlockResume, "resume", "", "Resume from checkpoint file")
}

func runUnlock(cmd *cobra.Command, args []string) error {
	// Resume mode
	if unlockResume != "" {
		return runUnlockResume()
	}

	if len(args) == 0 {
		return fmt.Errorf("bundle path is required (or use --resume to continue from checkpoint)")
	}

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
		payloadPath := unlockPayload
		if payloadPath == "" {
			payloadPath = bundlePath + ".payload"
		}
		encryptedPayload, err = os.ReadFile(payloadPath)
		if err != nil {
			return fmt.Errorf("failed to read payload: %w", err)
		}

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

	if len(encryptedPayload) < crypto.NonceSize {
		return fmt.Errorf("invalid payload: too short")
	}

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

	// Setup cancellation context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\n\nInterrupt received, saving checkpoint...\n")
		cancel()
	}()

	fmt.Fprintf(os.Stderr, "Deriving key (this may take a while)...\n")
	fmt.Fprintf(os.Stderr, "Press Ctrl+C to pause and save checkpoint.\n")
	state := delaykdf.NewState(seed, params)

	progress := NewProgressBar(params.Rounds, ModeUnlock)
	wrappingKey, err := delaykdf.DeriveWithContext(ctx, state, progress.Callback())

	if errors.Is(err, delaykdf.ErrInterrupted) {
		fmt.Fprintln(os.Stderr)
		cpPath := bundlePath + ".unlock.checkpoint"
		cp := checkpoint.UnlockCheckpoint(state, bundlePath, unlockOutput)
		if err := cp.Save(cpPath); err != nil {
			return fmt.Errorf("failed to save checkpoint: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Checkpoint saved: %s\n", cpPath)
		fmt.Fprintf(os.Stderr, "Resume with: timeseal unlock --resume %s\n", cpPath)
		return nil
	}
	if err != nil {
		return fmt.Errorf("delaykdf failed: %w", err)
	}
	progress.Finish()

	return finalizeUnlock(b, wrappingKey, encryptedPayload, unlockOutput)
}

func runUnlockResume() error {
	cp, err := checkpoint.Load(unlockResume)
	if err != nil {
		return fmt.Errorf("failed to load checkpoint: %w", err)
	}
	if cp.Type != checkpoint.TypeUnlock {
		return fmt.Errorf("checkpoint is not for unlock operation")
	}

	fmt.Fprintf(os.Stderr, "Resuming unlock from checkpoint...\n")
	fmt.Fprintf(os.Stderr, "Progress: %.1f%% (%d/%d)\n",
		float64(cp.CurrentRound)/float64(cp.TotalRounds)*100,
		cp.CurrentRound, cp.TotalRounds)

	bundlePath := cp.BundlePath

	// Read bundle
	bundleData, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to read bundle: %w", err)
	}

	b, err := bundle.ParseBytes(bundleData)
	if err != nil {
		return fmt.Errorf("failed to parse bundle: %w", err)
	}

	// Get encrypted payload
	var encryptedPayload []byte
	if b.IsInline() {
		encryptedPayload, err = b.GetInlinePayload()
		if err != nil {
			return fmt.Errorf("failed to get inline payload: %w", err)
		}
	} else {
		payloadPath := bundlePath + ".payload"
		encryptedPayload, err = os.ReadFile(payloadPath)
		if err != nil {
			return fmt.Errorf("failed to read payload: %w", err)
		}
	}

	state, err := cp.ToState()
	if err != nil {
		return fmt.Errorf("invalid checkpoint: %w", err)
	}

	// Setup cancellation context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\n\nInterrupt received, saving checkpoint...\n")
		cancel()
	}()

	fmt.Fprintf(os.Stderr, "Press Ctrl+C to pause and save checkpoint.\n")
	progress := NewProgressBar(state.Params.Rounds, ModeUnlock)
	progress.Update(state.CurrentRound) // Show initial progress
	wrappingKey, err := delaykdf.DeriveWithContext(ctx, state, progress.Callback())

	if errors.Is(err, delaykdf.ErrInterrupted) {
		fmt.Fprintln(os.Stderr)
		cp2 := checkpoint.UnlockCheckpoint(state, bundlePath, cp.OutputFile)
		if err := cp2.Save(unlockResume); err != nil {
			return fmt.Errorf("failed to save checkpoint: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Checkpoint updated: %s\n", unlockResume)
		fmt.Fprintf(os.Stderr, "Resume with: timeseal unlock --resume %s\n", unlockResume)
		return nil
	}
	if err != nil {
		return fmt.Errorf("delaykdf failed: %w", err)
	}
	progress.Finish()

	output := cp.OutputFile
	if unlockOutput != "" {
		output = unlockOutput
	}

	if err := finalizeUnlock(b, wrappingKey, encryptedPayload, output); err != nil {
		return err
	}

	// Cleanup checkpoint
	os.Remove(unlockResume)
	fmt.Fprintf(os.Stderr, "Checkpoint file removed.\n")

	return nil
}

func finalizeUnlock(b *bundle.Bundle, wrappingKey, encryptedPayload []byte, outputPath string) error {
	payloadNonce := encryptedPayload[:crypto.NonceSize]
	payloadCiphertext := encryptedPayload[crypto.NonceSize:]

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
	if outputPath != "" {
		f, err := os.Create(outputPath)
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

	if outputPath != "" {
		fmt.Fprintf(os.Stderr, "Output: %s (%d bytes)\n", outputPath, len(plaintext))
	}
	fmt.Fprintf(os.Stderr, "Unlocked successfully.\n")

	return nil
}
