package cli

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/koheiapril20/timeseal/internal/bundle"
	"github.com/koheiapril20/timeseal/internal/checkpoint"
	"github.com/koheiapril20/timeseal/internal/crypto"
	"github.com/koheiapril20/timeseal/internal/delaykdf"
	"github.com/spf13/cobra"
)

var sealCmd = &cobra.Command{
	Use:   "seal [input]",
	Short: "Seal data using a delay-based lock",
	Long: `Encrypts data with a key that requires sequential computation to derive.

Supports pause/resume: Press Ctrl+C to save progress to a checkpoint file.
Use --resume to continue from a saved checkpoint.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runSeal,
}

var (
	sealDifficulty uint32
	sealOutput     string
	sealResume     string
)

func init() {
	sealCmd.Flags().Uint32Var(&sealDifficulty, "difficulty", 0, "Difficulty (number of rounds)")
	sealCmd.Flags().StringVarP(&sealOutput, "output", "o", "", "Output file (default: stdout)")
	sealCmd.Flags().StringVar(&sealResume, "resume", "", "Resume from checkpoint file")
}

func runSeal(cmd *cobra.Command, args []string) error {
	// Resume mode
	if sealResume != "" {
		return runSealResume()
	}

	// Normal mode - require difficulty
	if sealDifficulty == 0 {
		return fmt.Errorf("--difficulty is required (or use --resume to continue from checkpoint)")
	}

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

	// Setup cancellation context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\n\nInterrupt received, saving checkpoint...\n")
		cancel()
	}()

	// Derive wrapping key using DelayKDF
	fmt.Fprintf(os.Stderr, "Deriving wrapping key (difficulty=%d)...\n", sealDifficulty)
	fmt.Fprintf(os.Stderr, "Press Ctrl+C to pause and save checkpoint.\n")
	params := delaykdf.DefaultParams(sealDifficulty)
	state := delaykdf.NewState(seed, params)

	progress := NewProgressBar(sealDifficulty, ModeSeal)
	wrappingKey, err := delaykdf.DeriveWithContext(ctx, state, progress.Callback())

	if errors.Is(err, delaykdf.ErrInterrupted) {
		fmt.Fprintln(os.Stderr)
		// Save checkpoint
		cpPath := getCheckpointPath(sealOutput, inputName)
		cp := checkpoint.SealCheckpoint(state, seed, dataKey, inputName, sealOutput)

		// Also save encrypted data to checkpoint for resume
		payloadNonce, encryptedPayload, encErr := crypto.Encrypt(dataKey, data)
		if encErr != nil {
			return fmt.Errorf("failed to encrypt payload for checkpoint: %w", encErr)
		}
		cp.InputFile = inputName
		// Store the encrypted data temporarily
		tempDataPath := cpPath + ".data"
		fullPayload := append(payloadNonce, encryptedPayload...)
		if err := os.WriteFile(tempDataPath, fullPayload, 0600); err != nil {
			return fmt.Errorf("failed to save encrypted data: %w", err)
		}

		if err := cp.Save(cpPath); err != nil {
			return fmt.Errorf("failed to save checkpoint: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Checkpoint saved: %s\n", cpPath)
		fmt.Fprintf(os.Stderr, "Resume with: timeseal seal --resume %s\n", cpPath)
		return nil
	}
	if err != nil {
		return fmt.Errorf("delaykdf failed: %w", err)
	}
	progress.Finish()

	return finalizeSeal(seed, dataKey, wrappingKey, data, params, sealOutput)
}

func runSealResume() error {
	cp, err := checkpoint.Load(sealResume)
	if err != nil {
		return fmt.Errorf("failed to load checkpoint: %w", err)
	}
	if cp.Type != checkpoint.TypeSeal {
		return fmt.Errorf("checkpoint is not for seal operation")
	}

	fmt.Fprintf(os.Stderr, "Resuming seal from checkpoint...\n")
	fmt.Fprintf(os.Stderr, "Progress: %.1f%% (%d/%d)\n",
		float64(cp.CurrentRound)/float64(cp.TotalRounds)*100,
		cp.CurrentRound, cp.TotalRounds)

	state, err := cp.ToState()
	if err != nil {
		return fmt.Errorf("invalid checkpoint: %w", err)
	}

	seed, err := cp.GetSeed()
	if err != nil {
		return fmt.Errorf("invalid checkpoint seed: %w", err)
	}

	dataKey, err := cp.GetDataKey()
	if err != nil {
		return fmt.Errorf("invalid checkpoint data key: %w", err)
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
	progress := NewProgressBar(state.Params.Rounds, ModeSeal)
	progress.Update(state.CurrentRound) // Show initial progress
	wrappingKey, err := delaykdf.DeriveWithContext(ctx, state, progress.Callback())

	if errors.Is(err, delaykdf.ErrInterrupted) {
		fmt.Fprintln(os.Stderr)
		// Update checkpoint
		cp2 := checkpoint.SealCheckpoint(state, seed, dataKey, cp.InputFile, cp.OutputFile)
		if err := cp2.Save(sealResume); err != nil {
			return fmt.Errorf("failed to save checkpoint: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Checkpoint updated: %s\n", sealResume)
		fmt.Fprintf(os.Stderr, "Resume with: timeseal seal --resume %s\n", sealResume)
		return nil
	}
	if err != nil {
		return fmt.Errorf("delaykdf failed: %w", err)
	}
	progress.Finish()

	// Read encrypted data from temp file
	tempDataPath := sealResume + ".data"
	encryptedData, err := os.ReadFile(tempDataPath)
	if err != nil {
		return fmt.Errorf("failed to read encrypted data: %w", err)
	}

	// Finalize
	output := cp.OutputFile
	if sealOutput != "" {
		output = sealOutput
	}

	if err := finalizeSealFromEncrypted(seed, dataKey, wrappingKey, encryptedData, state.Params, output); err != nil {
		return err
	}

	// Cleanup checkpoint files
	os.Remove(sealResume)
	os.Remove(tempDataPath)
	fmt.Fprintf(os.Stderr, "Checkpoint files removed.\n")

	return nil
}

func finalizeSeal(seed, dataKey, wrappingKey, data []byte, params delaykdf.Params, outputPath string) error {
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
	fullPayload := append(payloadNonce, encryptedPayload...)

	return writeBundleAndPayload(seed, wrapNonce, wrappedKey, fullPayload, params, outputPath, len(data))
}

func finalizeSealFromEncrypted(seed, dataKey, wrappingKey, encryptedPayload []byte, params delaykdf.Params, outputPath string) error {
	// Wrap data key with wrapping key
	wrapNonce, wrappedKey, err := crypto.Encrypt(wrappingKey, dataKey)
	if err != nil {
		return fmt.Errorf("failed to wrap data key: %w", err)
	}

	// encryptedPayload already includes nonce
	originalSize := len(encryptedPayload) - crypto.NonceSize - 16 // minus nonce and auth tag
	return writeBundleAndPayload(seed, wrapNonce, wrappedKey, encryptedPayload, params, outputPath, originalSize)
}

func writeBundleAndPayload(seed, wrapNonce, wrappedKey, fullPayload []byte, params delaykdf.Params, outputPath string, originalSize int) error {
	// Create bundle
	b := bundle.New(seed, params.Rounds, bundle.DelayParams{
		Argon2MemKiB: params.MemoryKiB,
		TimeCost:     params.TimeCost,
		Parallelism:  params.Parallelism,
		Rounds:       params.Rounds,
	})
	b.SetKeyWrap(wrapNonce, wrappedKey)

	var bundleOut io.Writer
	bundlePath := outputPath

	if originalSize <= bundle.InlineThreshold {
		// Inline mode
		b.SetInlinePayload(fullPayload)
		fmt.Fprintf(os.Stderr, "Mode: inline\n")
	} else {
		// External mode
		hash := sha256.Sum256(fullPayload)
		b.SetExternalPayload(hash[:], int64(len(fullPayload)))
		fmt.Fprintf(os.Stderr, "Mode: external\n")

		payloadPath := bundlePath + ".payload"
		if bundlePath == "" {
			return fmt.Errorf("external payload requires --output flag")
		}
		if err := os.WriteFile(payloadPath, fullPayload, 0600); err != nil {
			return fmt.Errorf("failed to write payload: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Payload: %s (%d bytes)\n", payloadPath, len(fullPayload))
	}

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

func getCheckpointPath(output, input string) string {
	if output != "" {
		return output + ".seal.checkpoint"
	}
	if input != "" && input != "stdin" {
		return input + ".seal.checkpoint"
	}
	return "timeseal.seal.checkpoint"
}

func getPayloadPath(bundlePath string) string {
	return bundlePath + ".payload"
}

func getBundleDir(bundlePath string) string {
	return filepath.Dir(bundlePath)
}
