package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/koheiapril20/timeseal/internal/bundle"
	"github.com/spf13/cobra"
)

var infoCmd = &cobra.Command{
	Use:   "info <bundle>",
	Short: "Inspect bundle metadata and estimates",
	Long:  `Displays information about a sealed bundle without unlocking it.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runInfo,
}

var infoJSON bool

func init() {
	infoCmd.Flags().BoolVar(&infoJSON, "json", false, "Output in JSON format")
}

func runInfo(cmd *cobra.Command, args []string) error {
	bundlePath := args[0]

	bundleData, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to read bundle: %w", err)
	}

	b, err := bundle.ParseBytes(bundleData)
	if err != nil {
		return fmt.Errorf("failed to parse bundle: %w", err)
	}

	if infoJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(b)
	}

	fmt.Printf("Format:      %s\n", b.Format)
	fmt.Printf("Version:     %d\n", b.Version)
	fmt.Println()
	fmt.Println("Challenge:")
	fmt.Printf("  KDF:        %s\n", b.Challenge.KDF)
	fmt.Printf("  Difficulty: %d\n", b.Challenge.Difficulty)
	fmt.Printf("  Params:\n")
	fmt.Printf("    Memory:      %d KiB (%d MiB)\n", b.Challenge.Params.Argon2MemKiB, b.Challenge.Params.Argon2MemKiB/1024)
	fmt.Printf("    Time cost:   %d\n", b.Challenge.Params.TimeCost)
	fmt.Printf("    Parallelism: %d\n", b.Challenge.Params.Parallelism)
	fmt.Printf("    Rounds:      %d\n", b.Challenge.Params.Rounds)
	fmt.Println()
	fmt.Println("Key Wrap:")
	fmt.Printf("  AEAD: %s\n", b.KeyWrap.AEAD)
	fmt.Println()
	fmt.Println("Payload:")
	fmt.Printf("  Mode: %s\n", b.Payload.Mode)
	if b.Payload.Mode == bundle.PayloadModeExternal {
		fmt.Printf("  Size: %d bytes\n", b.Payload.Size)
		fmt.Printf("  Expected file: %s.payload\n", bundlePath)
	}

	if b.Calibration != nil {
		fmt.Println()
		fmt.Println("Calibration (hint only):")
		fmt.Printf("  Bench difficulty: %d\n", b.Calibration.Bench.Difficulty)
		fmt.Printf("  Bench median:     %.3f seconds\n", b.Calibration.Bench.MedianSeconds)
		fmt.Printf("  Target hint:      %s\n", b.Calibration.TargetHint)
	}

	return nil
}
