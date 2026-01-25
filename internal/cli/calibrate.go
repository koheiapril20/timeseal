package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

var calibrateCmd = &cobra.Command{
	Use:   "calibrate",
	Short: "Suggest a difficulty based on target duration",
	Long:  `Runs benchmark internally and suggests a difficulty for the target duration.`,
	RunE:  runCalibrate,
}

var (
	calibrateTarget       string
	calibrateBenchSeconds int
	calibrateJSON         bool
)

func init() {
	calibrateCmd.Flags().StringVar(&calibrateTarget, "target", "", "Target duration (e.g., 1h, 1d, 7d)")
	calibrateCmd.Flags().IntVar(&calibrateBenchSeconds, "bench-seconds", 20, "Duration to run benchmark")
	calibrateCmd.Flags().BoolVar(&calibrateJSON, "json", false, "Output in JSON format")
	calibrateCmd.MarkFlagRequired("target")
}

type CalibrateResult struct {
	TargetDuration      string  `json:"target_duration"`
	TargetSeconds       float64 `json:"target_seconds"`
	BenchMedianSeconds  float64 `json:"bench_median_seconds"`
	SuggestedDifficulty uint32  `json:"suggested_difficulty"`
}

func runCalibrate(cmd *cobra.Command, args []string) error {
	targetDuration, err := parseDuration(calibrateTarget)
	if err != nil {
		return fmt.Errorf("invalid target duration: %w", err)
	}

	if !calibrateJSON {
		fmt.Fprintf(os.Stderr, "Running benchmark for %d seconds...\n", calibrateBenchSeconds)
	}

	bench, err := RunBenchmark(1, calibrateBenchSeconds)
	if err != nil {
		return fmt.Errorf("benchmark failed: %w", err)
	}

	targetSeconds := targetDuration.Seconds()
	suggestedDifficulty := uint32(targetSeconds / bench.MedianSeconds)
	if suggestedDifficulty < 1 {
		suggestedDifficulty = 1
	}

	result := CalibrateResult{
		TargetDuration:      calibrateTarget,
		TargetSeconds:       targetSeconds,
		BenchMedianSeconds:  bench.MedianSeconds,
		SuggestedDifficulty: suggestedDifficulty,
	}

	if calibrateJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	fmt.Printf("Target:              %s (%.0f seconds)\n", calibrateTarget, targetSeconds)
	fmt.Printf("Bench (difficulty=1): %.3f seconds/iteration\n", bench.MedianSeconds)
	fmt.Printf("Suggested difficulty: %d\n", suggestedDifficulty)
	fmt.Printf("\nNote: Actual unlock time may vary based on hardware.\n")

	return nil
}

func parseDuration(s string) (time.Duration, error) {
	// Try standard Go duration first
	d, err := time.ParseDuration(s)
	if err == nil {
		return d, nil
	}

	// Try custom format: Nd (days)
	re := regexp.MustCompile(`^(\d+)d$`)
	matches := re.FindStringSubmatch(s)
	if len(matches) == 2 {
		days, _ := strconv.Atoi(matches[1])
		return time.Duration(days) * 24 * time.Hour, nil
	}

	return 0, fmt.Errorf("invalid duration format: %s (use e.g., 1h, 30m, 1d)", s)
}
