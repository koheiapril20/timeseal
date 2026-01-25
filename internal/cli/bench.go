package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/koheiapril20/timeseal/internal/delaykdf"
	"github.com/spf13/cobra"
)

var benchCmd = &cobra.Command{
	Use:   "bench",
	Short: "Benchmark the local machine",
	Long:  `Measures how long difficulty=1 takes on this machine.`,
	RunE:  runBench,
}

var (
	benchDifficulty uint32
	benchSeconds    int
	benchJSON       bool
)

func init() {
	benchCmd.Flags().Uint32Var(&benchDifficulty, "difficulty", 1, "Difficulty level to benchmark")
	benchCmd.Flags().IntVar(&benchSeconds, "seconds", 20, "Duration to run benchmark")
	benchCmd.Flags().BoolVar(&benchJSON, "json", false, "Output in JSON format")
}

type BenchResult struct {
	Difficulty    uint32  `json:"difficulty"`
	Iterations    int     `json:"iterations"`
	MedianSeconds float64 `json:"median_seconds"`
	MinSeconds    float64 `json:"min_seconds"`
	MaxSeconds    float64 `json:"max_seconds"`
}

func runBench(cmd *cobra.Command, args []string) error {
	params := delaykdf.DefaultParams(benchDifficulty)

	if !benchJSON {
		fmt.Fprintf(os.Stderr, "Benchmarking difficulty=%d for %d seconds...\n", benchDifficulty, benchSeconds)
	}

	seed, err := delaykdf.GenerateSeed()
	if err != nil {
		return fmt.Errorf("failed to generate seed: %w", err)
	}

	var durations []time.Duration
	deadline := time.Now().Add(time.Duration(benchSeconds) * time.Second)

	for time.Now().Before(deadline) {
		start := time.Now()
		_, err := delaykdf.Derive(seed, params)
		if err != nil {
			return fmt.Errorf("delaykdf failed: %w", err)
		}
		durations = append(durations, time.Since(start))

		if !benchJSON {
			fmt.Fprintf(os.Stderr, "\r  Iterations: %d", len(durations))
		}
	}

	if !benchJSON {
		fmt.Fprintln(os.Stderr)
	}

	if len(durations) == 0 {
		return fmt.Errorf("no iterations completed")
	}

	sort.Slice(durations, func(i, j int) bool {
		return durations[i] < durations[j]
	})

	median := durations[len(durations)/2]
	minD := durations[0]
	maxD := durations[len(durations)-1]

	result := BenchResult{
		Difficulty:    benchDifficulty,
		Iterations:    len(durations),
		MedianSeconds: median.Seconds(),
		MinSeconds:    minD.Seconds(),
		MaxSeconds:    maxD.Seconds(),
	}

	if benchJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	fmt.Printf("Difficulty: %d\n", result.Difficulty)
	fmt.Printf("Iterations: %d\n", result.Iterations)
	fmt.Printf("Median:     %.3f seconds\n", result.MedianSeconds)
	fmt.Printf("Min:        %.3f seconds\n", result.MinSeconds)
	fmt.Printf("Max:        %.3f seconds\n", result.MaxSeconds)

	return nil
}

func RunBenchmark(difficulty uint32, seconds int) (*BenchResult, error) {
	params := delaykdf.DefaultParams(difficulty)

	seed, err := delaykdf.GenerateSeed()
	if err != nil {
		return nil, err
	}

	var durations []time.Duration
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)

	for time.Now().Before(deadline) {
		start := time.Now()
		_, err := delaykdf.Derive(seed, params)
		if err != nil {
			return nil, err
		}
		durations = append(durations, time.Since(start))
	}

	if len(durations) == 0 {
		return nil, fmt.Errorf("no iterations completed")
	}

	sort.Slice(durations, func(i, j int) bool {
		return durations[i] < durations[j]
	})

	median := durations[len(durations)/2]
	minD := durations[0]
	maxD := durations[len(durations)-1]

	return &BenchResult{
		Difficulty:    difficulty,
		Iterations:    len(durations),
		MedianSeconds: median.Seconds(),
		MinSeconds:    minD.Seconds(),
		MaxSeconds:    maxD.Seconds(),
	}, nil
}
