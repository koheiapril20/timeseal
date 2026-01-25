package cli

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "timeseal",
	Short: "Delay-sealed data bundle tool",
	Long: `timeseal is a CLI tool for sealing data such that recovery requires
a non-trivial amount of sequential computation.

It is designed so that even the creator cannot instantly unlock the data,
without relying on third parties or online services.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(benchCmd)
	rootCmd.AddCommand(calibrateCmd)
	rootCmd.AddCommand(sealCmd)
	rootCmd.AddCommand(unlockCmd)
	rootCmd.AddCommand(infoCmd)
}
