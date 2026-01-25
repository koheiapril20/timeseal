package main

import (
	"os"

	"github.com/koheiapril20/timeseal/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
