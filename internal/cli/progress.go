package cli

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// ProgressMode represents the operation type
type ProgressMode int

const (
	ModeSeal ProgressMode = iota
	ModeUnlock
)

// ProgressBar displays a visual progress bar with speed and ETA
type ProgressBar struct {
	total     uint32
	width     int
	startTime time.Time
	lastPrint time.Time
	mode      ProgressMode
}

// NewProgressBar creates a new progress bar
func NewProgressBar(total uint32, mode ProgressMode) *ProgressBar {
	return &ProgressBar{
		total:     total,
		width:     30,
		startTime: time.Now(),
		mode:      mode,
	}
}

func (p *ProgressBar) icon() string {
	if p.mode == ModeSeal {
		return "🔒"
	}
	return "🔓"
}

// Update updates the progress bar display
func (p *ProgressBar) Update(current uint32) {
	// Skip 100% - let Finish() handle that
	if current >= p.total {
		return
	}

	// Throttle updates to avoid excessive output (update every ~100ms or at key points)
	now := time.Now()
	if current != 0 && now.Sub(p.lastPrint) < 100*time.Millisecond {
		return
	}
	p.lastPrint = now

	pct := float64(current) / float64(p.total) * 100
	elapsed := now.Sub(p.startTime).Seconds()

	// Calculate speed (rounds per second)
	var speed float64
	if elapsed > 0 {
		speed = float64(current) / elapsed
	}

	// Calculate ETA
	var eta string
	if speed > 0 {
		remaining := float64(p.total-current) / speed
		eta = formatDuration(remaining)
	} else {
		eta = "--:--"
	}

	// Build progress bar
	filled := int(float64(p.width) * float64(current) / float64(p.total))
	if filled > p.width {
		filled = p.width
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", p.width-filled)

	// Format output
	fmt.Fprintf(os.Stderr, "\r  %s %s %5.1f%%  %d/%d  %.1f r/s  ETA %s   ",
		p.icon(), bar, pct, current, p.total, speed, eta)
}

// Finish completes the progress bar
func (p *ProgressBar) Finish() {
	elapsed := time.Since(p.startTime).Seconds()
	var speed float64
	if elapsed > 0 {
		speed = float64(p.total) / elapsed
	}

	bar := strings.Repeat("█", p.width)
	fmt.Fprintf(os.Stderr, "\r  %s %s %5.1f%%  %d/%d  %.1f r/s  %s   \n",
		p.icon(), bar, 100.0, p.total, p.total, speed, formatDuration(elapsed))
}

// formatDuration formats seconds as MM:SS or HH:MM:SS
func formatDuration(seconds float64) string {
	if seconds < 0 {
		return "--:--"
	}

	totalSecs := int(seconds)
	hours := totalSecs / 3600
	mins := (totalSecs % 3600) / 60
	secs := totalSecs % 60

	if hours > 0 {
		return fmt.Sprintf("%d:%02d:%02d", hours, mins, secs)
	}
	return fmt.Sprintf("%d:%02d", mins, secs)
}

// ProgressCallback returns a callback function for use with DeriveWithContext
func (p *ProgressBar) Callback() func(current, total uint32) {
	return func(current, total uint32) {
		p.Update(current)
	}
}
