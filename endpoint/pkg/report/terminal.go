package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Styles for terminal output
var (
	// Colors
	criticalColor = lipgloss.Color("#FF0000")
	highColor     = lipgloss.Color("#FF6600")
	mediumColor   = lipgloss.Color("#FFCC00")
	lowColor      = lipgloss.Color("#00CC00")
	infoColor     = lipgloss.Color("#0099FF")

	// Title box style
	titleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00FF00")).
		Background(lipgloss.Color("#1a1a1a")).
		Padding(0, 2).
		MarginBottom(1)

	// Box style for header
	boxStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#00FF00")).
		Padding(0, 2).
		Width(60)

	// Progress bar styles
	progressBarFull  = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00"))
	progressBarEmpty = lipgloss.NewStyle().Foreground(lipgloss.Color("#333333"))

	// Risk level styles
	criticalStyle = lipgloss.NewStyle().Foreground(criticalColor).Bold(true)
	highStyle     = lipgloss.NewStyle().Foreground(highColor).Bold(true)
	mediumStyle   = lipgloss.NewStyle().Foreground(mediumColor)
	lowStyle      = lipgloss.NewStyle().Foreground(lowColor)
	infoStyle     = lipgloss.NewStyle().Foreground(infoColor)

	// Section style
	sectionStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF")).
		Bold(true).
		MarginTop(1)

	// Divider
	dividerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#444444"))
)

// ScanPhase represents a scanning phase
type ScanPhase struct {
	Name     string
	Total    int
	Current  int
	Found    int
	Status   string // "waiting", "running", "done"
	Duration time.Duration
}

// Finding represents a discovered item
type Finding struct {
	Type    string // subdomain, path, port, auth
	Target  string
	Detail  string
	Risk    string
	Service string
}

// TerminalUI handles terminal output
type TerminalUI struct {
	Target     string
	Mode       string
	Workers    int
	Phases     []ScanPhase
	Findings   []Finding
	StartTime  time.Time
}

// NewTerminalUI creates a new terminal UI
func NewTerminalUI(target, mode string, workers int) *TerminalUI {
	return &TerminalUI{
		Target:    target,
		Mode:      mode,
		Workers:   workers,
		StartTime: time.Now(),
		Phases: []ScanPhase{
			{Name: "Subdomain Discovery", Status: "waiting"},
			{Name: "Path Discovery", Status: "waiting"},
			{Name: "Port Scanning", Status: "waiting"},
			{Name: "Service Detection", Status: "waiting"},
			{Name: "Auth Testing", Status: "waiting"},
		},
		Findings: make([]Finding, 0),
	}
}

// PrintHeader prints the scan header
func (ui *TerminalUI) PrintHeader() {
	header := fmt.Sprintf(`
  ENDPOINT SCANNER v2.0
  Target: %s
  Mode: %s
  Workers: %d
`, ui.Target, ui.Mode, ui.Workers)

	fmt.Println(boxStyle.Render(header))
}

// PrintProgress prints progress for all phases
func (ui *TerminalUI) PrintProgress() {
	fmt.Print("\033[H\033[2J") // Clear screen
	ui.PrintHeader()
	fmt.Println()

	for i, phase := range ui.Phases {
		status := ui.formatPhaseStatus(i+1, phase)
		fmt.Println(status)
	}

	fmt.Println()
	fmt.Println(dividerStyle.Render(strings.Repeat("─", 60)))
	fmt.Println(sectionStyle.Render(" Live Results"))
	fmt.Println(dividerStyle.Render(strings.Repeat("─", 60)))

	// Show last 10 findings
	start := 0
	if len(ui.Findings) > 10 {
		start = len(ui.Findings) - 10
	}
	for _, f := range ui.Findings[start:] {
		fmt.Println(ui.formatFinding(f))
	}
}

// formatPhaseStatus formats a phase status line
func (ui *TerminalUI) formatPhaseStatus(num int, phase ScanPhase) string {
	var statusIcon string
	var progressBar string
	var timeStr string

	switch phase.Status {
	case "waiting":
		statusIcon = "○"
		progressBar = ui.makeProgressBar(0, 20)
		timeStr = "(waiting)"
	case "running":
		statusIcon = "◉"
		percent := 0
		if phase.Total > 0 {
			percent = (phase.Current * 100) / phase.Total
		}
		progressBar = ui.makeProgressBar(percent, 20)
		timeStr = fmt.Sprintf("(%s)", phase.Duration.Round(time.Millisecond))
	case "done":
		statusIcon = "✓"
		progressBar = ui.makeProgressBar(100, 20)
		timeStr = fmt.Sprintf("(%.1fs)", phase.Duration.Seconds())
	}

	return fmt.Sprintf(" [%d/5] %s %s %s %d%% %s",
		num,
		statusIcon,
		padRight(phase.Name, 20),
		progressBar,
		ui.getPercent(phase),
		timeStr,
	)
}

// makeProgressBar creates a visual progress bar
func (ui *TerminalUI) makeProgressBar(percent, width int) string {
	filled := (percent * width) / 100
	empty := width - filled

	bar := progressBarFull.Render(strings.Repeat("█", filled))
	bar += progressBarEmpty.Render(strings.Repeat("░", empty))
	return bar
}

// getPercent calculates percentage
func (ui *TerminalUI) getPercent(phase ScanPhase) int {
	if phase.Status == "done" {
		return 100
	}
	if phase.Total == 0 {
		return 0
	}
	return (phase.Current * 100) / phase.Total
}

// formatFinding formats a finding for display
func (ui *TerminalUI) formatFinding(f Finding) string {
	var riskStyle lipgloss.Style

	switch f.Risk {
	case "CRITICAL":
		riskStyle = criticalStyle
	case "HIGH":
		riskStyle = highStyle
	case "MEDIUM":
		riskStyle = mediumStyle
	case "LOW":
		riskStyle = lowStyle
	default:
		riskStyle = infoStyle
	}

	risk := riskStyle.Render(fmt.Sprintf("[%s]", padRight(f.Risk, 8)))
	return fmt.Sprintf(" %s %s - %s", risk, f.Target, f.Detail)
}

// AddFinding adds a new finding
func (ui *TerminalUI) AddFinding(f Finding) {
	ui.Findings = append(ui.Findings, f)
}

// UpdatePhase updates a phase's progress
func (ui *TerminalUI) UpdatePhase(index, current, total, found int, status string) {
	if index >= 0 && index < len(ui.Phases) {
		ui.Phases[index].Current = current
		ui.Phases[index].Total = total
		ui.Phases[index].Found = found
		ui.Phases[index].Status = status
		ui.Phases[index].Duration = time.Since(ui.StartTime)
	}
}

// PrintSummary prints the final summary
func (ui *TerminalUI) PrintSummary() {
	totalTime := time.Since(ui.StartTime)

	fmt.Println()
	fmt.Println(boxStyle.Render(fmt.Sprintf(`
  SCAN COMPLETE

  Duration: %s
  Total Findings: %d

  By Severity:
    CRITICAL: %d
    HIGH:     %d
    MEDIUM:   %d
    LOW:      %d
    INFO:     %d
`,
		totalTime.Round(time.Second),
		len(ui.Findings),
		ui.countBySeverity("CRITICAL"),
		ui.countBySeverity("HIGH"),
		ui.countBySeverity("MEDIUM"),
		ui.countBySeverity("LOW"),
		ui.countBySeverity("INFO"),
	)))
}

// countBySeverity counts findings by severity
func (ui *TerminalUI) countBySeverity(severity string) int {
	count := 0
	for _, f := range ui.Findings {
		if f.Risk == severity {
			count++
		}
	}
	return count
}

// PrintFindingInstant prints a finding immediately (for non-TUI mode)
func PrintFindingInstant(risk, target, detail string) {
	var riskStyle lipgloss.Style

	switch risk {
	case "CRITICAL":
		riskStyle = criticalStyle
	case "HIGH":
		riskStyle = highStyle
	case "MEDIUM":
		riskStyle = mediumStyle
	case "LOW":
		riskStyle = lowStyle
	default:
		riskStyle = infoStyle
	}

	fmt.Printf(" %s %s - %s\n",
		riskStyle.Render(fmt.Sprintf("[%s]", padRight(risk, 8))),
		target,
		detail,
	)
}

// Helper function to pad strings
func padRight(s string, length int) string {
	if len(s) >= length {
		return s[:length]
	}
	return s + strings.Repeat(" ", length-len(s))
}

// PrintPhaseStart prints phase start message
func PrintPhaseStart(phase string, total int) {
	fmt.Printf("\n%s Scanning %d items...\n",
		sectionStyle.Render(fmt.Sprintf("[+] %s:", phase)),
		total,
	)
}

// PrintPhaseComplete prints phase completion message
func PrintPhaseComplete(phase string, found int, duration time.Duration) {
	fmt.Printf("%s Found %d items (%.1fs)\n",
		sectionStyle.Render(fmt.Sprintf("[✓] %s:", phase)),
		found,
		duration.Seconds(),
	)
}
