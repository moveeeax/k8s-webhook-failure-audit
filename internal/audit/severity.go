package audit

import (
	"fmt"
	"strings"
)

// Severity orders findings so --fail-on can gate on them.
type Severity int

const (
	// SeverityNone is only used as a --fail-on value meaning "never fail".
	SeverityNone Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
)

func (s Severity) String() string {
	switch s {
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "none"
	}
}

// MarshalJSON renders the severity as its lowercase name.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// SARIFLevel maps a severity onto the SARIF result levels GitHub code scanning
// understands.
func (s Severity) SARIFLevel() string {
	switch s {
	case SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// ParseSeverity accepts high, medium, low or none.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return SeverityHigh, nil
	case "medium", "med":
		return SeverityMedium, nil
	case "low":
		return SeverityLow, nil
	case "none", "off":
		return SeverityNone, nil
	}
	return SeverityNone, fmt.Errorf("unknown severity %q (want high, medium, low or none)", s)
}
