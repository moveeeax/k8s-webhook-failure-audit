// Package report renders findings as a table for humans, JSON for scripts and
// SARIF for GitHub code scanning.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/moveeeax/k8s-webhook-failure-audit/internal/audit"
)

// Mode selects an output format.
type Mode string

const (
	ModeTable Mode = "table"
	ModeJSON  Mode = "json"
	ModeSARIF Mode = "sarif"
)

// Meta describes the run so JSON and SARIF consumers can tell manifest scans
// apart from live-cluster scans.
type Meta struct {
	Version     string    `json:"version"`
	GeneratedAt time.Time `json:"generatedAt"`
	Target      string    `json:"target"`
	Configs     int       `json:"configs"`
	Webhooks    int       `json:"webhooks"`
}

// Write renders the findings in the requested mode.
func Write(w io.Writer, mode Mode, findings []audit.Finding, meta Meta) error {
	switch mode {
	case ModeJSON:
		return writeJSON(w, findings, meta)
	case ModeSARIF:
		return writeSARIF(w, findings, meta)
	default:
		return writeTable(w, findings, meta)
	}
}

func writeTable(out io.Writer, findings []audit.Finding, meta Meta) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintf(out, "no findings: %d webhook(s) across %d configuration(s) in %s look safe\n",
			meta.Webhooks, meta.Configs, meta.Target)
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tRULE\tCONFIGURATION\tWEBHOOK\tDETAIL")
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			strings.ToUpper(f.Severity.String()), f.Rule, f.Config, shorten(f.Webhook, 44), f.Message)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	s := audit.Summarize(findings)
	_, err := fmt.Fprintf(out, "\n%d finding(s): %d high, %d medium, %d low across %d webhook(s) in %s\n",
		s.Total, s.High, s.Medium, s.Low, meta.Webhooks, meta.Target)
	return err
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

type jsonDoc struct {
	Meta     Meta            `json:"meta"`
	Summary  audit.Summary   `json:"summary"`
	Findings []audit.Finding `json:"findings"`
}

func writeJSON(out io.Writer, findings []audit.Finding, meta Meta) error {
	if findings == nil {
		findings = []audit.Finding{}
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonDoc{Meta: meta, Summary: audit.Summarize(findings), Findings: findings})
}

func writeSARIF(out io.Writer, findings []audit.Finding, meta Meta) error {
	ruleIDs := map[string]bool{}
	for _, f := range findings {
		ruleIDs[f.Rule] = true
	}
	var ids []string
	for id := range ruleIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		desc := audit.Descriptions[id]
		if desc == "" {
			desc = id
		}
		rules = append(rules, sarifRule{
			ID:               id,
			Name:             id,
			ShortDescription: sarifText{Text: desc},
			FullDescription:  sarifText{Text: desc},
			HelpURI:          "https://github.com/moveeeax/k8s-webhook-failure-audit#rules",
		})
	}

	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		r := sarifResult{
			RuleID:  f.Rule,
			Level:   f.Severity.SARIFLevel(),
			Message: sarifText{Text: sarifMessage(f)},
		}
		if f.Source != "" && f.Source != "cluster" {
			r.Locations = []sarifLocation{{
				PhysicalLocation: &sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.Source},
					Region:           &sarifRegion{StartLine: 1},
				},
			}}
		} else {
			r.Locations = []sarifLocation{{
				LogicalLocations: []sarifLogical{{
					Name:               f.Webhook,
					FullyQualifiedName: f.Kind + "/" + f.Config + "/" + f.Webhook,
					Kind:               "resource",
				}},
			}}
		}
		results = append(results, r)
	}

	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "k8s-webhook-failure-audit",
				Version:        meta.Version,
				InformationURI: "https://github.com/moveeeax/k8s-webhook-failure-audit",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifMessage(f audit.Finding) string {
	msg := fmt.Sprintf("%s/%s webhook %q: %s", f.Kind, f.Config, f.Webhook, f.Message)
	if f.Remediation != "" {
		msg += " — " + f.Remediation
	}
	return msg
}

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription sarifText `json:"shortDescription"`
	FullDescription  sarifText `json:"fullDescription"`
	HelpURI          string    `json:"helpUri,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysical `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogical struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}
