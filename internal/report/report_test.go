package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/k8s-webhook-failure-audit/internal/audit"
	"github.com/moveeeax/k8s-webhook-failure-audit/internal/report"
)

var findings = []audit.Finding{
	{
		Rule: audit.RuleFailClosedNoExclusion, Severity: audit.SeverityHigh,
		Kind: "ValidatingWebhookConfiguration", Config: "policy-engine",
		Webhook:     "validate.policy-engine.io",
		Message:     "failurePolicy=Fail intercepts pods in kube-system",
		Remediation: "add a namespaceSelector exclusion", Source: "deploy/policy.yaml",
	},
	{
		Rule: audit.RuleTimeoutTooLong, Severity: audit.SeverityMedium,
		Kind: "ValidatingWebhookConfiguration", Config: "policy-engine",
		Webhook: "validate.policy-engine.io",
		Message: "timeoutSeconds=30 on a fail-closed webhook", Source: "cluster",
	},
}

var meta = report.Meta{
	Version:     "v0.1.0",
	GeneratedAt: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
	Target:      "deploy/",
	Configs:     1,
	Webhooks:    1,
}

func TestTableListsEveryFindingAndASummary(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Write(&buf, report.ModeTable, findings, meta); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"SEVERITY", "RULE", "HIGH", "MEDIUM",
		audit.RuleFailClosedNoExclusion, audit.RuleTimeoutTooLong,
		"policy-engine", "2 finding(s): 1 high, 1 medium, 0 low",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q:\n%s", want, out)
		}
	}
}

func TestTableSaysSoWhenClean(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Write(&buf, report.ModeTable, nil, meta); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no findings") {
		t.Fatalf("clean output = %q", buf.String())
	}
}

func TestJSONIsParseableAndCounted(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Write(&buf, report.ModeJSON, findings, meta); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Meta struct {
			Version  string `json:"version"`
			Target   string `json:"target"`
			Webhooks int    `json:"webhooks"`
		} `json:"meta"`
		Summary struct {
			High, Medium, Low, Total int
		} `json:"summary"`
		Findings []struct {
			Rule        string `json:"rule"`
			Severity    string `json:"severity"`
			Message     string `json:"message"`
			Remediation string `json:"remediation"`
			Source      string `json:"source"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if doc.Meta.Version != "v0.1.0" || doc.Meta.Target != "deploy/" || doc.Meta.Webhooks != 1 {
		t.Errorf("meta = %+v", doc.Meta)
	}
	if doc.Summary.Total != 2 || doc.Summary.High != 1 || doc.Summary.Medium != 1 {
		t.Errorf("summary = %+v", doc.Summary)
	}
	if len(doc.Findings) != 2 {
		t.Fatalf("findings = %d", len(doc.Findings))
	}
	// Severity has to serialize as a name, not the underlying integer.
	if doc.Findings[0].Severity != "high" {
		t.Errorf("severity = %q, want %q", doc.Findings[0].Severity, "high")
	}
	if doc.Findings[0].Remediation == "" {
		t.Error("remediation should survive the JSON round trip")
	}
}

func TestJSONEmitsAnEmptyArrayWhenClean(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Write(&buf, report.ModeJSON, nil, meta); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Fatalf("clean JSON should carry an empty array, got:\n%s", buf.String())
	}
}

func TestSARIFShape(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Write(&buf, report.ModeSARIF, findings, meta); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID               string `json:"id"`
						ShortDescription struct {
							Text string `json:"text"`
						} `json:"shortDescription"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation *struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
					LogicalLocations []struct {
						FullyQualifiedName string `json:"fullyQualifiedName"`
					} `json:"logicalLocations"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\n%s", err, buf.String())
	}
	if doc.Version != "2.1.0" || doc.Schema == "" {
		t.Errorf("version = %q, schema = %q", doc.Version, doc.Schema)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "k8s-webhook-failure-audit" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	// Every rule referenced by a result must be declared, with a description.
	declared := map[string]string{}
	for _, r := range run.Tool.Driver.Rules {
		declared[r.ID] = r.ShortDescription.Text
	}
	if len(declared) != 2 {
		t.Fatalf("declared rules = %v", declared)
	}
	for _, res := range run.Results {
		desc, ok := declared[res.RuleID]
		if !ok {
			t.Errorf("result references undeclared rule %q", res.RuleID)
		}
		if desc == "" {
			t.Errorf("rule %q has no description", res.RuleID)
		}
	}
	if len(run.Results) != 2 {
		t.Fatalf("results = %d", len(run.Results))
	}
	if run.Results[0].Level != "error" || run.Results[1].Level != "warning" {
		t.Errorf("levels = %q, %q", run.Results[0].Level, run.Results[1].Level)
	}
	// A manifest finding gets a file location; a cluster finding gets a
	// logical one, because there is no file to annotate.
	if loc := run.Results[0].Locations[0].PhysicalLocation; loc == nil || loc.ArtifactLocation.URI != "deploy/policy.yaml" {
		t.Errorf("manifest finding should carry a physical location, got %+v", run.Results[0].Locations[0])
	}
	if lls := run.Results[1].Locations[0].LogicalLocations; len(lls) == 0 ||
		lls[0].FullyQualifiedName != "ValidatingWebhookConfiguration/policy-engine/validate.policy-engine.io" {
		t.Errorf("cluster finding should carry a logical location, got %+v", run.Results[1].Locations[0])
	}
	if !strings.Contains(run.Results[0].Message.Text, "add a namespaceSelector exclusion") {
		t.Errorf("SARIF message should include the remediation: %q", run.Results[0].Message.Text)
	}
}

func TestSARIFLevels(t *testing.T) {
	for sev, want := range map[audit.Severity]string{
		audit.SeverityHigh:   "error",
		audit.SeverityMedium: "warning",
		audit.SeverityLow:    "note",
	} {
		if got := sev.SARIFLevel(); got != want {
			t.Errorf("%s -> %q, want %q", sev, got, want)
		}
	}
}
