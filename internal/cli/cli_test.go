package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/k8s-webhook-failure-audit/internal/audit"
	"github.com/moveeeax/k8s-webhook-failure-audit/internal/cli"
	"github.com/moveeeax/k8s-webhook-failure-audit/internal/load"
	"github.com/moveeeax/k8s-webhook-failure-audit/internal/model"
)

var refTime = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func deps() cli.Deps {
	return cli.Deps{
		Manifests: load.Manifests,
		Cluster: func(context.Context, string, string) ([]model.Config, *audit.ClusterInfo, error) {
			return nil, nil, errors.New("no cluster in tests")
		},
		Now: func() time.Time { return refTime },
	}
}

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := cli.RunWithDeps(args, &out, &errBuf, deps())
	return code, out.String(), errBuf.String()
}

func fixtures() string { return filepath.Join("..", "audit", "testdata") }

func TestHighFindingsExitOne(t *testing.T) {
	code, out, _ := run(t, "--manifests", filepath.Join(fixtures(), "deadlock.yaml"))
	if code != cli.ExitFindings {
		t.Fatalf("exit = %d, want %d\n%s", code, cli.ExitFindings, out)
	}
	if !strings.Contains(out, audit.RuleFailClosedNoExclusion) {
		t.Errorf("output missing the deadlock rule:\n%s", out)
	}
}

func TestCleanManifestsExitZero(t *testing.T) {
	code, out, _ := run(t, "--manifests", filepath.Join(fixtures(), "excluded.yaml"))
	if code != cli.ExitOK {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "no findings") {
		t.Errorf("output = %q", out)
	}
}

// A medium-only finding must not fail the default gate, but must fail
// --fail-on medium.
func TestFailOnThreshold(t *testing.T) {
	path := filepath.Join(fixtures(), "no-ca.yaml")
	if code, out, _ := run(t, "--manifests", path); code != cli.ExitOK {
		t.Fatalf("default gate: exit = %d, want 0\n%s", code, out)
	}
	if code, _, _ := run(t, "--manifests", path, "--fail-on", "medium"); code != cli.ExitFindings {
		t.Fatalf("medium gate: exit = %d, want 1", code)
	}
	if code, _, _ := run(t, "--manifests", filepath.Join(fixtures(), "deadlock.yaml"), "--fail-on", "none"); code != cli.ExitOK {
		t.Fatalf("--fail-on none: exit = %d, want 0", code)
	}
}

func TestJSONOutput(t *testing.T) {
	code, out, _ := run(t, "--manifests", filepath.Join(fixtures(), "deadlock.yaml"), "--json")
	if code != cli.ExitFindings {
		t.Fatalf("exit = %d", code)
	}
	var doc struct {
		Meta struct {
			Target   string `json:"target"`
			Configs  int    `json:"configs"`
			Webhooks int    `json:"webhooks"`
		} `json:"meta"`
		Summary struct {
			High, Total int
		} `json:"summary"`
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if doc.Meta.Configs != 1 || doc.Meta.Webhooks != 1 {
		t.Errorf("meta = %+v", doc.Meta)
	}
	if doc.Summary.High != 2 || doc.Summary.Total != 3 {
		t.Errorf("summary = %+v", doc.Summary)
	}
	if !strings.Contains(doc.Meta.Target, "deadlock.yaml") {
		t.Errorf("target = %q", doc.Meta.Target)
	}
}

func TestSARIFOutput(t *testing.T) {
	code, out, _ := run(t, "--manifests", filepath.Join(fixtures(), "deadlock.yaml"), "--sarif")
	if code != cli.ExitFindings {
		t.Fatalf("exit = %d", code)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid SARIF: %v\n%s", err, out)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v", doc["version"])
	}
}

func TestJSONAndSARIFAreExclusive(t *testing.T) {
	code, _, errOut := run(t, "--manifests", fixtures(), "--json", "--sarif")
	if code != cli.ExitError {
		t.Fatalf("exit = %d, want %d", code, cli.ExitError)
	}
	if !strings.Contains(errOut, "mutually exclusive") {
		t.Errorf("stderr = %q", errOut)
	}
}

func TestBadSeverityIsAnError(t *testing.T) {
	code, _, errOut := run(t, "--manifests", fixtures(), "--fail-on", "critical")
	if code != cli.ExitError {
		t.Fatalf("exit = %d, want %d", code, cli.ExitError)
	}
	if !strings.Contains(errOut, "critical") {
		t.Errorf("stderr = %q", errOut)
	}
}

func TestMissingManifestPathIsAnError(t *testing.T) {
	code, _, errOut := run(t, "--manifests", filepath.Join(t.TempDir(), "absent"))
	if code != cli.ExitError {
		t.Fatalf("exit = %d, want %d", code, cli.ExitError)
	}
	if !strings.Contains(errOut, "error:") {
		t.Errorf("stderr = %q", errOut)
	}
}

func TestClusterLoaderErrorIsAnError(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := cli.RunWithDeps(nil, &out, &errBuf, deps())
	if code != cli.ExitError {
		t.Fatalf("exit = %d, want %d", code, cli.ExitError)
	}
	if !strings.Contains(errBuf.String(), "no cluster in tests") {
		t.Errorf("stderr = %q", errBuf.String())
	}
}

func TestClusterModeUsesLiveInfo(t *testing.T) {
	d := deps()
	d.Cluster = func(context.Context, string, string) ([]model.Config, *audit.ClusterInfo, error) {
		cfgs := []model.Config{{
			Kind: model.KindValidating, Name: "live", Source: "cluster",
			Webhooks: []model.Webhook{{
				Name: "validate.live.example.com", FailurePolicy: "Fail",
				CABundle: nil,
				Service:  &model.ServiceRef{Namespace: "ops", Name: "gone"},
			}},
		}}
		info := &audit.ClusterInfo{
			Live:            true,
			NamespaceLabels: map[string]map[string]string{"kube-system": {"kubernetes.io/metadata.name": "kube-system"}},
			Services:        map[string]audit.ServiceInfo{"ops/gone": {Exists: false}},
		}
		return cfgs, info, nil
	}
	var out, errBuf bytes.Buffer
	code := cli.RunWithDeps([]string{"--context", "prod", "--json"}, &out, &errBuf, d)
	if code != cli.ExitFindings {
		t.Fatalf("exit = %d, want %d\n%s%s", code, cli.ExitFindings, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), audit.RuleBackendMissing) {
		t.Errorf("expected a missing-backend finding:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "cluster prod") {
		t.Errorf("target should name the context:\n%s", out.String())
	}
}

func TestEmptyTargetWarnsButSucceeds(t *testing.T) {
	dir := t.TempDir()
	code, out, errOut := run(t, "--manifests", dir)
	if code != cli.ExitOK {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(errOut, "no admission webhook configurations found") {
		t.Errorf("stderr = %q", errOut)
	}
}

func TestVersionFlag(t *testing.T) {
	code, out, _ := run(t, "--version")
	if code != cli.ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if strings.TrimSpace(out) == "" {
		t.Error("--version printed nothing")
	}
}

func TestThresholdFlagsAreHonoured(t *testing.T) {
	// deadlock.yaml has timeoutSeconds 30; raising the ceiling above it drops
	// the timeout finding and leaves the two high ones.
	_, out, _ := run(t, "--manifests", filepath.Join(fixtures(), "deadlock.yaml"), "--max-timeout", "60", "--json")
	if strings.Contains(out, audit.RuleTimeoutTooLong) {
		t.Errorf("--max-timeout was ignored:\n%s", out)
	}
	// excluded.yaml's bundle runs to 2035; a huge window must flag it.
	_, out, _ = run(t, "--manifests", filepath.Join(fixtures(), "excluded.yaml"), "--cert-expiry-days", "9000", "--json")
	if !strings.Contains(out, audit.RuleCertExpiring) {
		t.Errorf("--cert-expiry-days was ignored:\n%s", out)
	}
}

func TestProtectedNamespacesFlag(t *testing.T) {
	// excluded.yaml carves out kube-system and policy-system by name, so
	// protecting a third namespace brings the deadlock back.
	code, out, _ := run(t, "--manifests", filepath.Join(fixtures(), "excluded.yaml"),
		"--protected-namespaces", "flux-system")
	if code != cli.ExitFindings {
		t.Fatalf("exit = %d, want %d\n%s", code, cli.ExitFindings, out)
	}
	if !strings.Contains(out, "flux-system") {
		t.Errorf("output should name the protected namespace:\n%s", out)
	}
}

func TestSystemResourcesFlag(t *testing.T) {
	path := filepath.Join(fixtures(), "system-resources.yaml")
	code, out, _ := run(t, "--manifests", path)
	if code != cli.ExitFindings || !strings.Contains(out, audit.RuleSystemResources) {
		t.Fatalf("default list: exit = %d\n%s", code, out)
	}

	// An empty list turns the rule off.
	if code, out, _ := run(t, "--manifests", path, "--system-resources", ""); code != cli.ExitOK {
		t.Fatalf("empty list: exit = %d, want 0\n%s", code, out)
	}

	// A custom list replaces the defaults rather than adding to them.
	code, out, _ = run(t, "--manifests", path, "--system-resources", "nodes/status")
	if code != cli.ExitFindings || !strings.Contains(out, "nodes/status") || strings.Contains(out, "leases") {
		t.Fatalf("custom list: exit = %d\n%s", code, out)
	}
}

func TestBadSystemResourceIsAnError(t *testing.T) {
	code, _, errOut := run(t, "--manifests", fixtures(), "--system-resources", "pods/*")
	if code != cli.ExitError {
		t.Fatalf("exit = %d, want %d", code, cli.ExitError)
	}
	if !strings.Contains(errOut, "--system-resources") {
		t.Errorf("stderr = %q", errOut)
	}
}
