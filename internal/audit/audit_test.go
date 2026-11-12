package audit_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/moveeeax/k8s-webhook-failure-audit/internal/audit"
	"github.com/moveeeax/k8s-webhook-failure-audit/internal/load"
	"github.com/moveeeax/k8s-webhook-failure-audit/internal/model"
)

// refTime is pinned so the committed fixture certificate (valid 2025-2035)
// never turns the suite into a time bomb.
var refTime = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func opts() audit.Options {
	o := audit.DefaultOptions()
	o.Now = refTime
	return o
}

func loadFixture(t *testing.T, name string) []model.Config {
	t.Helper()
	cfgs, err := load.Manifests([]string{filepath.Join("testdata", name)})
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	if len(cfgs) == 0 {
		t.Fatalf("load %s: no webhook configurations parsed", name)
	}
	return cfgs
}

func ruleSet(findings []audit.Finding) []string {
	var out []string
	for _, f := range findings {
		out = append(out, f.Rule+"/"+f.Severity.String())
	}
	sort.Strings(out)
	return out
}

func TestManifestFixtures(t *testing.T) {
	cases := []struct {
		fixture string
		want    []string
	}{
		{"deadlock.yaml", []string{
			"FAIL_CLOSED_NO_EXCLUSION/high",
			"NO_CA_BUNDLE/high",
			"TIMEOUT_TOO_LONG/medium",
		}},
		{"excluded.yaml", nil},
		{"ingress-only.yaml", nil},
		{"broad.yaml", []string{
			"BROAD_RULES/high",
			"FAIL_CLOSED_NO_EXCLUSION/high",
			"INTERCEPTS_SYSTEM_RESOURCES/high",
			"TIMEOUT_TOO_LONG/medium",
		}},
		{"injected-ca.yaml", nil},
		{"fail-open.yaml", nil},
		{"label-selector.yaml", []string{"FAIL_CLOSED_NO_EXCLUSION/medium"}},
		{"no-ca.yaml", []string{"NO_CA_BUNDLE/medium"}},
		{"bad-ca.yaml", []string{"CA_BUNDLE_INVALID/high"}},
		{"system-resources.yaml", []string{"INTERCEPTS_SYSTEM_RESOURCES/high"}},
		{"system-match-conditions.yaml", []string{"INTERCEPTS_SYSTEM_RESOURCES/medium"}},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			got := ruleSet(audit.Run(loadFixture(t, tc.fixture), opts(), nil))
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Fatalf("findings mismatch\n got: %v\nwant: %v", got, tc.want)
			}
		})
	}
}

// The deadlock finding has to name both the control-plane namespace and the
// resources it intercepts, otherwise the output is not actionable.
func TestDeadlockMessageIsActionable(t *testing.T) {
	findings := audit.Run(loadFixture(t, "deadlock.yaml"), opts(), nil)
	var f audit.Finding
	for _, c := range findings {
		if c.Rule == audit.RuleFailClosedNoExclusion {
			f = c
		}
	}
	if f.Rule == "" {
		t.Fatal("expected a deadlock finding")
	}
	for _, want := range []string{"kube-system", "pods", "policy-system", "namespaceSelector"} {
		if !strings.Contains(f.Message+" "+f.Remediation, want) {
			t.Errorf("finding does not mention %q: %s / %s", want, f.Message, f.Remediation)
		}
	}
	if f.Source != filepath.Join("testdata", "deadlock.yaml") {
		t.Errorf("source = %q, want the fixture path", f.Source)
	}
}

// cert-manager's webhook uses resources ["*/*"], but only inside its own API
// groups, so the wildcard must not be read as "intercepts pods".
func TestWildcardResourcesRespectAPIGroups(t *testing.T) {
	for _, f := range audit.Run(loadFixture(t, "injected-ca.yaml"), opts(), nil) {
		if f.Rule == audit.RuleFailClosedNoExclusion {
			t.Fatalf("false positive on a CRD-scoped wildcard: %s", f.Message)
		}
	}
}

func TestMultiDocumentAndNonWebhookDocsAreHandled(t *testing.T) {
	cfgs := loadFixture(t, "multidoc.yaml")
	if len(cfgs) != 1 {
		t.Fatalf("parsed %d configurations, want 1", len(cfgs))
	}
	if cfgs[0].Name != "from-multidoc" {
		t.Fatalf("name = %q", cfgs[0].Name)
	}
	// configmaps are a recovery resource, so this one does deadlock.
	if got := ruleSet(audit.Run(cfgs, opts(), nil)); len(got) != 1 || !strings.HasPrefix(got[0], audit.RuleFailClosedNoExclusion) {
		t.Fatalf("findings = %v", got)
	}
}

func TestDeleteOnlyWebhookDoesNotDeadlock(t *testing.T) {
	cfg := model.Config{
		Kind: model.KindValidating, Name: "deleter", Source: "unit",
		Webhooks: []model.Webhook{{
			Name:          "delete.example.com",
			FailurePolicy: "Fail",
			CABundle:      certPEM(t, refTime.AddDate(2, 0, 0)),
			Service:       &model.ServiceRef{Namespace: "ops", Name: "deleter"},
			Rules: []model.Rule{{
				APIGroups: []string{""}, APIVersions: []string{"v1"},
				Resources: []string{"pods"}, Operations: []string{"DELETE"},
				Scope: "Namespaced",
			}},
		}},
	}
	if got := audit.Run([]model.Config{cfg}, opts(), nil); len(got) != 0 {
		t.Fatalf("expected no findings for a DELETE-only webhook, got %v", ruleSet(got))
	}
}

// An unset failurePolicy is Fail in admissionregistration/v1. Treating it as
// fail-open would miss the most common version of this outage.
func TestUnsetFailurePolicyIsFailClosed(t *testing.T) {
	cfg := model.Config{
		Kind: model.KindMutating, Name: "defaulted", Source: "unit",
		Webhooks: []model.Webhook{{
			Name:     "mutate.example.com",
			CABundle: certPEM(t, refTime.AddDate(2, 0, 0)),
			Service:  &model.ServiceRef{Namespace: "ops", Name: "mutator"},
			Rules: []model.Rule{{
				APIGroups: []string{""}, APIVersions: []string{"v1"},
				Resources: []string{"pods"}, Operations: []string{"CREATE"},
				Scope: "Namespaced",
			}},
		}},
	}
	got := audit.Run([]model.Config{cfg}, opts(), nil)
	if len(got) != 1 || got[0].Rule != audit.RuleFailClosedNoExclusion || got[0].Severity != audit.SeverityHigh {
		t.Fatalf("findings = %v", ruleSet(got))
	}
	if !strings.Contains(got[0].Message, "failurePolicy=Fail") {
		t.Errorf("message should spell out the defaulted policy: %s", got[0].Message)
	}
}

func TestCertificateExpiry(t *testing.T) {
	cases := []struct {
		name     string
		notAfter time.Time
		wantRule string
		wantSev  audit.Severity
	}{
		{"healthy", refTime.AddDate(1, 0, 0), "", audit.SeverityNone},
		{"expiring soon", refTime.Add(72 * time.Hour), audit.RuleCertExpiring, audit.SeverityHigh},
		{"expiring within window", refTime.Add(20 * 24 * time.Hour), audit.RuleCertExpiring, audit.SeverityMedium},
		{"expired", refTime.Add(-48 * time.Hour), audit.RuleCertExpired, audit.SeverityHigh},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := model.Config{
				Kind: model.KindValidating, Name: "certs", Source: "unit",
				Webhooks: []model.Webhook{{
					Name:          "validate.certs.example.com",
					FailurePolicy: "Fail",
					CABundle:      certPEM(t, tc.notAfter),
					Service:       &model.ServiceRef{Namespace: "ops", Name: "certs"},
					Rules: []model.Rule{{
						APIGroups: []string{"example.com"}, APIVersions: []string{"v1"},
						Resources: []string{"widgets"}, Operations: []string{"CREATE"},
						Scope: "Namespaced",
					}},
				}},
			}
			got := audit.Run([]model.Config{cfg}, opts(), nil)
			if tc.wantRule == "" {
				if len(got) != 0 {
					t.Fatalf("expected no findings, got %v", ruleSet(got))
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected one finding, got %v", ruleSet(got))
			}
			if got[0].Rule != tc.wantRule || got[0].Severity != tc.wantSev {
				t.Fatalf("got %s/%s, want %s/%s", got[0].Rule, got[0].Severity, tc.wantRule, tc.wantSev)
			}
		})
	}
}

// The earliest expiry in a bundle is the one that matters.
func TestBundleUsesEarliestExpiry(t *testing.T) {
	bundle := append(certPEM(t, refTime.AddDate(5, 0, 0)), certPEM(t, refTime.Add(96*time.Hour))...)
	cfg := model.Config{
		Kind: model.KindValidating, Name: "bundle", Source: "unit",
		Webhooks: []model.Webhook{{
			Name: "validate.bundle.example.com", FailurePolicy: "Ignore", CABundle: bundle,
		}},
	}
	got := audit.Run([]model.Config{cfg}, opts(), nil)
	if len(got) != 1 || got[0].Rule != audit.RuleCertExpiring {
		t.Fatalf("findings = %v", ruleSet(got))
	}
	if !strings.Contains(got[0].Message, "in 4 days") {
		t.Fatalf("message = %q, want the 4-day expiry", got[0].Message)
	}
}

func TestLiveClusterResolvesSelectorsAndBackends(t *testing.T) {
	cfgs := loadFixture(t, "label-selector.yaml")
	info := &audit.ClusterInfo{
		Live: true,
		NamespaceLabels: map[string]map[string]string{
			// kube-system is not labelled webhook-policy=enforced, so the
			// selector genuinely excludes it and the deadlock is not real.
			"kube-system": {"kubernetes.io/metadata.name": "kube-system"},
			"gate-system": {"kubernetes.io/metadata.name": "gate-system"},
			"team-a":      {"kubernetes.io/metadata.name": "team-a", "webhook-policy": "enforced"},
		},
		Services: map[string]audit.ServiceInfo{
			"gate-system/gate": {Exists: true, ReadyEndpoints: 2},
		},
	}
	if got := audit.Run(cfgs, opts(), info); len(got) != 0 {
		t.Fatalf("expected the live selector to clear the finding, got %v", ruleSet(got))
	}

	info.Services["gate-system/gate"] = audit.ServiceInfo{Exists: false}
	got := audit.Run(cfgs, opts(), info)
	if len(got) != 1 || got[0].Rule != audit.RuleBackendMissing || got[0].Severity != audit.SeverityHigh {
		t.Fatalf("findings = %v", ruleSet(got))
	}

	info.Services["gate-system/gate"] = audit.ServiceInfo{Exists: true, ReadyEndpoints: 0}
	got = audit.Run(cfgs, opts(), info)
	if len(got) != 1 || got[0].Rule != audit.RuleBackendMissing {
		t.Fatalf("findings = %v", ruleSet(got))
	}
	if !strings.Contains(got[0].Message, "no ready endpoints") {
		t.Errorf("message = %q", got[0].Message)
	}
}

// Manifest mode cannot resolve a label-keyed selector, and must say so instead
// of claiming a deadlock or claiming safety.
func TestInconclusiveSelectorIsMedium(t *testing.T) {
	got := audit.Run(loadFixture(t, "label-selector.yaml"), opts(), nil)
	if len(got) != 1 || got[0].Severity != audit.SeverityMedium {
		t.Fatalf("findings = %v", ruleSet(got))
	}
	if !strings.Contains(got[0].Message, "cannot be resolved") {
		t.Errorf("message = %q", got[0].Message)
	}
}

func TestNamespaceSelectorInOperatorExcludes(t *testing.T) {
	sel := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key:      "kubernetes.io/metadata.name",
		Operator: metav1.LabelSelectorOpIn,
		Values:   []string{"team-a", "team-b"},
	}}}
	cfg := model.Config{
		Kind: model.KindValidating, Name: "scoped", Source: "unit",
		Webhooks: []model.Webhook{{
			Name: "validate.scoped.example.com", FailurePolicy: "Fail",
			CABundle:          certPEM(t, refTime.AddDate(3, 0, 0)),
			NamespaceSelector: sel,
			Service:           &model.ServiceRef{Namespace: "team-a", Name: "scoped"},
			Rules: []model.Rule{{
				APIGroups: []string{""}, APIVersions: []string{"v1"},
				Resources: []string{"pods"}, Operations: []string{"CREATE"},
				Scope: "Namespaced",
			}},
		}},
	}
	// kube-system is excluded by the In list, but the webhook's own namespace
	// team-a is inside it: that is still a deadlock.
	got := audit.Run([]model.Config{cfg}, opts(), nil)
	if len(got) != 1 || got[0].Rule != audit.RuleFailClosedNoExclusion || got[0].Severity != audit.SeverityHigh {
		t.Fatalf("findings = %v", ruleSet(got))
	}
	if !strings.Contains(got[0].Message, "team-a") {
		t.Errorf("message should name the backend namespace: %s", got[0].Message)
	}
}

func TestClusterScopedRuleIsNotADeadlock(t *testing.T) {
	cfg := model.Config{
		Kind: model.KindValidating, Name: "cluster-scoped", Source: "unit",
		Webhooks: []model.Webhook{{
			Name: "validate.ns.example.com", FailurePolicy: "Fail",
			CABundle: certPEM(t, refTime.AddDate(3, 0, 0)),
			Service:  &model.ServiceRef{Namespace: "ops", Name: "ns-guard"},
			Rules: []model.Rule{{
				APIGroups: []string{""}, APIVersions: []string{"v1"},
				Resources: []string{"namespaces"}, Operations: []string{"CREATE"},
				Scope: "Cluster",
			}},
		}},
	}
	if got := audit.Run([]model.Config{cfg}, opts(), nil); len(got) != 0 {
		t.Fatalf("expected no findings, got %v", ruleSet(got))
	}
}

func TestTimeoutThresholdAndDefault(t *testing.T) {
	mk := func(timeout int32) []model.Config {
		return []model.Config{{
			Kind: model.KindValidating, Name: "timeouts", Source: "unit",
			Webhooks: []model.Webhook{{
				Name: "validate.timeouts.example.com", FailurePolicy: "Fail",
				TimeoutSeconds: timeout,
				CABundle:       certPEM(t, refTime.AddDate(3, 0, 0)),
				Rules: []model.Rule{{
					APIGroups: []string{"example.com"}, APIVersions: []string{"v1"},
					Resources: []string{"widgets"}, Operations: []string{"CREATE"},
					Scope: "Namespaced",
				}},
			}},
		}}
	}
	// An unset timeout defaults to 10s, which is exactly the threshold.
	if got := audit.Run(mk(0), opts(), nil); len(got) != 0 {
		t.Fatalf("unset timeout should not be flagged, got %v", ruleSet(got))
	}
	if got := audit.Run(mk(10), opts(), nil); len(got) != 0 {
		t.Fatalf("timeout at the threshold should not be flagged, got %v", ruleSet(got))
	}
	got := audit.Run(mk(11), opts(), nil)
	if len(got) != 1 || got[0].Rule != audit.RuleTimeoutTooLong {
		t.Fatalf("findings = %v", ruleSet(got))
	}
}

func TestGateAndSummary(t *testing.T) {
	findings := audit.Run(loadFixture(t, "deadlock.yaml"), opts(), nil)
	s := audit.Summarize(findings)
	if s.Total != 3 || s.High != 2 || s.Medium != 1 {
		t.Fatalf("summary = %+v", s)
	}
	if !audit.Gate(findings, audit.SeverityHigh) {
		t.Error("high findings must trip a high gate")
	}
	if audit.Gate(findings, audit.SeverityNone) {
		t.Error("severity none must never gate")
	}

	mediumOnly := audit.Run(loadFixture(t, "no-ca.yaml"), opts(), nil)
	if audit.Gate(mediumOnly, audit.SeverityHigh) {
		t.Error("a medium finding must not trip a high gate")
	}
	if !audit.Gate(mediumOnly, audit.SeverityMedium) {
		t.Error("a medium finding must trip a medium gate")
	}
}

func TestFindingsSortedBySeverity(t *testing.T) {
	cfgs := loadFixture(t, "deadlock.yaml")
	cfgs = append(cfgs, loadFixture(t, "no-ca.yaml")...)
	findings := audit.Run(cfgs, opts(), nil)
	for i := 1; i < len(findings); i++ {
		if findings[i-1].Severity < findings[i].Severity {
			t.Fatalf("findings not sorted most severe first: %v", ruleSet(findings))
		}
	}
}

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]audit.Severity{
		"high": audit.SeverityHigh, "HIGH": audit.SeverityHigh,
		"medium": audit.SeverityMedium, "med": audit.SeverityMedium,
		"low": audit.SeverityLow, "none": audit.SeverityNone, "off": audit.SeverityNone,
	} {
		got, err := audit.ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := audit.ParseSeverity("critical"); err == nil {
		t.Error("expected an error for an unknown severity")
	}
}

// certPEM mints a throwaway self-signed certificate with the requested expiry
// so cert tests never depend on wall-clock time or a committed fixture.
func certPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-webhook-ca"},
		NotBefore:             notAfter.AddDate(-1, 0, 0),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func systemWebhook(t *testing.T, policy string, sel *metav1.LabelSelector, rules ...model.Rule) []model.Config {
	t.Helper()
	return []model.Config{{
		Kind: model.KindValidating, Name: "system", Source: "unit",
		Webhooks: []model.Webhook{{
			Name: "validate.system.example.com", FailurePolicy: policy,
			CABundle:          certPEM(t, refTime.AddDate(3, 0, 0)),
			NamespaceSelector: sel,
			Service:           &model.ServiceRef{Namespace: "ops", Name: "system"},
			Rules:             rules,
		}},
	}}
}

func onlySystemFinding(t *testing.T, got []audit.Finding) audit.Finding {
	t.Helper()
	if len(got) != 1 || got[0].Rule != audit.RuleSystemResources {
		t.Fatalf("findings = %v", ruleSet(got))
	}
	return got[0]
}

// Excluding kube-system does not take a webhook out of the node heartbeat
// path: node status is cluster-scoped and node leases live in kube-node-lease.
func TestSystemResourcesSurviveKubeSystemExclusion(t *testing.T) {
	f := onlySystemFinding(t, audit.Run(loadFixture(t, "system-resources.yaml"), opts(), nil))
	if f.Severity != audit.SeverityHigh {
		t.Fatalf("severity = %s, want high", f.Severity)
	}
	for _, want := range []string{"leases.coordination.k8s.io", "nodes/status", "lease-guard/lease-guard"} {
		if !strings.Contains(f.Message, want) {
			t.Errorf("message does not mention %q: %s", want, f.Message)
		}
	}
	if !strings.Contains(f.Remediation, "matchCondition") {
		t.Errorf("remediation should point at matchConditions: %s", f.Remediation)
	}
}

func TestSystemResourcesFailOpenIsMedium(t *testing.T) {
	cfgs := systemWebhook(t, "Ignore", nil, model.Rule{
		APIGroups: []string{""}, Resources: []string{"nodes"},
		Operations: []string{"UPDATE"}, Scope: "Cluster",
	})
	f := onlySystemFinding(t, audit.Run(cfgs, opts(), nil))
	if f.Severity != audit.SeverityMedium {
		t.Fatalf("severity = %s, want medium", f.Severity)
	}
	if !strings.Contains(f.Message, "10s") {
		t.Errorf("message should name the effective timeout: %s", f.Message)
	}
}

// Leases only matter in kube-system (leader election) and kube-node-lease
// (node heartbeats). A selector that excludes both clears them.
func TestLeasesClearedWhenLeaseNamespacesExcluded(t *testing.T) {
	sel := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key:      "kubernetes.io/metadata.name",
		Operator: metav1.LabelSelectorOpNotIn,
		Values:   []string{"kube-system", "kube-node-lease", "ops"},
	}}}
	lease := model.Rule{
		APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"},
		Operations: []string{"UPDATE"}, Scope: "Namespaced",
	}
	if got := audit.Run(systemWebhook(t, "Fail", sel, lease), opts(), nil); len(got) != 0 {
		t.Fatalf("expected no findings, got %v", ruleSet(got))
	}

	// pods/status is written by every kubelet in every namespace, so the same
	// selector does not clear it.
	status := model.Rule{
		APIGroups: []string{""}, Resources: []string{"pods/status"},
		Operations: []string{"UPDATE"}, Scope: "Namespaced",
	}
	f := onlySystemFinding(t, audit.Run(systemWebhook(t, "Fail", sel, status), opts(), nil))
	if !strings.Contains(f.Message, "pods/status") || strings.Contains(f.Message, "leases") {
		t.Errorf("message = %s", f.Message)
	}
}

// Resource patterns follow admissionregistration/v1: "*" is every resource
// but no subresource, "x/*" every subresource of x, "*/status" the status of
// everything, "*/*" all of it.
func TestSystemResourcePatternMatching(t *testing.T) {
	cases := []struct {
		group, resource, scope string
		want                   []string
	}{
		{"", "pods", "*", nil},
		{"", "pods/*", "*", []string{"pods/status"}},
		{"", "*/status", "*", []string{"nodes/status", "pods/status"}},
		{"", "*", "*", []string{"nodes"}},
		{"", "nodes", "Namespaced", nil},
		{"*", "*/*", "*", []string{
			"leases.coordination.k8s.io", "nodes", "nodes/status", "pods/status",
			"subjectaccessreviews.authorization.k8s.io", "tokenreviews.authentication.k8s.io",
		}},
		{"admissionregistration.k8s.io", "*", "*", nil},
		{"authentication.k8s.io", "tokenreviews", "", []string{"tokenreviews.authentication.k8s.io"}},
	}
	for _, tc := range cases {
		t.Run(tc.group+"/"+tc.resource+"@"+tc.scope, func(t *testing.T) {
			cfgs := systemWebhook(t, "Fail", nil, model.Rule{
				APIGroups: []string{tc.group}, Resources: []string{tc.resource},
				Operations: []string{"CREATE", "UPDATE"}, Scope: tc.scope,
			})
			var got []audit.Finding
			for _, f := range audit.Run(cfgs, opts(), nil) {
				if f.Rule == audit.RuleSystemResources {
					got = append(got, f)
				}
			}
			if len(tc.want) == 0 {
				if len(got) != 0 {
					t.Fatalf("expected no system finding, got %s", got[0].Message)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected one system finding, got %d", len(got))
			}
			for _, w := range tc.want {
				if !strings.Contains(got[0].Message, w) {
					t.Errorf("message does not mention %q: %s", w, got[0].Message)
				}
			}
		})
	}
}

func TestSystemResourcesDeleteOnlyIsIgnored(t *testing.T) {
	cfgs := systemWebhook(t, "Fail", nil, model.Rule{
		APIGroups: []string{""}, Resources: []string{"nodes"},
		Operations: []string{"DELETE"}, Scope: "Cluster",
	})
	if got := audit.Run(cfgs, opts(), nil); len(got) != 0 {
		t.Fatalf("expected no findings, got %v", ruleSet(got))
	}
}

func TestMatchConditionsMakeSystemFindingUnverified(t *testing.T) {
	cfgs := loadFixture(t, "system-match-conditions.yaml")
	if got := cfgs[0].Webhooks[0].MatchConditions; len(got) != 1 || got[0] != "exclude-leases" {
		t.Fatalf("match conditions = %v", got)
	}
	f := onlySystemFinding(t, audit.Run(cfgs, opts(), nil))
	if f.Severity != audit.SeverityMedium || !strings.Contains(f.Message, "unverified") || !strings.Contains(f.Message, "exclude-leases") {
		t.Fatalf("finding = %s/%s", f.Severity, f.Message)
	}
}

func TestSystemResourcesOffWhenListEmpty(t *testing.T) {
	o := opts()
	o.SystemResources = nil
	got := ruleSet(audit.Run(loadFixture(t, "system-resources.yaml"), o, nil))
	if len(got) != 0 {
		t.Fatalf("findings = %v", got)
	}
}

func TestParseSystemResources(t *testing.T) {
	got, err := audit.ParseSystemResources([]string{"leases.coordination.k8s.io", " nodes/status ", "deployments/status.apps", "nodes/status", ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("parsed %d entries, want 3 (duplicates and blanks dropped): %+v", len(got), got)
	}
	// A built-in entry keeps its scope and namespaces.
	if got[0].Scope != "Namespaced" || len(got[0].Namespaces) != 2 {
		t.Errorf("leases lost built-in metadata: %+v", got[0])
	}
	want := audit.SystemResource{Group: "apps", Resource: "deployments", Subresource: "status"}
	if got[2].Group != want.Group || got[2].Resource != want.Resource || got[2].Subresource != want.Subresource || got[2].Scope != "" {
		t.Errorf("custom entry = %+v, want %+v", got[2], want)
	}
	if got[2].String() != "deployments/status.apps" {
		t.Errorf("String() = %q", got[2].String())
	}
	for _, bad := range []string{"*", "nodes/", "/status", "pods/*", "a/b/c"} {
		if _, err := audit.ParseSystemResources([]string{bad}); err == nil {
			t.Errorf("expected an error for %q", bad)
		}
	}
	defaults, err := audit.ParseSystemResources(audit.DefaultSystemResourceNames())
	if err != nil || len(defaults) != len(audit.DefaultSystemResources()) {
		t.Fatalf("defaults do not round-trip: %v, %v", defaults, err)
	}
}
