package load_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/moveeeax/k8s-webhook-failure-audit/internal/load"
	"github.com/moveeeax/k8s-webhook-failure-audit/internal/model"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const validating = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: vwc-one
webhooks:
  - name: a.example.com
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Fail
    timeoutSeconds: 7
    clientConfig:
      service:
        name: svc
        namespace: ns
        port: 443
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
        scope: Namespaced
`

const mutating = `apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: mwc-one
webhooks:
  - name: b.example.com
    admissionReviewVersions: ["v1"]
    sideEffects: None
    clientConfig:
      url: https://example.com/mutate
    rules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["UPDATE"]
        resources: ["deployments"]
`

func TestManifestsWalksDirectoryAndSortsFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "b-mutating.yaml", mutating)
	write(t, dir, "a-validating.yml", validating)
	write(t, dir, "nested/also-validating.yaml", validating)
	write(t, dir, "notes.txt", "ignored")
	write(t, dir, ".hidden/skipped.yaml", validating)

	cfgs, err := load.Manifests([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 3 {
		t.Fatalf("parsed %d configurations, want 3", len(cfgs))
	}
	// Files are walked in sorted order, so a-validating.yml comes first.
	if cfgs[0].Name != "vwc-one" || cfgs[0].Kind != model.KindValidating {
		t.Fatalf("first config = %s/%s", cfgs[0].Kind, cfgs[0].Name)
	}
	if cfgs[1].Name != "mwc-one" || cfgs[1].Kind != model.KindMutating {
		t.Fatalf("second config = %s/%s", cfgs[1].Kind, cfgs[1].Name)
	}
	if cfgs[0].Source != filepath.Join(dir, "a-validating.yml") {
		t.Fatalf("source = %q", cfgs[0].Source)
	}
}

func TestManifestsReadsFieldsAndDefaults(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, "both.yaml", validating+"---\n"+mutating)
	cfgs, err := load.Manifests([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 2 {
		t.Fatalf("parsed %d configurations, want 2", len(cfgs))
	}

	v := cfgs[0].Webhooks[0]
	if v.FailurePolicy != "Fail" || v.EffectiveTimeout() != 7 {
		t.Errorf("validating webhook = %+v", v)
	}
	if v.Service == nil || v.Service.String() != "ns/svc" {
		t.Errorf("service = %v", v.Service)
	}
	if len(v.Rules) != 1 || v.Rules[0].Resources[0] != "pods" || v.Rules[0].Operations[0] != "CREATE" {
		t.Errorf("rules = %+v", v.Rules)
	}

	m := cfgs[1].Webhooks[0]
	// An omitted failurePolicy must surface as fail-closed with the API
	// server's 10s default timeout.
	if !m.FailClosed() || m.EffectiveFailurePolicy() != "Fail" || m.EffectiveTimeout() != 10 {
		t.Errorf("mutating webhook defaults wrong: %+v", m)
	}
	if m.URL != "https://example.com/mutate" || m.Service != nil {
		t.Errorf("url backend = %q, service = %v", m.URL, m.Service)
	}
}

func TestManifestsIgnoresUnrelatedKinds(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "mixed.yaml", "apiVersion: v1\nkind: Service\nmetadata:\n  name: svc\n---\n"+validating)
	cfgs, err := load.Manifests([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 1 {
		t.Fatalf("parsed %d configurations, want 1", len(cfgs))
	}
}

func TestManifestsRejectsBrokenYAML(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "broken.yaml", "kind: ValidatingWebhookConfiguration\nwebhooks: [oops\n")
	if _, err := load.Manifests([]string{dir}); err == nil {
		t.Fatal("expected an error for unparseable YAML")
	}
}

func TestManifestsReportsMissingPath(t *testing.T) {
	if _, err := load.Manifests([]string{filepath.Join(t.TempDir(), "nope")}); err == nil {
		t.Fatal("expected an error for a missing path")
	}
}

func TestManifestsAcceptsMultiplePaths(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	write(t, a, "v.yaml", validating)
	write(t, b, "m.yaml", mutating)
	cfgs, err := load.Manifests([]string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 2 {
		t.Fatalf("parsed %d configurations, want 2", len(cfgs))
	}
}

// A "---" inside a block scalar is content, not a document separator.
func TestSeparatorInsideBlockScalarDoesNotSplit(t *testing.T) {
	dir := t.TempDir()
	body := `apiVersion: v1
kind: ConfigMap
metadata:
  name: cm
data:
  body: |
    first
    ---
    second
---
` + validating
	write(t, dir, "scalar.yaml", body)
	cfgs, err := load.Manifests([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 1 || cfgs[0].Name != "vwc-one" {
		t.Fatalf("configs = %+v", cfgs)
	}
}

func TestAnnotationsArePreserved(t *testing.T) {
	dir := t.TempDir()
	body := `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: annotated
  annotations:
    cert-manager.io/inject-ca-from: ns/ca
webhooks: []
`
	write(t, dir, "ann.yaml", body)
	cfgs, err := load.Manifests([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if cfgs[0].Annotations["cert-manager.io/inject-ca-from"] != "ns/ca" {
		t.Fatalf("annotations = %v", cfgs[0].Annotations)
	}
}
