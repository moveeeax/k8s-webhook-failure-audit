// Package cli wires flags to the loaders, the auditor and the writers. It
// returns an exit code instead of calling os.Exit so the whole command is
// testable.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/moveeeax/k8s-webhook-failure-audit/internal/audit"
	"github.com/moveeeax/k8s-webhook-failure-audit/internal/load"
	"github.com/moveeeax/k8s-webhook-failure-audit/internal/model"
	"github.com/moveeeax/k8s-webhook-failure-audit/internal/report"
)

// Version is overridden at build time with -ldflags "-X ...Version=v0.1.0".
var Version = "dev"

// Exit codes. 1 is reserved for "findings at or above the gate" so CI can tell
// a policy failure apart from a broken run.
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitError    = 2
)

const usage = `k8s-webhook-failure-audit — find admission webhooks that can wedge the cluster

Usage:
  k8s-webhook-failure-audit --manifests DIR[,DIR...] [flags]
  k8s-webhook-failure-audit [--context NAME] [--kubeconfig PATH] [flags]

With --manifests the tool reads YAML off disk and needs no cluster access.
Without it, it reads the live cluster and additionally resolves namespace
labels and backend Service health.

Flags:
`

type options struct {
	manifests  string
	kubeconfig string
	context    string
	failOn     string
	certDays   int
	maxTimeout int
	protected  string
	asJSON     bool
	asSARIF    bool
	version    bool
}

// Run executes the command. loaders are injected in tests via Deps.
func Run(args []string, stdout, stderr io.Writer) int {
	return RunWithDeps(args, stdout, stderr, Deps{
		Manifests: load.Manifests,
		Cluster:   load.Cluster,
		Now:       time.Now,
	})
}

// Deps are the seams tests replace: the two loaders and the clock.
type Deps struct {
	Manifests func(paths []string) ([]model.Config, error)
	Cluster   func(ctx context.Context, kubeconfig, kubeContext string) ([]model.Config, *audit.ClusterInfo, error)
	Now       func() time.Time
}

// RunWithDeps is Run with injectable dependencies.
func RunWithDeps(args []string, stdout, stderr io.Writer, deps Deps) int {
	var o options
	fs := flag.NewFlagSet("k8s-webhook-failure-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}
	fs.StringVar(&o.manifests, "manifests", "", "comma-separated files or directories of YAML manifests to audit instead of a cluster")
	fs.StringVar(&o.kubeconfig, "kubeconfig", "", "path to a kubeconfig (default: the usual discovery rules)")
	fs.StringVar(&o.context, "context", "", "kubeconfig context to use")
	fs.StringVar(&o.failOn, "fail-on", "high", "exit 1 when a finding is at or above this severity: high, medium, low, none")
	fs.IntVar(&o.certDays, "cert-expiry-days", 30, "report caBundle certificates expiring within this many days")
	fs.IntVar(&o.maxTimeout, "max-timeout", 10, "report fail-closed webhooks with timeoutSeconds above this")
	fs.StringVar(&o.protected, "protected-namespaces", "kube-system", "comma-separated namespaces whose writes must keep working to recover a webhook")
	fs.BoolVar(&o.asJSON, "json", false, "emit JSON")
	fs.BoolVar(&o.asSARIF, "sarif", false, "emit SARIF 2.1.0 for code scanning")
	fs.BoolVar(&o.version, "version", false, "print the version and exit")

	if err := fs.Parse(args); err != nil {
		return ExitError
	}
	if o.version {
		fmt.Fprintln(stdout, Version)
		return ExitOK
	}
	if o.asJSON && o.asSARIF {
		fmt.Fprintln(stderr, "error: --json and --sarif are mutually exclusive")
		return ExitError
	}
	threshold, err := audit.ParseSeverity(o.failOn)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return ExitError
	}

	opts := audit.Options{
		ProtectedNamespaces: splitList(o.protected),
		CertExpiryDays:      o.certDays,
		MaxTimeoutSeconds:   int32(o.maxTimeout),
		Now:                 deps.Now(),
	}

	var (
		configs []model.Config
		info    *audit.ClusterInfo
		target  string
	)
	if o.manifests != "" {
		paths := splitList(o.manifests)
		configs, err = deps.Manifests(paths)
		target = strings.Join(paths, ",")
	} else {
		configs, info, err = deps.Cluster(context.Background(), o.kubeconfig, o.context)
		target = "cluster"
		if o.context != "" {
			target = "cluster " + o.context
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return ExitError
	}
	if len(configs) == 0 {
		fmt.Fprintf(stderr, "warning: no admission webhook configurations found in %s\n", target)
	}

	findings := audit.Run(configs, opts, info)

	mode := report.ModeTable
	switch {
	case o.asJSON:
		mode = report.ModeJSON
	case o.asSARIF:
		mode = report.ModeSARIF
	}
	meta := report.Meta{
		Version:     Version,
		GeneratedAt: opts.Now.UTC(),
		Target:      target,
		Configs:     len(configs),
		Webhooks:    countWebhooks(configs),
	}
	if err := report.Write(stdout, mode, findings, meta); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return ExitError
	}
	if audit.Gate(findings, threshold) {
		return ExitFindings
	}
	return ExitOK
}

func countWebhooks(configs []model.Config) int {
	n := 0
	for _, c := range configs {
		n += len(c.Webhooks)
	}
	return n
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
