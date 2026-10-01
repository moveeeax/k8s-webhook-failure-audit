// Package audit holds the rules. A rule looks at one normalized webhook and
// decides whether that webhook can take the cluster down.
package audit

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/moveeeax/k8s-webhook-failure-audit/internal/model"
)

// Rule IDs. These are stable: they end up in SARIF and in people's CI gates.
const (
	RuleFailClosedNoExclusion = "FAIL_CLOSED_NO_EXCLUSION"
	RuleBackendMissing        = "BACKEND_MISSING"
	RuleNoCABundle            = "NO_CA_BUNDLE"
	RuleCABundleInvalid       = "CA_BUNDLE_INVALID"
	RuleCertExpiring          = "CERT_EXPIRING"
	RuleCertExpired           = "CERT_EXPIRED"
	RuleBroadRules            = "BROAD_RULES"
	RuleTimeoutTooLong        = "TIMEOUT_TOO_LONG"
)

// Descriptions feed the SARIF tool driver so code scanning shows something
// useful next to each alert.
var Descriptions = map[string]string{
	RuleFailClosedNoExclusion: "A fail-closed webhook intercepts writes to pods or workloads in a namespace it depends on, so the backend cannot be restarted once it is down.",
	RuleBackendMissing:        "The webhook backend Service does not exist or has no ready endpoints.",
	RuleNoCABundle:            "clientConfig has no caBundle and no CA injection annotation, so every admission call fails TLS verification.",
	RuleCABundleInvalid:       "clientConfig.caBundle does not contain a parseable X.509 certificate.",
	RuleCertExpiring:          "The serving CA certificate in caBundle expires soon.",
	RuleCertExpired:           "The serving CA certificate in caBundle has already expired.",
	RuleBroadRules:            "A fail-closed webhook matches all API groups, resources and operations.",
	RuleTimeoutTooLong:        "A fail-closed webhook has a timeout high enough to turn a slow backend into API server latency.",
}

// Finding is one problem found on one webhook.
type Finding struct {
	Rule        string   `json:"rule"`
	Severity    Severity `json:"severity"`
	Kind        string   `json:"kind"`
	Config      string   `json:"config"`
	Webhook     string   `json:"webhook"`
	Message     string   `json:"message"`
	Remediation string   `json:"remediation,omitempty"`
	Source      string   `json:"source"`
}

// Options tunes the thresholds.
type Options struct {
	// ProtectedNamespaces are the namespaces whose writes must keep working for
	// an operator to recover a dead webhook backend.
	ProtectedNamespaces []string
	CertExpiryDays      int
	MaxTimeoutSeconds   int32
	// Now is injected so tests are not time bombs.
	Now time.Time
}

// DefaultOptions returns the thresholds the CLI uses unless flags override them.
func DefaultOptions() Options {
	return Options{
		ProtectedNamespaces: []string{"kube-system"},
		CertExpiryDays:      30,
		MaxTimeoutSeconds:   10,
		Now:                 time.Now(),
	}
}

// ServiceInfo is what we know about a webhook's backend Service.
type ServiceInfo struct {
	Exists           bool
	ReadyEndpoints   int
	EndpointsUnknown bool
}

// ClusterInfo carries live-cluster facts. It is nil in manifest mode, and the
// rules degrade accordingly instead of guessing.
type ClusterInfo struct {
	Live            bool
	NamespaceLabels map[string]map[string]string
	Services        map[string]ServiceInfo
}

// recoveryResources maps each resource an operator must be able to write in
// order to bring a dead webhook backend back onto the API group that owns it.
// If a fail-closed webhook does not intercept any of them, a backend outage is
// painful but not a deadlock — which is why ingress-nginx (ingresses only) and
// cert-manager (resources "*/*" but only inside its own API groups) do not
// trip the deadlock rule.
var recoveryResources = map[string]string{
	"pods":            "",
	"configmaps":      "",
	"secrets":         "",
	"services":        "",
	"endpoints":       "",
	"serviceaccounts": "",
	"deployments":     "apps",
	"replicasets":     "apps",
	"statefulsets":    "apps",
	"daemonsets":      "apps",
	"jobs":            "batch",
	"endpointslices":  "discovery.k8s.io",
}

// Run applies every rule to every webhook and returns the findings, sorted
// most severe first.
func Run(configs []model.Config, opts Options, info *ClusterInfo) []Finding {
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	if opts.CertExpiryDays == 0 {
		opts.CertExpiryDays = 30
	}
	if opts.MaxTimeoutSeconds == 0 {
		opts.MaxTimeoutSeconds = 10
	}
	var out []Finding
	for _, c := range configs {
		for _, w := range c.Webhooks {
			out = append(out, auditWebhook(c, w, opts, info)...)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		if out[i].Config != out[j].Config {
			return out[i].Config < out[j].Config
		}
		if out[i].Webhook != out[j].Webhook {
			return out[i].Webhook < out[j].Webhook
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}

func auditWebhook(c model.Config, w model.Webhook, opts Options, info *ClusterInfo) []Finding {
	var out []Finding
	add := func(rule string, sev Severity, msg, fix string) {
		out = append(out, Finding{
			Rule: rule, Severity: sev,
			Kind: string(c.Kind), Config: c.Name, Webhook: w.Name,
			Message: msg, Remediation: fix, Source: c.Source,
		})
	}

	if f, ok := checkDeadlock(c, w, opts, info); ok {
		add(RuleFailClosedNoExclusion, f.severity, f.message, f.remediation)
	}
	if f, ok := checkBackend(w, info); ok {
		add(RuleBackendMissing, f.severity, f.message, f.remediation)
	}
	for _, f := range checkCABundle(c, w, opts) {
		add(f.rule, f.severity, f.message, f.remediation)
	}
	if f, ok := checkBroadRules(w); ok {
		add(RuleBroadRules, f.severity, f.message, f.remediation)
	}
	if f, ok := checkTimeout(w, opts); ok {
		add(RuleTimeoutTooLong, f.severity, f.message, f.remediation)
	}
	return out
}

type result struct {
	rule        string
	severity    Severity
	message     string
	remediation string
}

// checkDeadlock is the rule that matters. A fail-closed webhook that
// intercepts creates of the workloads living in a namespace it needs — its own
// backend namespace, or kube-system — cannot be recovered without deleting the
// configuration by hand.
func checkDeadlock(c model.Config, w model.Webhook, opts Options, info *ClusterInfo) (result, bool) {
	if !w.FailClosed() {
		return result{}, false
	}
	matched := matchedRecoveryResources(w.Rules)
	if len(matched) == 0 {
		return result{}, false
	}

	protected := append([]string{}, opts.ProtectedNamespaces...)
	if w.Service != nil && w.Service.Namespace != "" {
		protected = append(protected, w.Service.Namespace)
	}
	protected = dedupe(protected)

	var inconclusive []string
	for _, ns := range protected {
		switch namespaceExclusion(w.NamespaceSelector, ns, info) {
		case exclusionExcluded:
			continue
		case exclusionUnknown:
			inconclusive = append(inconclusive, ns)
		case exclusionIncluded:
			return result{
				severity: SeverityHigh,
				message: fmt.Sprintf("failurePolicy=%s intercepts %s in %s with no namespaceSelector exclusion: if the backend %s is down, nothing can restart it",
					w.EffectiveFailurePolicy(), summarizeResources(matched), ns, backendLabel(w)),
				remediation: fmt.Sprintf("add a namespaceSelector excluding %s (matchExpressions: key kubernetes.io/metadata.name, operator NotIn, values [%s]) or set failurePolicy: Ignore", ns, ns),
			}, true
		}
	}
	if len(inconclusive) > 0 {
		return result{
			severity: SeverityMedium,
			message: fmt.Sprintf("failurePolicy=%s intercepts %s and the namespaceSelector cannot be resolved without a cluster, so the %s carve-out is unverified",
				w.EffectiveFailurePolicy(), summarizeResources(matched), strings.Join(inconclusive, ",")),
			remediation: "re-run against the cluster, or key the namespaceSelector on kubernetes.io/metadata.name so it can be checked from manifests",
		}, true
	}
	return result{}, false
}

func backendLabel(w model.Webhook) string {
	if w.Service != nil {
		return "Service " + w.Service.String()
	}
	if w.URL != "" {
		return "URL " + w.URL
	}
	return "backend"
}

func matchedRecoveryResources(rules []model.Rule) []string {
	seen := map[string]bool{}
	var out []string
	add := func(res string) {
		if !seen[res] {
			seen[res] = true
			out = append(out, res)
		}
	}
	for _, r := range rules {
		// Cluster-scoped rules never touch namespaced workloads, and a
		// namespaceSelector does not apply to them either.
		if r.Scope == "Cluster" {
			continue
		}
		if !writesIntercepted(r.Operations) {
			continue
		}
		for _, res := range r.Resources {
			base := strings.SplitN(res, "/", 2)[0]
			if base == "*" {
				// A resource wildcard only reaches the workloads that matter if
				// the rule's apiGroups cover the groups those workloads live in.
				for name, group := range recoveryResources {
					if groupMatches(r.APIGroups, group) {
						add(name)
					}
				}
				continue
			}
			if group, ok := recoveryResources[base]; ok && groupMatches(r.APIGroups, group) {
				add(base)
			}
		}
	}
	sort.Strings(out)
	return out
}

func groupMatches(ruleGroups []string, group string) bool {
	return contains(ruleGroups, "*") || contains(ruleGroups, group)
}

// summarizeResources keeps the finding message readable when a wildcard rule
// matched the whole recovery set.
func summarizeResources(res []string) string {
	if len(res) <= 4 {
		return strings.Join(res, ",")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(res[:4], ","), len(res)-4)
}

// writesIntercepted reports whether the rule covers the operations needed to
// create replacement pods. A DELETE-only webhook cannot deadlock a restart.
func writesIntercepted(ops []string) bool {
	for _, op := range ops {
		switch strings.ToUpper(op) {
		case "*", "CREATE", "UPDATE":
			return true
		}
	}
	return false
}

type exclusion int

const (
	exclusionIncluded exclusion = iota
	exclusionExcluded
	exclusionUnknown
)

// namespaceExclusion decides whether sel keeps the webhook away from ns. With
// live namespace labels it is an exact answer; from manifests alone only
// selectors keyed on kubernetes.io/metadata.name can be resolved, and anything
// else is reported as unknown rather than assumed safe or unsafe.
func namespaceExclusion(sel *metav1.LabelSelector, ns string, info *ClusterInfo) exclusion {
	if sel == nil || (len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0) {
		return exclusionIncluded
	}
	if info != nil && info.Live {
		if nsLabels, ok := info.NamespaceLabels[ns]; ok {
			s, err := metav1.LabelSelectorAsSelector(sel)
			if err != nil {
				return exclusionUnknown
			}
			if s.Matches(labels.Set(nsLabels)) {
				return exclusionIncluded
			}
			return exclusionExcluded
		}
		// The namespace does not exist in this cluster, so nothing in it can be
		// intercepted.
		return exclusionExcluded
	}

	const nameKey = "kubernetes.io/metadata.name"
	resolvable := false
	for k, v := range sel.MatchLabels {
		if k != nameKey {
			continue
		}
		resolvable = true
		if v != ns {
			return exclusionExcluded
		}
	}
	for _, e := range sel.MatchExpressions {
		if e.Key != nameKey {
			continue
		}
		switch e.Operator {
		case metav1.LabelSelectorOpNotIn:
			resolvable = true
			if contains(e.Values, ns) {
				return exclusionExcluded
			}
		case metav1.LabelSelectorOpIn:
			resolvable = true
			if !contains(e.Values, ns) {
				return exclusionExcluded
			}
		case metav1.LabelSelectorOpDoesNotExist:
			// Every namespace carries the name label, so this excludes nothing.
			resolvable = true
		case metav1.LabelSelectorOpExists:
			resolvable = true
		}
	}
	if resolvable && len(sel.MatchExpressions) <= 1 && len(sel.MatchLabels) <= 1 {
		// The selector was entirely about the namespace name and it still
		// matches ns.
		return exclusionIncluded
	}
	return exclusionUnknown
}

func checkBackend(w model.Webhook, info *ClusterInfo) (result, bool) {
	if info == nil || !info.Live || w.Service == nil {
		return result{}, false
	}
	sev := SeverityMedium
	if w.FailClosed() {
		sev = SeverityHigh
	}
	si, ok := info.Services[w.Service.String()]
	if !ok {
		return result{}, false
	}
	if !si.Exists {
		return result{
			severity:    sev,
			message:     fmt.Sprintf("clientConfig points at Service %s which does not exist", w.Service),
			remediation: "fix clientConfig.service, or delete the webhook configuration if the controller is gone",
		}, true
	}
	if !si.EndpointsUnknown && si.ReadyEndpoints == 0 {
		return result{
			severity:    sev,
			message:     fmt.Sprintf("Service %s has no ready endpoints, so every admission call to this webhook is already failing", w.Service),
			remediation: "check the backend Deployment's pods and its readiness probe",
		}, true
	}
	return result{}, false
}

var caInjectionAnnotations = []string{
	"cert-manager.io/inject-ca-from",
	"cert-manager.io/inject-ca-from-secret",
	"cert-manager.io/inject-apiserver-ca",
	"service.beta.openshift.io/inject-cabundle",
}

func checkCABundle(c model.Config, w model.Webhook, opts Options) []result {
	sev := SeverityMedium
	if w.FailClosed() {
		sev = SeverityHigh
	}
	if len(w.CABundle) == 0 {
		if injected(c.Annotations) {
			return nil
		}
		return []result{{
			rule:        RuleNoCABundle,
			severity:    sev,
			message:     "clientConfig has no caBundle and no CA injection annotation, so the API server cannot verify the backend's certificate",
			remediation: "set clientConfig.caBundle, or annotate the configuration with cert-manager.io/inject-ca-from",
		}}
	}

	certs, err := parseCerts(w.CABundle)
	if err != nil || len(certs) == 0 {
		return []result{{
			rule:        RuleCABundleInvalid,
			severity:    sev,
			message:     "clientConfig.caBundle does not contain a parseable X.509 certificate",
			remediation: "regenerate the bundle: it must be base64-encoded PEM, not base64-encoded DER or a base64 of a base64",
		}}
	}

	// The bundle is only as good as its earliest expiry.
	earliest := certs[0].NotAfter
	for _, cert := range certs[1:] {
		if cert.NotAfter.Before(earliest) {
			earliest = cert.NotAfter
		}
	}
	days := int(earliest.Sub(opts.Now).Hours() / 24)
	if !earliest.After(opts.Now) {
		return []result{{
			rule:     RuleCertExpired,
			severity: sev,
			message: fmt.Sprintf("caBundle certificate expired %s (%d days ago)",
				earliest.UTC().Format("2006-01-02"), -days),
			remediation: "rotate the webhook serving CA now; with failurePolicy=Fail this webhook is already rejecting writes",
		}}
	}
	if days <= opts.CertExpiryDays {
		s := SeverityMedium
		if days <= 7 {
			s = SeverityHigh
		}
		return []result{{
			rule:     RuleCertExpiring,
			severity: s,
			message: fmt.Sprintf("caBundle certificate expires in %d days (%s)",
				days, earliest.UTC().Format("2006-01-02")),
			remediation: "rotate the serving certificate and update caBundle before it lapses",
		}}
	}
	return nil
}

func injected(annotations map[string]string) bool {
	for _, a := range caInjectionAnnotations {
		if v, ok := annotations[a]; ok && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// parseCerts walks every PEM block in the bundle. A bundle with a trailing
// private key or a comment block is still usable, so unknown blocks are
// skipped rather than rejected.
func parseCerts(bundle []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE block in caBundle")
	}
	return certs, nil
}

func checkBroadRules(w model.Webhook) (result, bool) {
	if !w.FailClosed() {
		return result{}, false
	}
	for _, r := range w.Rules {
		if contains(r.APIGroups, "*") && contains(r.Resources, "*") && contains(r.Operations, "*") {
			return result{
				severity:    SeverityHigh,
				message:     "failurePolicy=Fail with apiGroups=[*], resources=[*] and operations=[*]: the blast radius is every write in the cluster",
				remediation: "narrow the rule to the resources the webhook actually inspects",
			}, true
		}
	}
	return result{}, false
}

func checkTimeout(w model.Webhook, opts Options) (result, bool) {
	if !w.FailClosed() {
		return result{}, false
	}
	t := w.EffectiveTimeout()
	if t <= opts.MaxTimeoutSeconds {
		return result{}, false
	}
	return result{
		severity: SeverityMedium,
		message: fmt.Sprintf("timeoutSeconds=%d on a fail-closed webhook: a slow backend adds up to %ds to every matching API call",
			t, t),
		remediation: fmt.Sprintf("drop timeoutSeconds to %d or less", opts.MaxTimeoutSeconds),
	}, true
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

// Summary counts findings by severity.
type Summary struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	Total  int `json:"total"`
}

// Summarize counts the findings per severity.
func Summarize(findings []Finding) Summary {
	var s Summary
	for _, f := range findings {
		switch f.Severity {
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		}
	}
	s.Total = len(findings)
	return s
}

// Gate reports whether any finding is at or above threshold. SeverityNone
// never gates.
func Gate(findings []Finding, threshold Severity) bool {
	if threshold == SeverityNone {
		return false
	}
	for _, f := range findings {
		if f.Severity >= threshold {
			return true
		}
	}
	return false
}
