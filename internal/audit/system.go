package audit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/moveeeax/k8s-webhook-failure-audit/internal/model"
)

// SystemResource is a resource that the control plane and the kubelets write
// on a timer. A fail-closed webhook in front of it stalls node heartbeats,
// leader election or authentication cluster-wide, whatever namespaces the rest
// of its rules exclude.
type SystemResource struct {
	Group       string
	Resource    string
	Subresource string
	// Scope is "Namespaced", "Cluster", or "" when unknown (entries passed on
	// the command line). An unknown scope matches rules of either scope.
	Scope string
	// Namespaces lists where the objects that matter live. When every one of
	// them is excluded by the namespaceSelector, the webhook is not in the
	// path. Empty means the objects live everywhere, so no namespaceSelector
	// clears the finding.
	Namespaces []string
}

// String renders the resource the way --system-resources takes it:
// resource[/subresource][.group].
func (s SystemResource) String() string {
	out := s.Resource
	if s.Subresource != "" {
		out += "/" + s.Subresource
	}
	if s.Group != "" {
		out += "." + s.Group
	}
	return out
}

// builtinSystemResources are the defaults for --system-resources.
//
// admissionregistration.k8s.io is deliberately absent: the API server never
// calls webhooks for webhook configurations or admission policies
// (IsExemptAdmissionConfigurationResource in k8s.io/apiserver), so a rule on
// that group cannot lock anything out.
//
// tokenreviews and subjectaccessreviews stay in the list even though
// Kubernetes 1.37 stops dispatching webhooks for them by default
// (ExcludeAdmissionWebhookVirtualResources, beta): older clusters, and 1.37
// clusters with the gate off, still send them.
var builtinSystemResources = []SystemResource{
	{Group: "coordination.k8s.io", Resource: "leases", Scope: "Namespaced",
		Namespaces: []string{"kube-node-lease", "kube-system"}},
	{Resource: "nodes", Scope: "Cluster"},
	{Resource: "nodes", Subresource: "status", Scope: "Cluster"},
	{Resource: "pods", Subresource: "status", Scope: "Namespaced"},
	{Group: "authentication.k8s.io", Resource: "tokenreviews", Scope: "Cluster"},
	{Group: "authorization.k8s.io", Resource: "subjectaccessreviews", Scope: "Cluster"},
}

// DefaultSystemResources returns a copy of the built-in list.
func DefaultSystemResources() []SystemResource {
	out := make([]SystemResource, len(builtinSystemResources))
	copy(out, builtinSystemResources)
	return out
}

// DefaultSystemResourceNames is the built-in list in --system-resources form.
func DefaultSystemResourceNames() []string {
	var out []string
	for _, s := range builtinSystemResources {
		out = append(out, s.String())
	}
	return out
}

// ParseSystemResources reads entries of the form resource[/subresource][.group],
// for example "leases.coordination.k8s.io", "nodes/status" or
// "deployments/status.apps". An entry naming a built-in resource keeps the
// built-in scope and namespaces.
func ParseSystemResources(entries []string) ([]SystemResource, error) {
	known := map[string]SystemResource{}
	for _, s := range builtinSystemResources {
		known[s.String()] = s
	}
	var out []SystemResource
	seen := map[string]bool{}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		res, group, _ := strings.Cut(e, ".")
		name, sub, hasSub := strings.Cut(res, "/")
		if name == "" || strings.Contains(name, "*") || (hasSub && (sub == "" || strings.Contains(sub, "/") || strings.Contains(sub, "*"))) {
			return nil, fmt.Errorf("invalid system resource %q (want resource[/subresource][.group], for example leases.coordination.k8s.io or nodes/status)", e)
		}
		s := SystemResource{Group: group, Resource: name, Subresource: sub}
		if k, ok := known[s.String()]; ok {
			s = k
		}
		if seen[s.String()] {
			continue
		}
		seen[s.String()] = true
		out = append(out, s)
	}
	return out, nil
}

// checkSystemResources flags webhooks whose rules reach the resources the
// control plane writes on a timer. Unlike the deadlock rule this one stays
// medium for failurePolicy: Ignore, because every call still waits up to
// timeoutSeconds on a dead backend, and a lease renewal that waits too long
// is a missed lease.
func checkSystemResources(w model.Webhook, opts Options, info *ClusterInfo) (result, bool) {
	var matched []string
	for _, s := range opts.SystemResources {
		if !rulesMatchSystemResource(w.Rules, s) {
			continue
		}
		if s.Scope == "Namespaced" && len(s.Namespaces) > 0 && allExcluded(w, s.Namespaces, info) {
			continue
		}
		matched = append(matched, s.String())
	}
	if len(matched) == 0 {
		return result{}, false
	}
	sort.Strings(matched)

	fix := "drop these resources from the webhook's rules, or skip them with a matchCondition such as " +
		`!(request.resource.group == "coordination.k8s.io" && request.resource.resource == "leases")`

	if len(w.MatchConditions) > 0 {
		// CEL is not evaluated here, and a match condition is exactly how the
		// Kubernetes docs suggest excluding leases. Say so instead of guessing.
		return result{
			severity: SeverityMedium,
			message: fmt.Sprintf("failurePolicy=%s and the rules match %s; matchConditions %s may exclude them but are not evaluated, so this is unverified",
				w.EffectiveFailurePolicy(), strings.Join(matched, ","), strings.Join(w.MatchConditions, ",")),
			remediation: "check that the matchConditions skip these resources, or " + fix,
		}, true
	}

	if w.FailClosed() {
		return result{
			severity: SeverityHigh,
			message: fmt.Sprintf("failurePolicy=%s intercepts %s: if the backend %s is down, every one of those writes is rejected, which stalls node heartbeats, leader election or token and access reviews cluster-wide",
				w.EffectiveFailurePolicy(), strings.Join(matched, ","), backendLabel(w)),
			remediation: fix,
		}, true
	}
	return result{
		severity: SeverityMedium,
		message: fmt.Sprintf("failurePolicy=%s still puts %s behind a call that can take up to %ds when the backend %s is slow or down, long enough to miss lease renewals",
			w.EffectiveFailurePolicy(), strings.Join(matched, ","), w.EffectiveTimeout(), backendLabel(w)),
		remediation: fix,
	}, true
}

// rulesMatchSystemResource applies the admissionregistration/v1 resource
// matching rules: "*" is every resource but no subresource, "pods/*" is every
// subresource of pods, "*/status" is the status subresource of everything and
// "*/*" is all of it.
func rulesMatchSystemResource(rules []model.Rule, s SystemResource) bool {
	for _, r := range rules {
		if !writesIntercepted(r.Operations) || !groupMatches(r.APIGroups, s.Group) {
			continue
		}
		if s.Scope != "" && r.Scope != "" && r.Scope != "*" && r.Scope != s.Scope {
			continue
		}
		for _, pattern := range r.Resources {
			if pattern == "*/*" {
				return true
			}
			res, sub, _ := strings.Cut(pattern, "/")
			if res != "*" && res != s.Resource {
				continue
			}
			if sub == s.Subresource || (sub == "*" && s.Subresource != "") {
				return true
			}
		}
	}
	return false
}

func allExcluded(w model.Webhook, namespaces []string, info *ClusterInfo) bool {
	for _, ns := range namespaces {
		if namespaceExclusion(w.NamespaceSelector, ns, info) != exclusionExcluded {
			return false
		}
	}
	return true
}
