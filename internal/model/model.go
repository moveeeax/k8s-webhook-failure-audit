// Package model holds the normalized view of an admission webhook
// configuration. Both loaders (manifests on disk, live cluster) produce it and
// the auditor consumes only this, so the rules never care where the data came
// from.
package model

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// Kind distinguishes the two admission webhook configuration kinds.
type Kind string

const (
	KindValidating Kind = "ValidatingWebhookConfiguration"
	KindMutating   Kind = "MutatingWebhookConfiguration"
)

// Config is one ValidatingWebhookConfiguration or MutatingWebhookConfiguration.
type Config struct {
	Kind        Kind
	Name        string
	Annotations map[string]string
	// Source is the manifest path the config was read from, or "cluster".
	Source   string
	Webhooks []Webhook
}

// Webhook is a single entry from a configuration's webhooks list.
type Webhook struct {
	Name              string
	FailurePolicy     string
	TimeoutSeconds    int32
	SideEffects       string
	Rules             []Rule
	NamespaceSelector *metav1.LabelSelector
	ObjectSelector    *metav1.LabelSelector
	// MatchConditions holds the names of the webhook's CEL match conditions.
	// The expressions are not evaluated; rules only need to know they exist.
	MatchConditions []string
	CABundle        []byte
	Service         *ServiceRef
	URL             string
}

// Rule mirrors admissionregistration/v1 RuleWithOperations.
type Rule struct {
	APIGroups   []string
	APIVersions []string
	Resources   []string
	Operations  []string
	Scope       string
}

// ServiceRef is the in-cluster backend a webhook points at.
type ServiceRef struct {
	Namespace string
	Name      string
}

// String renders the backend as namespace/name.
func (s ServiceRef) String() string { return s.Namespace + "/" + s.Name }

// FailClosed reports whether the API server rejects requests when the webhook
// backend does not answer. Kubernetes defaults failurePolicy to Fail in
// admissionregistration/v1, so an unset policy is fail-closed — which is
// exactly the case people forget about.
func (w Webhook) FailClosed() bool {
	return w.FailurePolicy == "" || w.FailurePolicy == "Fail"
}

// EffectiveTimeout returns timeoutSeconds with the API server default (10s)
// substituted for an unset value.
func (w Webhook) EffectiveTimeout() int32 {
	if w.TimeoutSeconds <= 0 {
		return 10
	}
	return w.TimeoutSeconds
}

// EffectiveFailurePolicy returns the policy that the API server will apply.
func (w Webhook) EffectiveFailurePolicy() string {
	if w.FailurePolicy == "" {
		return "Fail"
	}
	return w.FailurePolicy
}
