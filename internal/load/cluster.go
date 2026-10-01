package load

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/moveeeax/k8s-webhook-failure-audit/internal/audit"
	"github.com/moveeeax/k8s-webhook-failure-audit/internal/model"
)

// Cluster reads the admission webhook configurations from a live cluster, plus
// the namespace labels and backend Service state the auditor needs to resolve
// namespaceSelector exclusions and dead backends for real instead of guessing.
func Cluster(ctx context.Context, kubeconfig, kubeContext string) ([]model.Config, *audit.ClusterInfo, error) {
	cs, err := clientset(kubeconfig, kubeContext)
	if err != nil {
		return nil, nil, err
	}
	var configs []model.Config

	vwc, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("list validatingwebhookconfigurations: %w", err)
	}
	for i := range vwc.Items {
		configs = append(configs, FromValidating(&vwc.Items[i], "cluster"))
	}

	mwc, err := cs.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("list mutatingwebhookconfigurations: %w", err)
	}
	for i := range mwc.Items {
		configs = append(configs, FromMutating(&mwc.Items[i], "cluster"))
	}

	info := &audit.ClusterInfo{
		Live:            true,
		NamespaceLabels: map[string]map[string]string{},
		Services:        map[string]audit.ServiceInfo{},
	}

	nss, err := cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("list namespaces: %w", err)
	}
	for _, ns := range nss.Items {
		labels := map[string]string{}
		for k, v := range ns.Labels {
			labels[k] = v
		}
		// Every modern API server sets this, but a hand-rolled namespace in a
		// test cluster may not; the name label is what selectors key on.
		if _, ok := labels["kubernetes.io/metadata.name"]; !ok {
			labels["kubernetes.io/metadata.name"] = ns.Name
		}
		info.NamespaceLabels[ns.Name] = labels
	}

	for _, c := range configs {
		for _, w := range c.Webhooks {
			if w.Service == nil {
				continue
			}
			key := w.Service.String()
			if _, done := info.Services[key]; done {
				continue
			}
			info.Services[key] = serviceInfo(ctx, cs, w.Service.Namespace, w.Service.Name)
		}
	}
	return configs, info, nil
}

func serviceInfo(ctx context.Context, cs kubernetes.Interface, ns, name string) audit.ServiceInfo {
	if _, err := cs.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{}); err != nil {
		return audit.ServiceInfo{Exists: false}
	}
	ep, err := cs.CoreV1().Endpoints(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		// The Service is there but we could not read Endpoints; report the
		// Service as present and leave endpoint readiness unknown rather than
		// inventing an outage.
		return audit.ServiceInfo{Exists: true, EndpointsUnknown: true}
	}
	ready := 0
	for _, s := range ep.Subsets {
		ready += len(s.Addresses)
	}
	return audit.ServiceInfo{Exists: true, ReadyEndpoints: ready}
}

func clientset(kubeconfig, kubeContext string) (*kubernetes.Clientset, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if kubeContext != "" {
		overrides.CurrentContext = kubeContext
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("build kubeconfig: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build client: %w", err)
	}
	return cs, nil
}
