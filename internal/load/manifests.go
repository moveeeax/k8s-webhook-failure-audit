// Package load turns admission webhook configurations into the normalized
// model, either from YAML manifests on disk or from a live cluster.
package load

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	admv1 "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/yaml"

	"github.com/moveeeax/k8s-webhook-failure-audit/internal/model"
)

// Manifests reads every YAML/JSON document under the given files or
// directories and returns the admission webhook configurations it finds.
// Documents of any other kind are skipped silently, so pointing the tool at a
// whole Helm render or a kustomize build output works.
func Manifests(paths []string) ([]model.Config, error) {
	files, err := collectFiles(paths)
	if err != nil {
		return nil, err
	}
	var out []model.Config
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		cfgs, err := parseDocuments(raw, f)
		if err != nil {
			return nil, err
		}
		out = append(out, cfgs...)
	}
	return out, nil
}

func collectFiles(paths []string) ([]string, error) {
	var files []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", p, err)
		}
		if !info.IsDir() {
			files = append(files, p)
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				// Skip vendored or hidden trees; they are never the manifests
				// somebody wants audited.
				if path != p && strings.HasPrefix(d.Name(), ".") {
					return fs.SkipDir
				}
				return nil
			}
			switch strings.ToLower(filepath.Ext(path)) {
			case ".yaml", ".yml", ".json":
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk %s: %w", p, err)
		}
	}
	sort.Strings(files)
	return files, nil
}

// typeMeta is the cheap probe used to decide whether a document is worth
// unmarshalling into a full webhook configuration.
type typeMeta struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

func parseDocuments(raw []byte, source string) ([]model.Config, error) {
	var out []model.Config
	for i, doc := range splitDocuments(string(raw)) {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var tm typeMeta
		if err := yaml.Unmarshal([]byte(doc), &tm); err != nil {
			// A single unparseable document should not sink the whole run, but
			// a malformed file the user explicitly pointed at should be loud.
			return nil, fmt.Errorf("%s: document %d: %w", source, i+1, err)
		}
		switch tm.Kind {
		case string(model.KindValidating):
			var c admv1.ValidatingWebhookConfiguration
			if err := yaml.Unmarshal([]byte(doc), &c); err != nil {
				return nil, fmt.Errorf("%s: document %d: %w", source, i+1, err)
			}
			out = append(out, FromValidating(&c, source))
		case string(model.KindMutating):
			var c admv1.MutatingWebhookConfiguration
			if err := yaml.Unmarshal([]byte(doc), &c); err != nil {
				return nil, fmt.Errorf("%s: document %d: %w", source, i+1, err)
			}
			out = append(out, FromMutating(&c, source))
		}
	}
	return out, nil
}

// splitDocuments splits a YAML stream on document separators. It only treats a
// line whose content is exactly "---" (optionally followed by a comment) as a
// separator, so a "---" inside a block scalar or a string does not split.
func splitDocuments(s string) []string {
	lines := strings.Split(s, "\n")
	var docs []string
	var cur []string
	for _, ln := range lines {
		if isSeparator(ln) {
			docs = append(docs, strings.Join(cur, "\n"))
			cur = cur[:0]
			continue
		}
		cur = append(cur, ln)
	}
	docs = append(docs, strings.Join(cur, "\n"))
	return docs
}

func isSeparator(line string) bool {
	t := strings.TrimRight(line, " \t\r")
	if t != "---" && !strings.HasPrefix(t, "--- ") && !strings.HasPrefix(t, "---#") {
		return false
	}
	// Indented separators are not separators.
	return !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t")
}

// FromValidating normalizes a ValidatingWebhookConfiguration.
func FromValidating(c *admv1.ValidatingWebhookConfiguration, source string) model.Config {
	out := model.Config{
		Kind:        model.KindValidating,
		Name:        c.Name,
		Annotations: c.Annotations,
		Source:      source,
	}
	for _, w := range c.Webhooks {
		mw := model.Webhook{
			Name:              w.Name,
			NamespaceSelector: w.NamespaceSelector,
			ObjectSelector:    w.ObjectSelector,
			CABundle:          w.ClientConfig.CABundle,
			Rules:             convertRules(w.Rules),
		}
		if w.FailurePolicy != nil {
			mw.FailurePolicy = string(*w.FailurePolicy)
		}
		if w.TimeoutSeconds != nil {
			mw.TimeoutSeconds = *w.TimeoutSeconds
		}
		if w.SideEffects != nil {
			mw.SideEffects = string(*w.SideEffects)
		}
		applyClientConfig(&mw, w.ClientConfig)
		out.Webhooks = append(out.Webhooks, mw)
	}
	return out
}

// FromMutating normalizes a MutatingWebhookConfiguration.
func FromMutating(c *admv1.MutatingWebhookConfiguration, source string) model.Config {
	out := model.Config{
		Kind:        model.KindMutating,
		Name:        c.Name,
		Annotations: c.Annotations,
		Source:      source,
	}
	for _, w := range c.Webhooks {
		mw := model.Webhook{
			Name:              w.Name,
			NamespaceSelector: w.NamespaceSelector,
			ObjectSelector:    w.ObjectSelector,
			CABundle:          w.ClientConfig.CABundle,
			Rules:             convertRules(w.Rules),
		}
		if w.FailurePolicy != nil {
			mw.FailurePolicy = string(*w.FailurePolicy)
		}
		if w.TimeoutSeconds != nil {
			mw.TimeoutSeconds = *w.TimeoutSeconds
		}
		if w.SideEffects != nil {
			mw.SideEffects = string(*w.SideEffects)
		}
		applyClientConfig(&mw, w.ClientConfig)
		out.Webhooks = append(out.Webhooks, mw)
	}
	return out
}

func applyClientConfig(mw *model.Webhook, cc admv1.WebhookClientConfig) {
	if cc.Service != nil {
		mw.Service = &model.ServiceRef{Namespace: cc.Service.Namespace, Name: cc.Service.Name}
	}
	if cc.URL != nil {
		mw.URL = *cc.URL
	}
}

func convertRules(rules []admv1.RuleWithOperations) []model.Rule {
	var out []model.Rule
	for _, r := range rules {
		mr := model.Rule{
			APIGroups:   r.APIGroups,
			APIVersions: r.APIVersions,
			Resources:   r.Resources,
		}
		for _, op := range r.Operations {
			mr.Operations = append(mr.Operations, string(op))
		}
		if r.Scope != nil {
			mr.Scope = string(*r.Scope)
		}
		out = append(out, mr)
	}
	return out
}
