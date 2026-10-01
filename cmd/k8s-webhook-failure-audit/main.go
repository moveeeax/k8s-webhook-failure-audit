// Command k8s-webhook-failure-audit audits ValidatingWebhookConfiguration and
// MutatingWebhookConfiguration objects for the settings that can take a
// cluster offline for writes.
package main

import (
	"os"

	"github.com/moveeeax/k8s-webhook-failure-audit/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
