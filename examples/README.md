# examples

Four webhook configurations in the shapes you actually meet in a cluster:

| file | shape | expected |
| --- | --- | --- |
| `webhooks/policy-engine.yaml` | fail-closed, intercepts pods and workloads everywhere, no carve-out, no `caBundle` | 2 high + 1 medium |
| `webhooks/catch-all-mutator.yaml` | fail-closed with `apiGroups: ["*"]`, `resources: ["*"]`, `operations: ["*"]` | 2 high + 1 medium |
| `webhooks/ingress-nginx.yaml` | fail-closed, but only inspects `Ingress` objects | clean |
| `webhooks/cert-manager.yaml` | fail-closed, `resources: ["*/*"]` inside its own API groups, `caBundle` injected by annotation | clean |

The last two are the reason the deadlock rule looks at `apiGroups` and at which
resources a rule matches. A tool that only checks `failurePolicy: Fail` plus an
empty `namespaceSelector` flags both of them, and then nobody reads its output.

```console
$ k8s-webhook-failure-audit --manifests examples/webhooks
```
