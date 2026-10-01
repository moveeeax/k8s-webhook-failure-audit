# k8s-webhook-failure-audit

[![ci](https://github.com/moveeeax/k8s-webhook-failure-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/k8s-webhook-failure-audit/actions/workflows/ci.yml)
[![go](https://img.shields.io/badge/go-1.26%2B-00ADD8)](https://go.dev/dl/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Admission webhooks are the only objects in Kubernetes that can take a healthy
cluster fully offline for writes. With `failurePolicy: Fail` the API server
rejects a request whenever the webhook backend does not answer — including the
request that would create a replacement pod for that backend. If the rules also
match the namespace where the backend runs, you cannot restart it, because the
restart goes through the same admission chain.

`k8s-webhook-failure-audit` finds that configuration before it happens at 3am.
It runs against a live cluster, or against YAML in CI with no cluster access.

## Rules

| rule | severity | what it catches |
| --- | --- | --- |
| `FAIL_CLOSED_NO_EXCLUSION` | high | fail-closed webhook intercepting creates/updates of pods or workloads in `kube-system` or in its own backend namespace, with no `namespaceSelector` carve-out |
| `BACKEND_MISSING` | high | `clientConfig.service` points at a Service that does not exist, or one with no ready endpoints (live cluster only) |
| `NO_CA_BUNDLE` | high | no `caBundle` and no CA-injection annotation, so every call fails TLS verification |
| `CA_BUNDLE_INVALID` | high | `caBundle` holds no parseable X.509 certificate |
| `CERT_EXPIRED` | high | the serving CA in `caBundle` has already lapsed |
| `CERT_EXPIRING` | high / medium | the serving CA expires within `--cert-expiry-days` (high at 7 days or less) |
| `BROAD_RULES` | high | fail-closed with `apiGroups: ["*"]`, `resources: ["*"]` and `operations: ["*"]` |
| `TIMEOUT_TOO_LONG` | medium | fail-closed with `timeoutSeconds` above `--max-timeout` |

Severity drops to medium when `failurePolicy: Ignore` makes the same mistake
survivable.

## How it works

Both inputs — manifests on disk and the live API — are normalized into one
small model, and the rules only see that. So a rule behaves identically in CI
and against production, except where it genuinely needs cluster facts.

The deadlock rule is the one with real logic in it. A webhook only deadlocks
recovery if it intercepts writes to the resources needed to recreate the backend
pod, so the rule resolves each rule's `resources` **against its `apiGroups`**.
That is why `cert-manager`, whose webhook declares `resources: ["*/*"]` but only
inside `cert-manager.io` and `acme.cert-manager.io`, is not flagged, and neither
is `ingress-nginx`, which is fail-closed but only inspects `Ingress` objects. A
checker that looks at `failurePolicy: Fail` plus an empty `namespaceSelector`
flags both, and output nobody trusts is output nobody reads.

Exclusions are resolved honestly. In cluster mode the real namespace labels are
read and the `namespaceSelector` is evaluated properly. From manifests alone only
selectors keyed on `kubernetes.io/metadata.name` can be decided; a carve-out
based on a custom label is reported as **medium, unverified** rather than
silently assumed safe or loudly called a deadlock.

## Install

```console
$ go install github.com/moveeeax/k8s-webhook-failure-audit/cmd/k8s-webhook-failure-audit@latest
```

Or build it:

```console
$ git clone https://github.com/moveeeax/k8s-webhook-failure-audit.git
$ cd k8s-webhook-failure-audit
$ go build -o k8s-webhook-failure-audit ./cmd/k8s-webhook-failure-audit
```

## Usage

```console
$ k8s-webhook-failure-audit --manifests examples/webhooks
SEVERITY  RULE                      CONFIGURATION      WEBHOOK                        DETAIL
HIGH      BROAD_RULES               catch-all-mutator  mutate.everything.example.com  failurePolicy=Fail with apiGroups=[*], resources=[*] and operations=[*]: the blast radius is every write in the cluster
HIGH      FAIL_CLOSED_NO_EXCLUSION  catch-all-mutator  mutate.everything.example.com  failurePolicy=Fail intercepts configmaps,daemonsets,deployments,endpoints and 8 more in kube-system with no namespaceSelector exclusion: if the backend URL https://mutator.example.com/mutate is down, nothing can restart it
HIGH      FAIL_CLOSED_NO_EXCLUSION  policy-engine      validate.policy-engine.io      failurePolicy=Fail intercepts daemonsets,deployments,pods,statefulsets in kube-system with no namespaceSelector exclusion: if the backend Service policy-system/policy-engine-webhook is down, nothing can restart it
HIGH      NO_CA_BUNDLE              policy-engine      validate.policy-engine.io      clientConfig has no caBundle and no CA injection annotation, so the API server cannot verify the backend's certificate
MEDIUM    TIMEOUT_TOO_LONG          catch-all-mutator  mutate.everything.example.com  timeoutSeconds=28 on a fail-closed webhook: a slow backend adds up to 28s to every matching API call
MEDIUM    TIMEOUT_TOO_LONG          policy-engine      validate.policy-engine.io      timeoutSeconds=30 on a fail-closed webhook: a slow backend adds up to 30s to every matching API call

6 finding(s): 4 high, 2 medium, 0 low across 4 webhook(s) in examples/webhooks
$ echo $?
1
```

Audit the cluster you are pointed at:

```console
$ k8s-webhook-failure-audit --context prod
```

Gate a pull request on manifests, with no cluster credentials:

```console
$ k8s-webhook-failure-audit --manifests deploy/ --fail-on high
```

Feed GitHub code scanning:

```console
$ k8s-webhook-failure-audit --manifests deploy/ --sarif --fail-on none > webhooks.sarif
```

### Flags

| flag | default | meaning |
| --- | --- | --- |
| `--manifests` | — | comma-separated files or directories of YAML to audit instead of a cluster |
| `--context` | — | kubeconfig context |
| `--kubeconfig` | — | explicit kubeconfig path |
| `--fail-on` | `high` | exit 1 when a finding is at or above this severity (`high`, `medium`, `low`, `none`) |
| `--cert-expiry-days` | `30` | report `caBundle` certificates expiring within this window |
| `--max-timeout` | `10` | report fail-closed webhooks with `timeoutSeconds` above this |
| `--protected-namespaces` | `kube-system` | namespaces whose writes must keep working to recover a webhook |
| `--json` | `false` | emit JSON |
| `--sarif` | `false` | emit SARIF 2.1.0 |

### Exit codes

| code | meaning |
| --- | --- |
| `0` | no findings at or above `--fail-on` |
| `1` | findings at or above `--fail-on` |
| `2` | the run itself failed (bad flags, unreadable manifests, no cluster) |

`1` is reserved for policy failures, so CI can tell a real finding apart from a
broken invocation.

### In CI

```yaml
- name: audit admission webhooks
  run: |
    go install github.com/moveeeax/k8s-webhook-failure-audit/cmd/k8s-webhook-failure-audit@latest
    k8s-webhook-failure-audit --manifests deploy/ --fail-on high
```

## Cluster mode permissions

Read-only, and only these:

```yaml
rules:
  - apiGroups: ["admissionregistration.k8s.io"]
    resources: ["validatingwebhookconfigurations", "mutatingwebhookconfigurations"]
    verbs: ["list"]
  - apiGroups: [""]
    resources: ["namespaces", "services", "endpoints"]
    verbs: ["get", "list"]
```

## Development

```console
$ go test ./...
$ go vet ./...
$ gofmt -l .
```

Fixtures live in `internal/audit/testdata/`. Certificate tests mint their own
throwaway certificates at run time, so nothing in the suite expires.

## License

MIT — see [LICENSE](LICENSE).
