# k8s-webhook-failure-audit
Audits admission webhook configurations for the settings that can wedge a whole cluster: failurePolicy=Fail with no namespace exclusion, missing CA bundles, dead backend Services, and expiring serving certificates.
