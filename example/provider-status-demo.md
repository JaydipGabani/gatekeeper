# Example Provider Status Demonstration

This example demonstrates the new Provider status functionality in Gatekeeper.

## Overview

The provider status feature adds visibility into external data providers across all Gatekeeper pods. It includes:

1. **ProviderPodStatus objects** - Track provider status per pod
2. **Provider metrics** - Monitor provider health via OpenTelemetry metrics
3. **Error tracking** - Capture conversion and cache errors with retry information

## Example Provider

```yaml
apiVersion: externaldata.gatekeeper.sh/v1beta1
kind: Provider
metadata:
  name: example-provider
spec:
  url: https://api.example.com/validate
  timeout: 30
  caBundle: LS0tLS1CRUdJTi... # base64 encoded CA bundle
```

## Generated Status Objects

When the provider is created, Gatekeeper will automatically create ProviderPodStatus objects for each pod:

```yaml
apiVersion: status.gatekeeper.sh/v1beta1
kind: ProviderPodStatus
metadata:
  name: gatekeeper-controller-manager-abc123-provider-example-provider
  namespace: gatekeeper-system
  labels:
    internal.gatekeeper.sh/provider-name: example-provider
    internal.gatekeeper.sh/pod: gatekeeper-controller-manager-abc123
status:
  id: gatekeeper-controller-manager-abc123
  providerUID: 12345678-1234-1234-1234-123456789abc
  active: true
  errors: []
  operations: ["*"]
  lastTransitionTime: "2024-01-01T12:00:00Z"
  lastCacheUpdateTime: "2024-01-01T12:00:00Z"
  observedGeneration: 1
```

## Metrics Available

The implementation provides two OpenTelemetry metrics:

### 1. gatekeeper_providers (Gauge)
Tracks the current number of external data providers by status:
- `status="active"` - Successfully loaded providers
- `status="error"` - Providers with errors

### 2. gatekeeper_provider_error_count (Counter)
Incremental counter for all provider errors occurring over time.

## Error Handling

When errors occur during provider processing, they are captured in the ProviderPodStatus:

```yaml
status:
  active: false
  errors:
  - type: conversion_error
    message: "failed to convert provider spec"
    retryable: false
    errorTimestamp: "2024-01-01T12:01:00Z"
  - type: upsert_cache_error
    message: "failed to add provider to cache"
    retryable: true
    errorTimestamp: "2024-01-01T12:02:00Z"
```

## Monitoring and Alerting

You can use the metrics and status objects to set up monitoring:

1. **Prometheus queries:**
   ```promql
   # Number of active providers
   gatekeeper_providers{status="active"}
   
   # Rate of provider errors
   rate(gatekeeper_provider_error_count[5m])
   ```

2. **Kubectl commands:**
   ```bash
   # List all provider pod status objects
   kubectl get providerpodstatus -n gatekeeper-system
   
   # Check status of a specific provider
   kubectl get providerpodstatus -n gatekeeper-system -l internal.gatekeeper.sh/provider-name=example-provider
   
   # Get detailed status information
   kubectl describe providerpodstatus -n gatekeeper-system provider-status-name
   ```

## Benefits

- **Visibility**: See provider status across all Gatekeeper pods
- **Debugging**: Identify which pods have provider issues
- **Monitoring**: Track provider health over time
- **Alerting**: Set up alerts for provider failures
- **Operations**: Understand provider lifecycle and errors