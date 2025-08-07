package externaldata

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	providersMetricName    = "providers"
	providerErrorCountName = "provider_error_count"
	statusKey              = "status"
)

// ProviderStatus defines the status of a provider.
type ProviderStatus string

const (
	// ProviderStatusActive denotes a successfully loaded provider, ready to handle requests.
	ProviderStatusActive ProviderStatus = "active"
	// ProviderStatusError denotes a provider that failed to load or has errors.
	ProviderStatusError ProviderStatus = "error"
)

// StatsReporter reports provider-related metrics.
type StatsReporter interface {
	ReportProviderStatus(status ProviderStatus, count int) error
	ReportProviderError(ctx context.Context, providerName string) error
}

// reporter implements StatsReporter interface.
type reporter struct {
	mu                   sync.RWMutex
	providerStatusReport map[ProviderStatus]int
	errorCounter         metric.Int64Counter
}

// NewStatsReporter creates a reporter for provider metrics.
func NewStatsReporter() StatsReporter {
	r := &reporter{
		providerStatusReport: make(map[ProviderStatus]int),
	}
	meter := otel.GetMeterProvider().Meter("gatekeeper")

	// Create the providers gauge metric
	_, err := meter.Int64ObservableGauge(
		providersMetricName,
		metric.WithDescription("The current number of external data providers"),
		metric.WithInt64Callback(r.observeProviderStatus),
	)
	if err != nil {
		panic(err)
	}

	// Create the provider error counter metric
	r.errorCounter, err = meter.Int64Counter(
		providerErrorCountName,
		metric.WithDescription("Total number of external data provider errors"),
	)
	if err != nil {
		panic(err)
	}

	return r
}

// ReportProviderStatus reports the number of providers with a specific status.
func (r *reporter) ReportProviderStatus(status ProviderStatus, count int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providerStatusReport[status] = count
	return nil
}

// ReportProviderError increments the error counter when provider errors occur.
func (r *reporter) ReportProviderError(ctx context.Context, providerName string) error {
	r.errorCounter.Add(ctx, 1)
	return nil
}

func (r *reporter) observeProviderStatus(_ context.Context, observer metric.Int64Observer) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for status, count := range r.providerStatusReport {
		observer.Observe(int64(count), metric.WithAttributes(attribute.String(statusKey, string(status))))
	}
	return nil
}
