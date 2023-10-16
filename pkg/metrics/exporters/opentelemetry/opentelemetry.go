package opentelemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/open-policy-agent/gatekeeper/v3/pkg/metrics/exporters/view"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/sdk/metric"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	Name                          = "opentelemetry"
	metricPrefix                  = "gatekeeper"
	defaultMetricsCollectInterval = 10 * time.Second
)

var log = logf.Log.WithName("opentelemetry-exporter")

func Start(ctx context.Context) error {
	exp, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return err
	}
	log.Info("otel provider started")
	meterProvider := metric.NewMeterProvider(
		metric.WithReader(metric.NewPeriodicReader(
			exp,
			metric.WithTimeout(defaultMetricsCollectInterval),
			metric.WithInterval(defaultMetricsCollectInterval),
		)),
		metric.WithView(view.Views()...),
	)
	err = runtime.Start(
		runtime.WithMinimumReadMemStatsInterval(defaultMetricsCollectInterval),
		runtime.WithMeterProvider(meterProvider))
	if err != nil {
		return fmt.Errorf("start runtime metrics: %w", err)
	}
	otel.SetMeterProvider(meterProvider)
	defer func() {
		if err := meterProvider.Shutdown(ctx); err != nil {
			panic(err)
		}
	}()

	// From here, the meterProvider can be used by instrumentation to collect
	// telemetry.
	<-ctx.Done()
	return nil
}
