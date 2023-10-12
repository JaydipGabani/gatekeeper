package opentelemetry

import (
	"context"

	"github.com/open-policy-agent/gatekeeper/v3/pkg/metrics/exporters/view"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/sdk/metric"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	Name         = "opentelemetry"
	metricPrefix = "gatekeeper"
)

var log = logf.Log.WithName("opentelemetry-exporter")

func Start(ctx context.Context) error {
	exp, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return err
	}

	meterProvider := metric.NewMeterProvider(metric.WithReader(metric.NewPeriodicReader(exp)), metric.WithView(view.Views()...))
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
