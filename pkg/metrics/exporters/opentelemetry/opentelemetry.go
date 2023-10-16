package opentelemetry

import (
	"context"
	"flag"
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

var (
	log          = logf.Log.WithName("opentelemetry-exporter")
	otlpEndPoint = flag.String("otlp-end-point", "", "Opentelemetry exporter endpoint")
)

func Start(ctx context.Context) error {
	if *otlpEndPoint == "" {
		return fmt.Errorf("otlp-end-point must be specified")
	}
	exp, err := otlpmetrichttp.New(ctx, otlpmetrichttp.WithInsecure(), otlpmetrichttp.WithEndpoint(*otlpEndPoint))
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

	otel.SetMeterProvider(meterProvider)
	defer func() {
		if err := meterProvider.Shutdown(ctx); err != nil {
			panic(err)
		}
	}()

	<-ctx.Done()
	return nil
}
