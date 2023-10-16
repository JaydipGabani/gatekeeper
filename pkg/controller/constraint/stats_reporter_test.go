package constraint

import (
	"context"
	"testing"

	"github.com/open-policy-agent/gatekeeper/v3/pkg/metrics"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/metric/metricdata/metricdatatest"
)

type fnExporter struct {
	temporalityFunc sdkmetric.TemporalitySelector
	aggregationFunc sdkmetric.AggregationSelector
	exportFunc      func(context.Context, *metricdata.ResourceMetrics) error
	flushFunc       func(context.Context) error
	shutdownFunc    func(context.Context) error
}

func (e *fnExporter) Temporality(k sdkmetric.InstrumentKind) metricdata.Temporality {
	if e.temporalityFunc != nil {
		return e.temporalityFunc(k)
	}
	return sdkmetric.DefaultTemporalitySelector(k)
}

func (e *fnExporter) Aggregation(k sdkmetric.InstrumentKind) sdkmetric.Aggregation {
	if e.aggregationFunc != nil {
		return e.aggregationFunc(k)
	}
	return sdkmetric.DefaultAggregationSelector(k)
}

func (e *fnExporter) Export(ctx context.Context, m *metricdata.ResourceMetrics) error {
	if e.exportFunc != nil {
		return e.exportFunc(ctx, m)
	}
	return nil
}

func (e *fnExporter) ForceFlush(ctx context.Context) error {
	if e.flushFunc != nil {
		return e.flushFunc(ctx)
	}
	return nil
}

func (e *fnExporter) Shutdown(ctx context.Context) error {
	if e.shutdownFunc != nil {
		return e.shutdownFunc(ctx)
	}
	return nil
}

func TestReportConstraints(t *testing.T) {
	var err error
	conctraintCache := NewConstraintsCache()
	reportMetrics = true
	tests := []struct {
		name        string
		ctx         context.Context
		expectedErr error
		want        metricdata.Metrics
	}{
		{
			name:        "reporting total constraint with attributes",
			ctx:         context.Background(),
			expectedErr: nil,
			want: metricdata.Metrics{
				Name: "test",
				Data: metricdata.Gauge[int64]{
					DataPoints: []metricdata.DataPoint[int64]{
						{Attributes: attribute.NewSet(attribute.String(enforcementActionKey, string(util.Warn)), attribute.String(statusKey, string(metrics.ActiveStatus))), Value: 0},
						{Attributes: attribute.NewSet(attribute.String(enforcementActionKey, string(util.Deny)), attribute.String(statusKey, string(metrics.ErrorStatus))), Value: 0},
						{Attributes: attribute.NewSet(attribute.String(enforcementActionKey, string(util.Dryrun)), attribute.String(statusKey, string(metrics.ErrorStatus))), Value: 0},
						{Attributes: attribute.NewSet(attribute.String(enforcementActionKey, string(util.Warn)), attribute.String(statusKey, string(metrics.ErrorStatus))), Value: 0},
						{Attributes: attribute.NewSet(attribute.String(enforcementActionKey, string(util.Deny)), attribute.String(statusKey, string(metrics.ActiveStatus))), Value: 0},
						{Attributes: attribute.NewSet(attribute.String(enforcementActionKey, string(util.Dryrun)), attribute.String(statusKey, string(metrics.ActiveStatus))), Value: 0},
						{Attributes: attribute.NewSet(attribute.String(enforcementActionKey, string(util.Unrecognized)), attribute.String(statusKey, string(metrics.ActiveStatus))), Value: 0},
						{Attributes: attribute.NewSet(attribute.String(enforcementActionKey, string(util.Unrecognized)), attribute.String(statusKey, string(metrics.ErrorStatus))), Value: 0},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rdr := sdkmetric.NewPeriodicReader(new(fnExporter))
			mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(rdr))
			meter := mp.Meter("test")

			// Ensure the pipeline has a callback setup
			constraintsM, err = meter.Int64ObservableGauge("test")
			assert.NoError(t, err)
			_, err = meter.RegisterCallback(conctraintCache.reportConstraints, constraintsM)
			assert.NoError(t, err)

			rm := &metricdata.ResourceMetrics{}
			assert.Equal(t, tt.expectedErr, rdr.Collect(tt.ctx, rm))

			for _, enforcementAction := range util.KnownEnforcementActions {
				for _, status := range metrics.AllStatuses {
					_ = tags{
						enforcementAction: enforcementAction,
						status:            status,
					}
				}
			}
			metricdatatest.AssertEqual(t, tt.want, rm.ScopeMetrics[0].Metrics[0], metricdatatest.IgnoreTimestamp())
		})
	}
}
