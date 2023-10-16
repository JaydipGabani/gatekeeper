package audit

import (
	"context"
	"errors"
	"time"
	"errors"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	violationsMetricName       = "violations"
	auditDurationMetricName    = "audit_duration_seconds"
	lastRunStartTimeMetricName = "audit_last_run_time"
	lastRunEndTimeMetricName   = "audit_last_run_end_time"
	enforcementActionKey       = "enforcement_action"
)

var (
	violationsM       metric.Int64ObservableGauge
	auditDurationM    metric.Float64Histogram
	lastRunStartTimeM metric.Float64ObservableGauge
	lastRunEndTimeM   metric.Float64ObservableGauge
	endTime           time.Time
	latency           time.Duration
	startTime         time.Time
	meter             metric.Meter
)

func init() {
	var err error
	meter = otel.GetMeterProvider().Meter("gatekeeper")

	violationsM, err = meter.Int64ObservableGauge(
		violationsMetricName,
		metric.WithDescription("Total number of audited violations"),
	)

	if err != nil {
		panic(err)
	}

	auditDurationM, err = meter.Float64Histogram(
		auditDurationMetricName,
		metric.WithDescription("Latency of audit operation in seconds"))
	if err != nil {
		panic(err)
	}

	lastRunStartTimeM, err = meter.Float64ObservableGauge(
		lastRunStartTimeMetricName,
		metric.WithDescription("Timestamp of last audit run starting time"),
	)
	if err != nil {
		panic(err)
	}

	lastRunEndTimeM, err = meter.Float64ObservableGauge(
		lastRunEndTimeMetricName,
		metric.WithDescription("Timestamp of last audit run ending time"),
	)
	if err != nil {
		panic(err)
	}
}

func (r *reporter) registerCallback() error {
	_, err1 := meter.RegisterCallback(r.reportTotalViolations, violationsM)
	_, err2 := meter.RegisterCallback(r.reportRunEnd, lastRunEndTimeM)
	_, err3 := meter.RegisterCallback(r.reportRunStart, lastRunStartTimeM)
	return errors.Join(err1, err2, err3)
}

func (r *reporter) reportTotalViolations(_ context.Context, o metric.Observer) error {
	for k, v := range totalViolationsPerEnforcementAction {
		o.ObserveInt64(violationsM, v, metric.WithAttributes(attribute.String(enforcementActionKey, string(k))))
	}
	return nil
}

func (r *reporter) reportLatency(d time.Duration) error {
	auditDurationM.Record(context.Background(), d.Seconds())
	return nil
}

func (r *reporter) reportRunStart(_ context.Context, o metric.Observer) error {
	o.ObserveFloat64(lastRunStartTimeM, float64(startTime.Unix()))
	return nil
}

func (r *reporter) reportRunEnd(_ context.Context, o metric.Observer) error {
	o.ObserveFloat64(lastRunEndTimeM, float64(endTime.Unix()))
	return nil
}

// newStatsReporter creates a reporter for audit metrics.
func newStatsReporter() *reporter {
	return &reporter{}
}

type reporter struct{}
