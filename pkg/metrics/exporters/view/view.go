package view

import (
	"go.opentelemetry.io/otel/sdk/metric"
)

func Views() []metric.View {
	return []metric.View{
		metric.NewView(
			metric.Instrument{Name: "audit_duration_seconds"},
			metric.Stream{
				Aggregation: metric.AggregationExplicitBucketHistogram{
					Boundaries: []float64{1 * 60, 3 * 60, 5 * 60, 10 * 60, 15 * 60, 20 * 60, 40 * 60, 80 * 60, 160 * 60, 320 * 60},
				},
			},
		),
		metric.NewView(
			metric.Instrument{Name: "mutator_ingestion_duration_seconds"},
			metric.Stream{
				Aggregation: metric.AggregationExplicitBucketHistogram{
					Boundaries: []float64{0.001, 0.002, 0.003, 0.004, 0.005, 0.006, 0.007, 0.008, 0.009, 0.01, 0.02, 0.03, 0.04, 0.05},
				},
			},
		),
		metric.NewView(
			metric.Instrument{Name: "mutation_system_iterations"},
			metric.Stream{
				Aggregation: metric.AggregationExplicitBucketHistogram{
					Boundaries: []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 50, 100, 200, 500},
				},
			},
		),
		metric.NewView(
			metric.Instrument{Name: "validation_request_duration_seconds"},
			metric.Stream{
				Aggregation: metric.AggregationExplicitBucketHistogram{
					Boundaries: []float64{0.001, 0.002, 0.003, 0.004, 0.005, 0.006, 0.007, 0.008, 0.009, 0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.5, 2, 2.5, 3},
				},
			},
		),
		metric.NewView(
			metric.Instrument{Name: "mutation_request_duration_seconds"},
			metric.Stream{
				Aggregation: metric.AggregationExplicitBucketHistogram{
					Boundaries: []float64{0.001, 0.002, 0.003, 0.004, 0.005, 0.006, 0.007, 0.008, 0.009, 0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.5, 2, 2.5, 3},
				},
			},
		),
		metric.NewView(
			metric.Instrument{Name: "constraint_template_ingestion_duration_seconds"},
			metric.Stream{
				Aggregation: metric.AggregationExplicitBucketHistogram{
					Boundaries: []float64{0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09, 0.1, 0.2, 0.3, 0.4, 0.5, 1, 2, 3, 4, 5},
				},
			},
		),
		metric.NewView(
			metric.Instrument{Name: "sync_duration_seconds"},
			metric.Stream{
				Aggregation: metric.AggregationExplicitBucketHistogram{
					Boundaries: []float64{0.0001, 0.0002, 0.0003, 0.0004, 0.0005, 0.0006, 0.0007, 0.0008, 0.0009, 0.001, 0.002, 0.003, 0.004, 0.005, 0.01, 0.02, 0.03, 0.04, 0.05},
				},
			},
		),
		metric.NewView(
			metric.Instrument{Name: "sync"},
			metric.Stream{
				Aggregation: metric.AggregationLastValue{},
			},
		),
		metric.NewView(
			metric.Instrument{Name: "sync_last_run_time"},
			metric.Stream{
				Aggregation: metric.AggregationLastValue{},
			},
		),
	}
}
