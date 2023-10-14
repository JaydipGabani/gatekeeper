package audit

 

func TestReporter_reportTotalViolations(t *testing.T) {
	var err error
	totalViolationsPerEnforcementAction = map[util.EnforcementAction]int64{
		util.Deny: 1,
		util.Dryrun: 2,
		util.Warn: 3,
		util.Unrecognized: 4,
	}
	tests := []struct {
		name        string
		ctx         context.Context
		expectedErr error
		want metricdata.Metrics
		r *reporter
	}{
		{
			name:        "reporting total violations with attributes",
			ctx:         context.Background(),
			expectedErr: nil,
			r: newStatsReporter(),
			want: metricdata.Metrics{
				Name: "test",
				Data: metricdata.Gauge[int64]{
					DataPoints: []metricdata.DataPoint[int64]{
						{Attributes: attribute.NewSet(attribute.String(enforcementActionKey, string(util.Deny))), Value: 1},
						{Attributes: attribute.NewSet(attribute.String(enforcementActionKey, string(util.Dryrun))), Value: 2},
						{Attributes: attribute.NewSet(attribute.String(enforcementActionKey, string(util.Warn))), Value: 3},
						{Attributes: attribute.NewSet(attribute.String(enforcementActionKey, string(util.Unrecognized))), Value: 4},	
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
			violationsM, err = meter.Int64ObservableGauge("test")
			assert.NoError(t, err)
			_, err = meter.RegisterCallback(tt.r.reportTotalViolations, violationsM)
			assert.NoError(t, err)

			rm := &metricdata.ResourceMetrics{}
			assert.Equal(t, tt.expectedErr, rdr.Collect(tt.ctx, rm))

			metricdatatest.AssertEqual(t, tt.want, rm.ScopeMetrics[0].Metrics[0], metricdatatest.IgnoreTimestamp())	
		})
	}
}

func TestReporter_reportLatency(t *testing.T) {
	tests := []struct {
		name        string
		ctx         context.Context
		expectedErr error
		want metricdata.Metrics
		r *reporter
		duration time.Duration
	}{
		{
			name:        "reporting audit latency",
			ctx:         context.Background(),
			expectedErr: nil,
			r: newStatsReporter(),
			duration: 7000000000,
			want: metricdata.Metrics{
				Name: "test",
				Data: metricdata.Histogram[float64]{
					Temporality: metricdata.CumulativeTemporality,
					DataPoints: []metricdata.HistogramDataPoint[float64]{
						{
							Attributes:   attribute.Set{},
							Count:        1,
							Bounds:       []float64{0, 5, 10, 25, 50, 75, 100, 250, 500, 750, 1000, 2500, 5000, 7500, 10000},
							BucketCounts: []uint64{0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
							Min:          metricdata.NewExtrema[float64](7.),
							Max:          metricdata.NewExtrema[float64](7.),
							Sum:          7,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			rdr := sdkmetric.NewPeriodicReader(new(fnExporter))
			mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(rdr))
			meter := mp.Meter("test")

			// Ensure the pipeline has a callback setup
			auditDurationM, err = meter.Float64Histogram("test")
			assert.NoError(t, err)
			tt.r.reportLatency(tt.duration)
			
			rm := &metricdata.ResourceMetrics{}
			assert.Equal(t, tt.expectedErr, rdr.Collect(tt.ctx, rm))
			metricdatatest.AssertEqual(t, tt.want, rm.ScopeMetrics[0].Metrics[0], metricdatatest.IgnoreTimestamp())	
		})
	}
}

func TestReporter_reportRunStart(t *testing.T) {
	startTime = time.Now()
	tests := []struct {
		name        string
		ctx         context.Context
		expectedErr error
		want metricdata.Metrics
		r *reporter
	}{
		{
			name:        "reporting audit start time",
			ctx:         context.Background(),
			expectedErr: nil,
			r: newStatsReporter(),
			want: metricdata.Metrics{
				Name: "test",
				Data: metricdata.Gauge[float64]{
					DataPoints: []metricdata.DataPoint[float64]{
						{Value: float64(startTime.Unix())},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			rdr := sdkmetric.NewPeriodicReader(new(fnExporter))
			mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(rdr))
			meter := mp.Meter("test")

			// Ensure the pipeline has a callback setup
			lastRunStartTimeM, err = meter.Float64ObservableGauge("test")
			assert.NoError(t, err)
			_, err = meter.RegisterCallback(tt.r.reportRunStart, lastRunStartTimeM)
			assert.NoError(t, err)

			rm := &metricdata.ResourceMetrics{}
			assert.Equal(t, tt.expectedErr, rdr.Collect(tt.ctx, rm))

			metricdatatest.AssertEqual(t, tt.want, rm.ScopeMetrics[0].Metrics[0], metricdatatest.IgnoreTimestamp())	
		})
	}
}

func TestReporter_reportRunEnd(t *testing.T) {
	endTime = time.Now()
	tests := []struct {
		name        string
		ctx         context.Context
		expectedErr error
		want metricdata.Metrics
		r *reporter
	}{
		{
			name:        "reporting audit end time",
			ctx:         context.Background(),
			expectedErr: nil,
			r: newStatsReporter(),
			want: metricdata.Metrics{
				Name: "test",
				Data: metricdata.Gauge[float64]{
					DataPoints: []metricdata.DataPoint[float64]{
						{Value: float64(endTime.Unix())},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			rdr := sdkmetric.NewPeriodicReader(new(fnExporter))
			mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(rdr))
			meter := mp.Meter("test")

			// Ensure the pipeline has a callback setup
			lastRunEndTimeM, err = meter.Float64ObservableGauge("test")
			assert.NoError(t, err)
			_, err = meter.RegisterCallback(tt.r.reportRunEnd, lastRunEndTimeM)
			assert.NoError(t, err)

			rm := &metricdata.ResourceMetrics{}
			assert.Equal(t, tt.expectedErr, rdr.Collect(tt.ctx, rm))

			metricdatatest.AssertEqual(t, tt.want, rm.ScopeMetrics[0].Metrics[0], metricdatatest.IgnoreTimestamp())	
		})
	}
}

