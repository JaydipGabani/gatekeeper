package externaldata

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStatsReporter(t *testing.T) {
	reporter := NewStatsReporter()
	require.NotNil(t, reporter)
}

func TestReportProviderStatus(t *testing.T) {
	reporter := NewStatsReporter()

	// Test reporting active providers
	err := reporter.ReportProviderStatus(ProviderStatusActive, 5)
	assert.NoError(t, err)

	// Test reporting error providers
	err = reporter.ReportProviderStatus(ProviderStatusError, 2)
	assert.NoError(t, err)
}

func TestReportProviderError(t *testing.T) {
	reporter := NewStatsReporter()
	ctx := context.Background()

	// Test reporting provider error
	err := reporter.ReportProviderError(ctx, "test-provider")
	assert.NoError(t, err)

	// Test multiple errors
	err = reporter.ReportProviderError(ctx, "another-provider")
	assert.NoError(t, err)
}

func TestProviderStatusConstants(t *testing.T) {
	assert.Equal(t, ProviderStatus("active"), ProviderStatusActive)
	assert.Equal(t, ProviderStatus("error"), ProviderStatusError)
}
