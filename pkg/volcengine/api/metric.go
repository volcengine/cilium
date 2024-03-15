package api

import (
	"github.com/cilium/cilium/pkg/api/helpers"
	apiMetrics "github.com/cilium/cilium/pkg/api/metrics"
)

type VolcengineMetric interface {
	helpers.MetricsAPI
	ObserveAPICall(call, status string, duration float64)
}

func NewMetric() VolcengineMetric {
	return &apiMetrics.NoOpMetrics{}
}
