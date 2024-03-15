package api

import (
	"context"

	"github.com/volcengine/volcengine-go-sdk/service/ecs"

	"github.com/cilium/cilium/pkg/volcengine/eni"
)

// VolcengineClient is a subset of Volcengine Open API method
type VolcengineClient interface {
	eni.VolcengineAPI
	GetInstanceTypes(ctx context.Context) ([]ecs.InstanceTypeForDescribeInstanceTypesOutput, error)
}

// client implemented VolcengineClient for open api call
type client struct {
	eni.VolcengineAPI
}

func (c client) GetInstanceTypes(ctx context.Context) ([]ecs.InstanceTypeForDescribeInstanceTypesOutput, error) {
	return nil, nil
}

func NewClient(regionID, vpcID string, metric VolcengineMetric, qpsLimit float64, burst int, filters map[string]string) (VolcengineClient, error) {
	return newClient()
}

func newClient() (*client, error) {
	return &client{}, nil
}
