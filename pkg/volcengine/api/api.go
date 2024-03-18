package api

import (
	"context"

	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/volcengine/types"
	"github.com/volcengine/volcengine-go-sdk/service/ecs"

	eniTypes "github.com/cilium/cilium/pkg/volcengine/eni/types"
)

type (
	VolcengineAPI interface {
		VPC
		Subnet
		ENI
		SecurityGroup
		Instance
	}
	VPC interface {
		GetVPCs(ctx context.Context) (ipamTypes.VirtualNetworkMap, error)
	}
	Subnet interface {
		GetSubnet(id string) *ipamTypes.Subnet
		GetSubnets(ctx context.Context) (ipamTypes.SubnetMap, error)
	}
	ENI interface {
		CreateNetworkInterface(ctx context.Context, secondaryPrivateIPCount int, vSwitchID string, groups []string, tags map[string]string) (string, *eniTypes.ENI, error)
		AttachNetworkInterface(ctx context.Context, instanceID, eniID string) error
		WaitENIAttached(ctx context.Context, eniID string) (string, error)
		DeleteNetworkInterface(ctx context.Context, eniID string) error

		IP
	}
	IP interface {
		AssignPrivateIPAddresses(ctx context.Context, eniID string, toAllocate int) ([]string, error)
		UnassignPrivateIPAddresses(ctx context.Context, eniID string, addresses []string) error
	}
	SecurityGroup interface {
		GetSecurityGroups(ctx context.Context) (types.SecurityGroupMap, error)
	}
	Instance interface {
		GetInstance(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error)
		GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error)
	}
)

// VolcengineClient is a subset of Volcengine Open API method
type VolcengineClient interface {
	VolcengineAPI
	GetInstanceTypes(ctx context.Context) ([]ecs.InstanceTypeForDescribeInstanceTypesOutput, error)
}

// client implemented VolcengineClient for open api call
type client struct {
	VolcengineAPI
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
