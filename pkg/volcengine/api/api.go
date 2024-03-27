// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"fmt"
	"maps"

	"github.com/volcengine/volcengine-go-sdk/service/ecs"
	"github.com/volcengine/volcengine-go-sdk/service/vpc"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/pkg/api/helpers"
	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/time"
	eniTypes "github.com/cilium/cilium/pkg/volcengine/eni/types"
	"github.com/cilium/cilium/pkg/volcengine/types"
)

var apiWriteBackoff = wait.Backoff{
	Duration: time.Second * 4,
	Factor:   1.5,
	Jitter:   0.5,
	Steps:    6,
}

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
		GetSubnet(ctx context.Context, id string) (*ipamTypes.Subnet, error)
		GetSubnets(ctx context.Context) (ipamTypes.SubnetMap, error)
	}
	ENI interface {
		CreateNetworkInterface(ctx context.Context, secondaryPrivateIPCount int, vSwitchID string, groups []string, tags map[string]string) (string, *eniTypes.ENI, error)
		AttachNetworkInterface(ctx context.Context, instanceID, eniID string) error
		WaitENIAttached(ctx context.Context, eniID string) (string, error)
		DeleteNetworkInterface(ctx context.Context, eniID string) error
		GetDetachedNetworkInterfaces(ctx context.Context, tags ipamTypes.Tags, maxInterval time.Duration) ([]string, error)

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
		GetInstanceTypes(ctx context.Context) (map[string]ipamTypes.Limits, error)
	}
)

// Client implemented VolcengineClient for open api call
type Client struct {
	ecsClient       *ecs.ECS
	vpcClient       *vpc.VPC
	limiter         *helpers.APILimiter
	projectName     string
	ecsTagFilters   []*ecs.TagFilterForDescribeInstancesInput
	eniCreationTags map[string]string
	vpcID           string //currently not used
}

type TagFilters[T any] interface {
	SetKey(string) T
	SetValues([]*string) T
}

func NewClient(config *volcengine.Config, metric VolcengineMetric, qpsLimit float64, burst int,
	project, vpcID string, ecsTags, eniTags, subnetTags map[string]string) (*Client, error) {
	sess, err := session.NewSession(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	return newClient(vpc.New(sess), ecs.New(sess), metric, qpsLimit, burst, project, vpcID, eniTags, NewInstanceTagFilters(ecsTags)), nil
}

func newClient(vpcClient *vpc.VPC, ecsClient *ecs.ECS, metrics VolcengineMetric, rateLimit float64, burst int,
	projectName, vpcID string, eniTags map[string]string, ecsTagFilters []*ecs.TagFilterForDescribeInstancesInput) *Client {
	return &Client{
		vpcClient:       vpcClient,
		ecsClient:       ecsClient,
		limiter:         helpers.NewAPILimiter(metrics, rateLimit, burst),
		projectName:     projectName,
		vpcID:           vpcID,
		eniCreationTags: eniTags,
		ecsTagFilters:   ecsTagFilters,
	}
}

// NewInstanceTagFilters returns tag filter for describe instances.
func NewInstanceTagFilters(tags map[string]string) []*ecs.TagFilterForDescribeInstancesInput {
	return newTagFilters(tags, func() *ecs.TagFilterForDescribeInstancesInput {
		return &ecs.TagFilterForDescribeInstancesInput{}
	})
}

// NewInterfaceTagFilters returns tag filter for describe network interfaces.
func NewInterfaceTagFilters(tags map[string]string) []*vpc.TagFilterForDescribeNetworkInterfacesInput {
	return newTagFilters(tags, func() *vpc.TagFilterForDescribeNetworkInterfacesInput {
		return &vpc.TagFilterForDescribeNetworkInterfacesInput{}
	})
}

// NewSecurityGroupTagFilters returns tag filters for describe security groups.
func NewSecurityGroupTagFilters(tags map[string]string) []*vpc.TagFilterForDescribeSecurityGroupsInput {
	return newTagFilters(tags, func() *vpc.TagFilterForDescribeSecurityGroupsInput {
		return &vpc.TagFilterForDescribeSecurityGroupsInput{}
	})
}

func newTagFilters[T TagFilters[T]](tags map[string]string, newFilter func() T) []T {
	if len(tags) == 0 {
		return nil
	}
	filters := make([]T, 0, len(tags))
	for k, v := range tags {
		filters = append(filters, newFilter().SetKey(k).SetValues([]*string{volcengine.String(v)}))
	}
	return filters
}

// CreateNetworkInterface creates a network interface(ENI).
func (c *Client) CreateNetworkInterface(ctx context.Context, secondaryPrivateIPCount int, subnetID string, groups []string, extraTags map[string]string) (string, *eniTypes.ENI, error) {
	resp, err := c.createNetworkInterface(ctx, secondaryPrivateIPCount, subnetID, groups, MergeTags(c.eniCreationTags, extraTags))
	if err != nil {
		return "", nil, err
	}
	iface := &eniTypes.ENI{
		NetworkInterfaceID: volcengine.StringValue(resp.NetworkInterfaceId),
		//ProjectName:        volcengine.StringValue(resp.ProjectName),
		Type:             eniTypes.ENITypeSecondary,
		MACAddress:       volcengine.StringValue(resp.MacAddress),
		PrimaryIPAddress: volcengine.StringValue(resp.PrimaryIpAddress),
		PrivateIPSets:    getPrivateIPSetsFromInterfacesAttrOutput(resp.PrivateIpSets),
		VPC: eniTypes.VPC{
			VPCID:               volcengine.StringValue(resp.VpcId),
			CIDRBlock:           "",
			IPv6CIDRBlock:       "",
			SecondaryCIDRBlocks: nil,
		},
		ZoneID: volcengine.StringValue(resp.ZoneId),
		Subnet: eniTypes.Subnet{
			SubnetID:      volcengine.StringValue(resp.SubnetId),
			CIDRBlock:     "",
			IPv6CIDRBlock: "",
		},
		DeviceID:         volcengine.StringValue(resp.DeviceId),
		SecurityGroupIds: volcengine.StringValueSlice(resp.SecurityGroupIds),
		Tags:             parseENITagsForDescribeNetworkInterfaceAttr(resp),
	}
	return iface.NetworkInterfaceID, iface, nil
}

// AttachNetworkInterface attaches: interface(ENI) to the instance(ECS) asynchronously,
// WaitENIAttached should be called before using ENI.
func (c *Client) AttachNetworkInterface(ctx context.Context, instanceID, eniID string) error {
	return c.attachNetworkInterface(ctx, instanceID, eniID)
}

// WaitENIAttached waits until eni status become "InUse".
func (c *Client) WaitENIAttached(ctx context.Context, eniID string) (string, error) {
	resp, err := c.waitNetworkInterfaceAttached(ctx, eniID)
	if err != nil {
		return "", fmt.Errorf("failed to wait ENI: %v attached, err: %w", eniID, err)
	}
	return volcengine.StringValue(resp.DeviceId), nil
}

// DeleteNetworkInterface deletes network interface(ENI).
func (c *Client) DeleteNetworkInterface(ctx context.Context, eniID string) error {
	return c.deleteNetworkInterface(ctx, eniID)
}

// GetDetachedNetworkInterfaces returns all available interfaces that exceeds maxInterval since last updated time.
func (c *Client) GetDetachedNetworkInterfaces(ctx context.Context, tags ipamTypes.Tags, maxInterval time.Duration) ([]string, error) {
	interfaces, err := c.describeInterfaces(ctx, NewInterfaceTagFilters(tags))
	if err != nil {
		return nil, fmt.Errorf("failed to describe detached interfaces, err %v", err)
	}

	eniIDsTobeDeleted := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		if volcengine.StringValue(iface.Status) == eniTypes.ENIStatusAvailable {
			updateAt, err := time.Parse(time.RFC3339, volcengine.StringValue(iface.UpdatedAt))
			if err != nil {
				return nil, fmt.Errorf("failed to parse update time for interface")
			}
			if time.Since(updateAt) > maxInterval {
				eniIDsTobeDeleted = append(eniIDsTobeDeleted, volcengine.StringValue(iface.NetworkInterfaceId))
			}
		}
	}
	return eniIDsTobeDeleted, nil
}

// AssignPrivateIPAddresses allocates a bunch of ipv4 addresses to network interfaces(ENI).
func (c *Client) AssignPrivateIPAddresses(ctx context.Context, eniID string, toAllocate int) ([]string, error) {
	resp, err := c.assignPrivateIPAddresses(ctx, eniID, toAllocate)
	if err != nil {
		return nil, fmt.Errorf("failed to assigne address to interface %v, err: %w", eniID, err)
	}
	return volcengine.StringValueSlice(resp.PrivateIpSet), nil
}

// UnassignPrivateIPAddresses deallocates a bunch of ipv4 addresses to network interfaces(ENI).
func (c *Client) UnassignPrivateIPAddresses(ctx context.Context, eniID string, addresses []string) error {
	_, err := c.unassignPrivateIPAddresses(ctx, eniID, addresses)
	return err
}

// GetVPCs returns all vpcs.
func (c *Client) GetVPCs(ctx context.Context) (ipamTypes.VirtualNetworkMap, error) {
	vpcMap := ipamTypes.VirtualNetworkMap{}
	vpcs, err := c.describeVPCs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get vpcs, err: %w", err)
	}
	for _, v := range vpcs {
		id := volcengine.StringValue(v.VpcId)
		vpcMap[id] = &ipamTypes.VirtualNetwork{
			ID:          volcengine.StringValue(v.VpcId),
			PrimaryCIDR: volcengine.StringValue(v.CidrBlock),
			CIDRs:       volcengine.StringValueSlice(v.SecondaryCidrBlocks),
		}
	}
	return vpcMap, nil
}

// GetInstanceTypes returns instances' network limits.
func (c *Client) GetInstanceTypes(ctx context.Context) (map[string]ipamTypes.Limits, error) {
	limits := make(map[string]ipamTypes.Limits)
	types, err := c.describeInstanceTypes(ctx)
	if err != nil {
		return nil, err
	}
	for _, t := range types {
		limits[volcengine.StringValue(t.InstanceTypeId)] = ipamTypes.Limits{
			Adapters: int(volcengine.Int32Value(t.Network.MaximumNetworkInterfaces)),
			IPv4:     int(volcengine.Int32Value(t.Network.MaximumPrivateIpv4AddressesPerNetworkInterface)),
			// Currently, Volcengine SDK hasn't provided this field, but the value is same as IPv4.
			IPv6:           0,
			HypervisorType: "",
		}
	}
	return limits, nil
}

// GetInstance returns instance ID along with attached network interfaces(ENI).
func (c *Client) GetInstance(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error) {
	instance := &ipamTypes.Instance{}
	instance.Interfaces = map[string]ipamTypes.InterfaceRevision{}
	networkInterfaces, err := c.describeInterfaceByInstanceId(ctx, instanceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces for instance %v, err: %w", instanceID, err)
	}
	for _, iface := range networkInterfaces {
		eni := eniTypes.ENI{
			NetworkInterfaceID: volcengine.StringValue(iface.NetworkInterfaceId),
			//ProjectName:        volcengine.StringValue(iface.ProjectName),
			Type:             eniTypes.ENIType(volcengine.StringValue(iface.Type)),
			MACAddress:       volcengine.StringValue(iface.MacAddress),
			PrimaryIPAddress: volcengine.StringValue(iface.PrimaryIpAddress),
			PrivateIPSets:    getPrivateIPSetsFromInterfacesOutput(iface.PrivateIpSets),
			VPC: eniTypes.VPC{
				VPCID:               volcengine.StringValue(iface.VpcId),
				CIDRBlock:           "",
				IPv6CIDRBlock:       "",
				SecondaryCIDRBlocks: nil,
			},
			ZoneID: volcengine.StringValue(iface.ZoneId),
			Subnet: eniTypes.Subnet{
				SubnetID:      volcengine.StringValue(iface.SubnetId),
				CIDRBlock:     "",
				IPv6CIDRBlock: "",
			},
			DeviceID:         volcengine.StringValue(iface.DeviceId),
			SecurityGroupIds: volcengine.StringValueSlice(iface.SecurityGroupIds),
			Tags:             parseENITagsForDescribeNetworkInterfaces(iface),
		}
		item, err := parseENI(&eni, vpcs, subnets)
		if err != nil {
			return nil, fmt.Errorf("failed to parse interface for instance %v, err: %w", instanceID, err)
		}

		instance.Interfaces[item.InterfaceID()] = ipamTypes.InterfaceRevision{
			Resource: item,
		}
	}
	return instance, nil
}

// GetInstances  returns instance map along with attached network interfaces(ENI).
func (c *Client) GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	instances := ipamTypes.NewInstanceMap()
	var networkInterfaces []*vpc.NetworkInterfaceSetForDescribeNetworkInterfacesOutput
	var err error

	if len(c.ecsTagFilters) > 0 {
		networkInterfaces, err = c.describeInterfacesOfInstances(ctx)
	} else {
		networkInterfaces, err = c.describeInterfaces(ctx, nil)
	}
	if err != nil {
		return nil, err
	}

	for _, iface := range networkInterfaces {
		eni := eniTypes.ENI{
			NetworkInterfaceID: volcengine.StringValue(iface.NetworkInterfaceId),
			ProjectName:        volcengine.StringValue(iface.ProjectName),
			Type:               eniTypes.ENIType(volcengine.StringValue(iface.Type)),
			MACAddress:         volcengine.StringValue(iface.MacAddress),
			PrimaryIPAddress:   volcengine.StringValue(iface.PrimaryIpAddress),
			PrivateIPSets:      getPrivateIPSetsFromInterfacesOutput(iface.PrivateIpSets),
			VPC: eniTypes.VPC{
				VPCID:               volcengine.StringValue(iface.VpcId),
				CIDRBlock:           "",
				IPv6CIDRBlock:       "",
				SecondaryCIDRBlocks: nil,
			},
			ZoneID: volcengine.StringValue(iface.ZoneId),
			Subnet: eniTypes.Subnet{
				SubnetID:      volcengine.StringValue(iface.SubnetId),
				CIDRBlock:     "",
				IPv6CIDRBlock: "",
			},
			DeviceID:         volcengine.StringValue(iface.DeviceId),
			SecurityGroupIds: volcengine.StringValueSlice(iface.SecurityGroupIds),
			Tags:             parseENITagsForDescribeNetworkInterfaces(iface),
		}
		item, err := parseENI(&eni, vpcs, subnets)
		if err != nil {
			instances.Update(item.DeviceID, ipamTypes.InterfaceRevision{Resource: item})
		}
	}

	return instances, nil
}

// GetSubnet returns subnet's information.
func (c *Client) GetSubnet(ctx context.Context, id string) (*ipamTypes.Subnet, error) {
	resp, err := c.describeSubnetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get subnet %v, err: %w", id, err)
	}
	cidrBlock, err := cidr.ParseCIDR(volcengine.StringValue(resp.CidrBlock))
	if err != nil {
		return nil, fmt.Errorf("failed to parse cidr block: %v, err: %w", *resp.CidrBlock, err)
	}
	return &ipamTypes.Subnet{
		ID:                 volcengine.StringValue(resp.SubnetId),
		Name:               volcengine.StringValue(resp.SubnetName),
		CIDR:               cidrBlock,
		AvailabilityZone:   volcengine.StringValue(resp.ZoneId),
		VirtualNetworkID:   volcengine.StringValue(resp.VpcId),
		AvailableAddresses: int(volcengine.Int64Value(resp.AvailableIpAddressCount)),
		Tags:               nil, //currently not supported by volcengine SDK
	}, err

}

// GetSubnets returns a map that records subnets' information.
func (c *Client) GetSubnets(ctx context.Context) (ipamTypes.SubnetMap, error) {
	subnetMap := ipamTypes.SubnetMap{}
	subnets, err := c.describeSubnets(ctx)
	if err != nil {
		return nil, fmt.Errorf("faile to get subnets, err: %w", err)
	}
	for _, subnet := range subnets {
		cidrBlock, err := cidr.ParseCIDR(volcengine.StringValue(subnet.CidrBlock))
		if err != nil {
			return nil, fmt.Errorf("failed to parse cidr block: %v, err: %w", *subnet.CidrBlock, err)
		}
		subnetMap[volcengine.StringValue(subnet.SubnetId)] = &ipamTypes.Subnet{
			ID:                 volcengine.StringValue(subnet.SubnetId),
			Name:               volcengine.StringValue(subnet.SubnetName),
			CIDR:               cidrBlock,
			AvailabilityZone:   volcengine.StringValue(subnet.ZoneId),
			VirtualNetworkID:   volcengine.StringValue(subnet.VpcId),
			AvailableAddresses: int(volcengine.Int64Value(subnet.AvailableIpAddressCount)),
			Tags:               nil, //currently not supported by volcengine SDK
		}
	}
	return subnetMap, nil
}

// GetSecurityGroups returns a map that records security groups.
func (c *Client) GetSecurityGroups(ctx context.Context) (types.SecurityGroupMap, error) {
	sgMap := types.SecurityGroupMap{}
	sgs, err := c.describeSecurityGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("faile to get subnets, err: %w", err)
	}
	for _, sg := range sgs {
		id := volcengine.StringValue(sg.SecurityGroupId)
		sgMap[id] = &types.SecurityGroup{
			ID:          volcengine.StringValue(sg.SecurityGroupId),
			VPCID:       volcengine.StringValue(sg.VpcId),
			ProjectName: volcengine.StringValue(sg.ProjectName),
			Tags:        parseSecurityGroupForDescribeSecurityGroups(sg),
		}
	}
	return sgMap, nil
}

func (c *Client) describeSubnetByID(ctx context.Context, id string) (*vpc.DescribeSubnetAttributesOutput, error) {
	c.limiter.Limit(ctx, "DescribeSubnetAttributes")
	return c.vpcClient.DescribeSubnetAttributes(
		&vpc.DescribeSubnetAttributesInput{SubnetId: volcengine.String(id)})
}

func (c *Client) describeSubnets(ctx context.Context) ([]*vpc.SubnetForDescribeSubnetsOutput, error) {
	result := make([]*vpc.SubnetForDescribeSubnetsOutput, 0)
	input := &vpc.DescribeSubnetsInput{
		//ProjectName: volcengine.String(c.projectName),
		MaxResults: volcengine.Int64(100),
	}
	c.limiter.Limit(ctx, "DescribeSubnets")
	resp, err := c.vpcClient.DescribeSubnets(input)
	if err != nil {
		return nil, err
	}
	result = append(result, resp.Subnets...)
	input.NextToken = resp.NextToken
	for len(volcengine.StringValue(input.NextToken)) > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			c.limiter.Limit(ctx, "DescribeSubnets")
			resp, err = c.vpcClient.DescribeSubnets(input)
			if err != nil {
				return nil, err
			}
			result = append(result, resp.Subnets...)
			input.NextToken = resp.NextToken
		}
	}
	return result, nil
}

func (c *Client) describeInterfaceByInstanceId(ctx context.Context, instanceID string) ([]*vpc.NetworkInterfaceSetForDescribeNetworkInterfacesOutput, error) {
	result := make([]*vpc.NetworkInterfaceSetForDescribeNetworkInterfacesOutput, 0, 10)
	input := &vpc.DescribeNetworkInterfacesInput{
		InstanceId: volcengine.String(instanceID),
		MaxResults: volcengine.Int64(100),
		//ProjectName: volcengine.String(c.projectName),
	}
	c.limiter.Limit(ctx, "DescribeNetworkInterfaces")
	resp, err := c.vpcClient.DescribeNetworkInterfaces(input)
	if err != nil {
		return nil, err
	}
	result = append(result, resp.NetworkInterfaceSets...)
	input.NextToken = resp.NextToken
	for len(volcengine.StringValue(input.NextToken)) > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			c.limiter.Limit(ctx, "DescribeNetworkInterfaces")
			resp, err = c.vpcClient.DescribeNetworkInterfaces(input)
			if err != nil {
				return nil, err
			}
			result = append(result, resp.NetworkInterfaceSets...)
			input.NextToken = resp.NextToken
		}
	}
	return result, nil

}

func (c *Client) describeInterfacesOfInstances(ctx context.Context) ([]*vpc.NetworkInterfaceSetForDescribeNetworkInterfacesOutput, error) {
	results := make([]*vpc.NetworkInterfaceSetForDescribeNetworkInterfacesOutput, 0, 100)

	input := &ecs.DescribeInstancesInput{
		//ProjectName: volcengine.String(c.projectName),
		TagFilters: c.ecsTagFilters,
		MaxResults: volcengine.Int32(100),
	}
	c.limiter.Limit(ctx, "DescribeInstances")
	resp, err := c.ecsClient.DescribeInstances(input)
	if err != nil {
		return nil, err
	}
	for _, instance := range resp.Instances {
		enis, err := c.describeInterfaceByInstanceId(ctx, volcengine.StringValue(instance.InstanceId))
		if err != nil {
			return nil, err
		}
		results = append(results, enis...)
	}
	input.NextToken = resp.NextToken
	for len(volcengine.StringValue(input.NextToken)) > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			c.limiter.Limit(ctx, "DescribeInstances")
			resp, err = c.ecsClient.DescribeInstances(input)
			if err != nil {
				return nil, err
			}
			for _, instance := range resp.Instances {
				enis, err := c.describeInterfaceByInstanceId(ctx, volcengine.StringValue(instance.InstanceId))
				if err != nil {
					return nil, err
				}
				results = append(results, enis...)

			}
			input.NextToken = resp.NextToken
		}
	}
	return results, nil
}

func (c *Client) describeInterfaces(ctx context.Context, filters []*vpc.TagFilterForDescribeNetworkInterfacesInput) ([]*vpc.NetworkInterfaceSetForDescribeNetworkInterfacesOutput, error) {
	results := make([]*vpc.NetworkInterfaceSetForDescribeNetworkInterfacesOutput, 0, 100)
	input := &vpc.DescribeNetworkInterfacesInput{
		MaxResults: volcengine.Int64(100),
		//ProjectName: volcengine.String(c.projectName),
		TagFilters: filters,
	}
	c.limiter.Limit(ctx, "DescribeNetworkInterfaces")
	resp, err := c.vpcClient.DescribeNetworkInterfaces(input)
	if err != nil {
		return nil, err
	}
	results = append(results, resp.NetworkInterfaceSets...)
	input.NextToken = resp.NextToken
	for len(volcengine.StringValue(input.NextToken)) > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			c.limiter.Limit(ctx, "DescribeNetworkInterfaces")
			resp, err = c.vpcClient.DescribeNetworkInterfaces(input)
			if err != nil {
				return nil, err
			}
			results = append(results, resp.NetworkInterfaceSets...)
			input.NextToken = resp.NextToken
		}
	}
	return results, nil
}

func (c *Client) describeVPCs(ctx context.Context) ([]*vpc.VpcForDescribeVpcsOutput, error) {
	result := make([]*vpc.VpcForDescribeVpcsOutput, 0)
	input := &vpc.DescribeVpcsInput{
		MaxResults: volcengine.Int64(100),
		//ProjectName: volcengine.String(c.projectName),
	}
	c.limiter.Limit(ctx, "DescribeVpcs")
	resp, err := c.vpcClient.DescribeVpcs(input)
	if err != nil {
		return nil, err
	}
	result = append(result, resp.Vpcs...)

	input.NextToken = resp.NextToken
	for len(volcengine.StringValue(input.NextToken)) > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			c.limiter.Limit(ctx, "DescribeVpcs")
			resp, err = c.vpcClient.DescribeVpcs(input)
			if err != nil {
				return nil, err
			}
			result = append(result, resp.Vpcs...)
			input.NextToken = resp.NextToken
		}
	}
	return result, nil
}

func (c *Client) describeSecurityGroups(ctx context.Context) ([]*vpc.SecurityGroupForDescribeSecurityGroupsOutput, error) {
	result := make([]*vpc.SecurityGroupForDescribeSecurityGroupsOutput, 0, 5)
	input := &vpc.DescribeSecurityGroupsInput{
		MaxResults: volcengine.Int64(100),
		//ProjectName: volcengine.String(c.projectName),
	}
	c.limiter.Limit(ctx, "DescribeSecurityGroups")
	resp, err := c.vpcClient.DescribeSecurityGroups(input)
	if err != nil {
		return nil, err
	}
	result = append(result, resp.SecurityGroups...)
	input.NextToken = resp.NextToken
	for len(volcengine.StringValue(input.NextToken)) > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			c.limiter.Limit(ctx, "DescribeSecurityGroups")
			resp, err = c.vpcClient.DescribeSecurityGroups(input)
			if err != nil {
				return nil, err
			}
			result = append(result, resp.SecurityGroups...)
			input.NextToken = resp.NextToken
		}
	}
	return result, nil
}

func (c *Client) describeInstanceTypes(ctx context.Context) ([]*ecs.InstanceTypeForDescribeInstanceTypesOutput, error) {
	result := make([]*ecs.InstanceTypeForDescribeInstanceTypesOutput, 0, 100)
	input := &ecs.DescribeInstanceTypesInput{
		MaxResults: volcengine.Int32(100),
	}
	c.limiter.Limit(ctx, "DescribeInstanceTypes")
	resp, err := c.ecsClient.DescribeInstanceTypes(input)
	if err != nil {
		return nil, err
	}
	result = append(result, resp.InstanceTypes...)
	input.NextToken = resp.NextToken
	for len(volcengine.StringValue(input.NextToken)) > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			c.limiter.Limit(ctx, "DescribeInstanceTypes")
			resp, err = c.ecsClient.DescribeInstanceTypes(input)
			if err != nil {
				return nil, err
			}
			result = append(result, resp.InstanceTypes...)
			input.NextToken = resp.NextToken
		}
	}
	return result, nil
}

func (c *Client) createNetworkInterface(ctx context.Context, ipCount int, subnetId string, groups []string, tags map[string]string) (*vpc.DescribeNetworkInterfaceAttributesOutput, error) {
	input := &vpc.CreateNetworkInterfaceInput{
		//ProjectName:                    volcengine.String(c.projectName),
		SecondaryPrivateIpAddressCount: volcengine.Int64(min(int64(1), int64(ipCount))),
		SecurityGroupIds:               volcengine.StringSlice(groups),
		SubnetId:                       volcengine.String(subnetId),
		Tags:                           buildENITagsForCreateNetworkInterface(tags),
	}
	c.limiter.Limit(ctx, "CreateNetworkInterface")
	resp, err := c.vpcClient.CreateNetworkInterface(input)
	if err != nil {
		return nil, err
	}
	var output *vpc.DescribeNetworkInterfaceAttributesOutput
	err = wait.ExponentialBackoffWithContext(ctx, apiWriteBackoff, func(ctx context.Context) (done bool, err error) {
		c.limiter.Limit(ctx, "DescribeNetworkInterfaceAttribute")
		output, err = c.vpcClient.DescribeNetworkInterfaceAttributes(
			&vpc.DescribeNetworkInterfaceAttributesInput{
				NetworkInterfaceId: resp.NetworkInterfaceId,
			})
		if err != nil {
			return false, err
		} else if volcengine.StringValue(output.Status) == eniTypes.ENIStatusAvailable {
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return output, nil
}

func (c *Client) attachNetworkInterface(ctx context.Context, instanceID string, interfaceID string) error {
	input := &vpc.AttachNetworkInterfaceInput{
		InstanceId:         volcengine.String(instanceID),
		NetworkInterfaceId: volcengine.String(interfaceID),
	}
	c.limiter.Limit(ctx, "AttachNetworkInterface")
	_, err := c.vpcClient.AttachNetworkInterface(input)
	return err
}

func (c *Client) waitNetworkInterfaceAttached(ctx context.Context, interfaceID string) (*vpc.DescribeNetworkInterfaceAttributesOutput, error) {
	var output *vpc.DescribeNetworkInterfaceAttributesOutput
	var err error
	backOffCtx, cancel := context.WithCancel(ctx)

	wait.JitterUntilWithContext(backOffCtx, func(ctx context.Context) {
		c.limiter.Limit(ctx, "DescribeNetworkInterfaceAttribute")
		output, err = c.vpcClient.DescribeNetworkInterfaceAttributes(
			&vpc.DescribeNetworkInterfaceAttributesInput{
				NetworkInterfaceId: volcengine.String(interfaceID),
			})
		if err == nil && volcengine.StringValue(output.Status) == eniTypes.ENIStatusInUse {
			cancel()
		}
	}, 5*time.Second, 0.5, true)

	return output, err
}

func (c *Client) deleteNetworkInterface(ctx context.Context, eniID string) error {
	c.limiter.Limit(ctx, "DescribeNetworkInterfaceAttribute")
	output, err := c.vpcClient.DescribeNetworkInterfaceAttributes(
		&vpc.DescribeNetworkInterfaceAttributesInput{
			NetworkInterfaceId: volcengine.String(eniID),
		})
	if err != nil {
		return err
	} else if output.NetworkInterfaceId == nil {
		// Interface not found.
		return nil
	} else if volcengine.StringValue(output.Status) == eniTypes.ENIStatusInUse {
		// Interface is supposed to detach first.
		instanceID := volcengine.StringValue(output.DeviceId)
		err = c.detachNetworkInterface(ctx, instanceID, eniID)
		if err != nil {
			return fmt.Errorf("failed to datach interface %v, err: %w", eniID, err)
		}
	}

	input := &vpc.DeleteNetworkInterfaceInput{NetworkInterfaceId: volcengine.String(eniID)}
	c.limiter.Limit(ctx, "DeleteNetworkInterface")
	_, err = c.vpcClient.DeleteNetworkInterface(input)
	return err
}

func (c *Client) detachNetworkInterface(ctx context.Context, instanceID, eniID string) error {
	c.limiter.Limit(ctx, "DetachNetworkInterface")
	_, err := c.vpcClient.DetachNetworkInterface(&vpc.DetachNetworkInterfaceInput{
		NetworkInterfaceId: volcengine.String(eniID),
		InstanceId:         volcengine.String(instanceID),
	})
	if err != nil {
		return err
	}

	//Wait until ENI detached.
	err = wait.ExponentialBackoffWithContext(ctx, apiWriteBackoff, func(ctx context.Context) (done bool, err error) {
		c.limiter.Limit(ctx, "DescribeNetworkInterfacesAttribute")
		output, err := c.vpcClient.DescribeNetworkInterfaceAttributes(
			&vpc.DescribeNetworkInterfaceAttributesInput{
				NetworkInterfaceId: volcengine.String(eniID),
			})
		if err != nil {
			return false, err
		} else if volcengine.StringValue(output.Status) == eniTypes.ENIStatusAvailable {
			return true, nil
		}
		return true, nil
	})
	return nil
}

func (c *Client) assignPrivateIPAddresses(ctx context.Context, id string, count int) (*vpc.AssignPrivateIpAddressesOutput, error) {
	c.limiter.Limit(ctx, "AssignPrivateIPAddresses")
	return c.vpcClient.AssignPrivateIpAddresses(&vpc.AssignPrivateIpAddressesInput{
		NetworkInterfaceId:             volcengine.String(id),
		SecondaryPrivateIpAddressCount: volcengine.Int64(int64(count)),
	})
}

func (c *Client) unassignPrivateIPAddresses(ctx context.Context, id string, addresses []string) (*vpc.UnassignPrivateIpAddressesOutput, error) {
	c.limiter.Limit(ctx, "UnassignPrivateIPAddresses")
	return c.vpcClient.UnassignPrivateIpAddresses(&vpc.UnassignPrivateIpAddressesInput{
		NetworkInterfaceId: volcengine.String(id),
		PrivateIpAddress:   volcengine.StringSlice(addresses),
	})
}

func buildENITagsForCreateNetworkInterface(tags map[string]string) []*vpc.TagForCreateNetworkInterfaceInput {
	if tags == nil {
		return nil
	}
	eniTags := make([]*vpc.TagForCreateNetworkInterfaceInput, 0, len(tags))
	for k, v := range tags {
		eniTags = append(eniTags, &vpc.TagForCreateNetworkInterfaceInput{
			Key:   volcengine.String(k),
			Value: volcengine.String(v),
		})
	}
	return eniTags
}

func parseENITagsForDescribeNetworkInterfaces(iface *vpc.NetworkInterfaceSetForDescribeNetworkInterfacesOutput) map[string]string {
	return parseTagFromFilter(iface.Tags, func(output *vpc.TagForDescribeNetworkInterfacesOutput) (key string, value string) {
		return volcengine.StringValue(output.Key), volcengine.StringValue(output.Value)
	})
}
func parseENITagsForDescribeNetworkInterfaceAttr(iface *vpc.DescribeNetworkInterfaceAttributesOutput) map[string]string {
	return parseTagFromFilter(iface.Tags, func(output *vpc.TagForDescribeNetworkInterfaceAttributesOutput) (key string, value string) {
		return volcengine.StringValue(output.Key), volcengine.StringValue(output.Value)
	})
}

func parseSecurityGroupForDescribeSecurityGroups(sg *vpc.SecurityGroupForDescribeSecurityGroupsOutput) map[string]string {
	return parseTagFromFilter(sg.Tags, func(output *vpc.TagForDescribeSecurityGroupsOutput) (key string, value string) {
		return volcengine.StringValue(output.Key), volcengine.StringValue(output.Value)
	})
}

func parseTagFromFilter[T any](filters []T, kvReader func(T) (key string, value string)) map[string]string {
	if filters == nil {
		return nil
	}
	tags := make(map[string]string)
	for _, filter := range filters {
		key, value := kvReader(filter)
		tags[key] = value
	}
	return tags
}

func getPrivateIPSetsFromInterfacesOutput(output *vpc.PrivateIpSetsForDescribeNetworkInterfacesOutput) []eniTypes.PrivateIPSet {
	return parseIPSetFromOutput(output.PrivateIpSet, func(ipSet *vpc.PrivateIpSetForDescribeNetworkInterfacesOutput) eniTypes.PrivateIPSet {
		return eniTypes.PrivateIPSet{
			PrivateIpAddress: volcengine.StringValue(ipSet.PrivateIpAddress),
			Primary:          volcengine.BoolValue(ipSet.Primary),
		}
	})
}

func getPrivateIPSetsFromInterfacesAttrOutput(output *vpc.PrivateIpSetsForDescribeNetworkInterfaceAttributesOutput) []eniTypes.PrivateIPSet {
	return parseIPSetFromOutput(output.PrivateIpSet, func(ipSet *vpc.PrivateIpSetForDescribeNetworkInterfaceAttributesOutput) eniTypes.PrivateIPSet {
		return eniTypes.PrivateIPSet{
			PrivateIpAddress: volcengine.StringValue(ipSet.PrivateIpAddress),
			Primary:          volcengine.BoolValue(ipSet.Primary),
		}
	})
}

func parseIPSetFromOutput[T any](ipSets []T, parseIPSet func(T) eniTypes.PrivateIPSet) []eniTypes.PrivateIPSet {
	results := make([]eniTypes.PrivateIPSet, 0, 30)
	for _, ipSet := range ipSets {
		results = append(results, parseIPSet(ipSet))
	}
	return results
}

func parseENI(iface *eniTypes.ENI, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*eniTypes.ENI, error) {
	if v, ok := vpcs[iface.VPC.VPCID]; ok {
		iface.VPC.CIDRBlock = v.PrimaryCIDR
		iface.VPC.SecondaryCIDRBlocks = v.CIDRs
		//TODO: update ipv6 cidr block.
	} else {
		return nil, fmt.Errorf("vpc:%v not found for iface: %v", iface.VPC.VPCID, iface.NetworkInterfaceID)
	}

	if s, ok := subnets[iface.Subnet.SubnetID]; ok && s.CIDR != nil {
		iface.Subnet.CIDRBlock = s.CIDR.String()
		//TODO: update ipv6 cidr block.
	} else {
		return nil, fmt.Errorf("subnet:%v not found for iface: %v", iface.Subnet.SubnetID, iface.NetworkInterfaceID)
	}
	return iface, nil
}

func MergeTags(tagMaps ...map[string]string) map[string]string {
	tags := make(map[string]string)
	for _, m := range tagMaps {
		maps.Copy(tags, m)
	}
	return tags
}
