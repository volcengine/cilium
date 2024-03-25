package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/cilium/cilium/pkg/safeio"
	"github.com/cilium/cilium/pkg/time"
)

const (
	DefaultURL     = "http://100.96.0.96/latest/"
	DefaultTimeout = 10 * time.Second
)

type Metadata struct {
	metadataEndpoint string
	httpClient       *http.Client
}

// InterfaceInfo represents NIC information that metadata service would return
type InterfaceInfo struct {
	NetworkInterfaceID string `json:"NetworkInterfaceId,omitempty"`
	PrimaryIPAddress   string `json:"PrimaryIpAddress,omitempty"`
	Gateway            string `json:"Gateway,omitempty"`
	SubnetID           string `json:"SubnetId,omitempty"`
	SubnetCidrBlock    string `json:"SubnetCidrBlock,omitempty"`
	PrivateIpv4s       string `json:"PrivateIpv4s,omitempty"`
}

func NewMetadataWithConfig(url string, timeout time.Duration) *Metadata {
	return &Metadata{
		metadataEndpoint: url,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// NewMetadata creates a volcengine metadata client with default url: "http://100.96.0.96/volcstack/latest/"
// and default timeout 10 seconds.
func NewMetadata() *Metadata {
	return NewMetadataWithConfig(DefaultURL, DefaultTimeout)
}

// getMetadata get information from metadata by path.
func (client *Metadata) getMetadata(ctx context.Context, path string) ([]byte, error) {
	url := fmt.Sprintf("%s/%s", client.metadataEndpoint, path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http request %v err: %w", *req, err)
	}

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request to metadata service request: %v, error: %w", *req, err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request metadata %v code: %d", *req, resp.StatusCode)

	}
	var respBytes []byte
	if respBytes, err = safeio.ReadAllLimit(resp.Body, safeio.MB); err != nil {
		return nil, fmt.Errorf("failed to read response error %w", err)
	}
	return respBytes, nil
}

// Region returns region id of instance, eg: cn-beijing.
func (client *Metadata) Region(ctx context.Context) (string, error) {
	data, err := client.getMetadata(ctx, "region_id")
	if err != nil {
		return "", fmt.Errorf("failed to get region id: %w", err)
	}
	return string(data), err
}

// AvailabilityZone returns availability zone id of instance, eg: cn-beijing-a.
func (client *Metadata) AvailabilityZone(ctx context.Context) (string, error) {
	data, err := client.getMetadata(ctx, "availability_zone")
	if err != nil {
		return "", fmt.Errorf("failed to get az id: %w", err)
	}
	return string(data), err
}

// InstanceID returns instance id.
func (client *Metadata) InstanceID(ctx context.Context) (string, error) {
	data, err := client.getMetadata(ctx, "instance_id")
	if err != nil {
		return "", fmt.Errorf("failed to get instance id: %w", err)
	}
	return string(data), err
}

// InstanceType returns instance type id, eg: ecs.g1ie.xlarge.
func (client *Metadata) InstanceType(ctx context.Context) (string, error) {
	data, err := client.getMetadata(ctx, "instance_type_id")
	if err != nil {
		return "", fmt.Errorf("failed to get instance type: %w", err)
	}
	return string(data), err
}

// VPCID returns vpc id of instance's primary interface.
func (client *Metadata) VPCID(ctx context.Context) (string, error) {
	data, err := client.getMetadata(ctx, "vpc_id")
	if err != nil {
		return "", fmt.Errorf("failed to get vpc_id: %w", err)
	}
	return string(data), err
}

// VPCCidrBlock returns CIDR block of instance's primary interface， eg: 172.16.0.0/12.
func (client *Metadata) VPCCidrBlock(ctx context.Context) (string, error) {
	data, err := client.getMetadata(ctx, "vpc_cidr_block")
	if err != nil {
		return "", fmt.Errorf("failed to get vpc_cidr: %w", err)
	}
	return string(data), err
}

// InterfaceMacAddresses  returns a list of interfaces' mac address.
func (client *Metadata) InterfaceMacAddresses(ctx context.Context) ([]string, error) {
	data, err := client.getMetadata(ctx, "network/interfaces/macs")
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}
	return strings.Split(string(data), "\n"), nil
}

// PrimaryInterfaceMacAddress returns primary interface's mac address.
func (client *Metadata) PrimaryInterfaceMacAddress(ctx context.Context) (string, error) {
	data, err := client.getMetadata(ctx, "mac")
	if err != nil {
		return "", fmt.Errorf("failed to get primary interface: %w", err)
	}
	return string(data), err
}

// PrimaryIP returns primary interface's ip address.
func (client *Metadata) PrimaryIP(ctx context.Context, mac string) (string, error) {
	addr, err := client.getMetadata(ctx, fmt.Sprintf("network/interfaces/macs/%s/primary_ip_address", mac))
	if err != nil {
		return "", fmt.Errorf("failed to get interface %v primary ip: %w", mac, err)
	}
	return string(addr), nil
}

// GatewayIP returns gateway ip of interface.
func (client *Metadata) GatewayIP(ctx context.Context, mac string) (string, error) {
	addr, err := client.getMetadata(ctx, fmt.Sprintf("network/interfaces/macs/%s/gateway", mac))
	if err != nil {
		return "", fmt.Errorf("failed to get gateway ip for interface %v: %w", mac, err)
	}
	return string(addr), err
}

// InterfaceInfo returns network information of interface.
func (client *Metadata) InterfaceInfo(ctx context.Context, mac string) (*InterfaceInfo, error) {
	data, err := client.getMetadata(ctx, fmt.Sprintf("network/interfaces/macs/%s/network_info", mac))
	if err != nil {
		return nil, err
	}
	var nicInfo InterfaceInfo
	err = json.Unmarshal(data, &nicInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to get network inteface %v information: %w", mac, err)
	}
	return &nicInfo, err
}

func (client *Metadata) GetSTSCredential(ctx context.Context, role string) (string, error) {
	if len(role) == 0 {
		return "", fmt.Errorf("invalid role name")
	}
	data, err := client.getMetadata(ctx, "iam/security_credentials"+role)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
