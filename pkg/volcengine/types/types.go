// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

// SecurityGroup represents a Volcengine security group
//
// +k8s:deepcopy-gen=true
type SecurityGroup struct {
	// ID is the ID of the security group
	ID string

	// VPCID is the VPC ID in which the security group resides
	VPCID string

	// ProjectName is the name of the project in which the security group resides
	ProjectName string

	// Tags are the tags associated with the security group
	Tags ipamTypes.Tags
}

type SecurityGroupMap map[string]*SecurityGroup
