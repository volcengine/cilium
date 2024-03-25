// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package limits

import (
	"context"

	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/volcengine/api"
)

// limits contains limits for adapter count and addresses. The mappings will be
// updated from agent configuration at bootstrap time.
var limits = struct {
	lock.RWMutex

	m map[string]ipamTypes.Limits
}{
	m: map[string]ipamTypes.Limits{},
}

// Get returns the instance limits of a particular instance type.
func Get(instanceType string) (limit ipamTypes.Limits, ok bool) {
	limits.RLock()
	limit, ok = limits.m[instanceType]
	limits.RUnlock()
	return
}

func UpdateFromAPI(ctx context.Context, ec2 api.Client) error {
	return nil
}
