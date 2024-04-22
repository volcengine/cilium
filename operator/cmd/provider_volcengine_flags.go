// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_volcengine

package cmd

import (
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	flags := rootCmd.Flags()

	flags.Var(option.NewNamedMapOptions(operatorOption.VolcengineENITags, &operatorOption.Config.VolcengineENITags, nil),
		operatorOption.ENITags, "ENI tags in the form of k1=v1 (multiple k/v pairs can be passed by repeating the CLI flag)")
	option.BindEnv(Vp, operatorOption.ENITags)

	flags.Var(option.NewNamedMapOptions(operatorOption.VolcengineENIGCTags, &operatorOption.Config.VolcengineENIGCTags, nil),
		operatorOption.VolcengineENIGCTags, "Additional tags attached to Volcengine ENIs created by Cilium. Dangling ENIs with this tag will be garbage collected")
	option.BindEnv(Vp, operatorOption.VolcengineENIGCTags)

	flags.Duration(operatorOption.VolcengineENIGCInterval, defaults.ENIGarbageCollectionInterval,
		"Interval for garbage collection of unattached Volcengine ENIs. Set to 0 to disable")
	option.BindEnv(Vp, operatorOption.VolcengineENIGCInterval)

	flags.String(operatorOption.VolcengineVPCID, "", "Specific VPC ID for Volcengine ENI. If not set use same VPC as operator")
	option.BindEnv(Vp, operatorOption.VolcengineVPCID)

	flags.Bool(operatorOption.VolcengineReleaseExcessIPs, false, "Enable releasing excess free IP addresses from Volcengine ENI.")
	option.BindEnv(Vp, operatorOption.VolcengineReleaseExcessIPs)

	Vp.BindPFlags(flags)
}
