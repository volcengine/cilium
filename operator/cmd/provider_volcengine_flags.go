// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_volcengine

package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	FlagsHooks = append(FlagsHooks, new(volcengineFlagsHooks))
}

type volcengineFlagsHooks struct{}

func (h *volcengineFlagsHooks) RegisterProviderFlag(cmd *cobra.Command, vp *viper.Viper) {
	flags := cmd.Flags()

	flags.Var(option.NewNamedMapOptions(operatorOption.VolcengineENIGCTags, &operatorOption.Config.VolcengineENIGCTags, nil),
		operatorOption.VolcengineENIGCTags, "Additional tags attached to Volcengine ENIs created by Cilium. Dangling ENIs with this tag will be garbage collected")
	option.BindEnv(vp, operatorOption.VolcengineENIGCTags)

	flags.Duration(operatorOption.VolcengineENIGCInterval, defaults.ENIGarbageCollectionInterval,
		"Interval for garbage collection of unattached Volcengine ENIs. Set to 0 to disable")
	option.BindEnv(vp, operatorOption.VolcengineENIGCInterval)

	flags.String(operatorOption.VolcengineVPCID, "", "Specific VPC ID for Volcengine ENI. If not set use same VPC as operator")
	option.BindEnv(vp, operatorOption.VolcengineVPCID)

	flags.Bool(operatorOption.VolcengineReleaseExcessIPs, false, "Enable releasing excess free IP addresses from Volcengine ENI.")
	option.BindEnv(vp, operatorOption.VolcengineReleaseExcessIPs)

	vp.BindEnv(flags)
}
