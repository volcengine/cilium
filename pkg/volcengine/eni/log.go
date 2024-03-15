// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/volcengine/constant"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, constant.Volcengine)
)
