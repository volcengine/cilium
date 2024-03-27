// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"context"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/volcengine/constant"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, constant.Volcengine)
)

func logs(ctx context.Context, module, method string) func() {
	log.Debugf("enter %s.%s...", module, method)
	return func() { log.Debugf("leave %s.%s...", module, method) }
}
