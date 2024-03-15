package eni

import (
	"context"
	"time"

	"github.com/cilium/cilium/pkg/ipam/types"
)

type GarbageCollectionParams struct {
	// RunInterval is both the GC interval and also the minimum amount of time
	// an ENI has to be available before it is garbage collected
	RunInterval time.Duration
	// MaxPerInterval is the maximum number of ENIs which are deleted in a
	// single interval
	MaxPerInterval int32
	// ENITags is used to only garbage collect ENIs with this set of tags
	ENITags types.Tags
}

func StartENIGarbageCollector(ctx context.Context, api VolcengineAPI, params GarbageCollectionParams) {
	log.Info("Starting to garbage collect detached ENIs")
}
