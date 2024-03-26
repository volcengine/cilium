package eni

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/volcengine/api"
)

const gcENIControllerName = "ipam-eni-gc"

var (
	controllerManager = controller.NewManager()

	gcENIControllerGroup = controller.NewGroup(gcENIControllerName)
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

func StartENIGarbageCollector(ctx context.Context, api api.VolcengineAPI, params GarbageCollectionParams) {
	log.Info("Starting to garbage collect detached ENIs")

	var enisMarkedForDeletion []string
	controllerManager.UpdateController(gcENIControllerName, controller.ControllerParams{
		Group: gcENIControllerGroup,
		DoFunc: func(ctx context.Context) error {
			var err error
			enisMarkedForDeletion, err = api.GetDetachedNetworkInterfaces(ctx, params.ENITags, params.RunInterval)
			if err != nil {
				return fmt.Errorf("failed to fetch available interfaces: %w", err)
			}

			if numENIs := len(enisMarkedForDeletion); numENIs > 0 {
				log.WithField("numInterfaces", numENIs).
					Debug("Marked unattached interfaces for garbage collection")
			}

			for _, eniID := range enisMarkedForDeletion {
				log.WithField("eniID", eniID).Debug("Garbage collecting ENI")
				err := api.DeleteNetworkInterface(ctx, eniID)
				if err != nil {
					log.WithError(err).Debug("Failed to garbage collect ENI")
				}
			}

			return nil
		},
		RunInterval: params.RunInterval,
		Context:     ctx,
	})

}
