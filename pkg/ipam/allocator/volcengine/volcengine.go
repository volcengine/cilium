// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package volcengine

import (
	"context"
	"fmt"

	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	apiMetrics "github.com/cilium/cilium/pkg/api/metrics"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	ipamMetrics "github.com/cilium/cilium/pkg/ipam/metrics"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/volcengine/api"
	"github.com/cilium/cilium/pkg/volcengine/constant"
	"github.com/cilium/cilium/pkg/volcengine/eni"
	"github.com/cilium/cilium/pkg/volcengine/eni/limits"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-allocator-volcengine")

type AllocatorVolcengine struct {
	client    *api.Client
	eniGCTags map[string]string
}

func (a *AllocatorVolcengine) buildENIGarbageCollectionTags(ctx context.Context, cfg *operatorOption.OperatorConfig) {
	// Use user-provided tags if available
	if len(cfg.VolcengineENIGCTags) != 0 {
		a.eniGCTags = cfg.VolcengineENIGCTags
		return
	}

	// Use cilium managed garbage collection tag by default
	a.eniGCTags = map[string]string{
		defaults.ENIGarbageCollectionTagManagedName: defaults.ENIGarbageCollectionTagManagedValue,
		defaults.ENIGarbageCollectionTagClusterName: defaults.ENIGarbageCollectionTagClusterValue,
	}

	// Use cilium cluster name if available
	if clusterName := option.Config.ClusterName; clusterName != defaults.ClusterName {
		a.eniGCTags[defaults.ENIGarbageCollectionTagClusterName] = clusterName
	}
	// TODO:determine cluster tag if cluster-name not set
}

// Init sets up ENI limits based on given options
func (a *AllocatorVolcengine) Init(ctx context.Context) (err error) {
	metric := api.NewMetric()
	cfg := operatorOption.Config

	if cfg.EnableMetrics {
		metric = apiMetrics.NewPrometheusMetrics(metrics.Namespace, constant.Volcengine, operatorMetrics.Registry)
	}

	metadata := api.NewMetadata()

	project := "default"

	vpcID := cfg.VolcengineVPCID
	if len(vpcID) < 1 {
		if vpcID, err = metadata.VPCID(ctx); err != nil {
			log.Debugf("get vpc id from metadata of Volcengine failed: %v", err)
			return err
		}
	}
	regionID, err := metadata.Region(ctx)
	if err != nil {
		log.Debugf("get region id from metadata of Volcengine failed: %v", err)
		return err
	}
	//TODO: create credential form ak/sk and sts role
	var cred *credentials.Credentials

	cred = credentials.NewEnvCredentials()
	config := volcengine.NewConfig().WithRegion(regionID).
		WithExtraUserAgent(volcengine.String("cilium-operator")).
		WithDisableSSL(true).
		WithLogger(volcengine.NewDefaultLogger()) //TODO: unify logger
	config.WithCredentials(cred)

	eniCreationTags := cfg.VolcengineENITags
	if cfg.VolcengineENIGCInterval > 0 {
		a.eniGCTags = cfg.VolcengineENIGCTags
		eniCreationTags = api.MergeTags(eniCreationTags, a.eniGCTags)
	}

	a.client, err = api.NewClient(config, metric, cfg.IPAMAPIQPSLimit, cfg.IPAMAPIBurst,
		project, vpcID, cfg.IPAMInstanceTags, eniCreationTags, nil)
	if err != nil {
		log.Debugf("create client by %s.%s of Volcengine fialed: %v", regionID, vpcID, err)
		return err
	}

	if err = limits.UpdateFromAPI(ctx, a.client); err != nil {
		return fmt.Errorf("unable to update instance type to add adapter limits form Volcengine API: %w", err)
	}

	return nil
}

// Start kicks of ENI allocation, the initial connection to Volcengine
// APIs is done in a blocking manner, given that is successful, a controller is
// started to manage allocation based on CiliumNode custom resources
func (a *AllocatorVolcengine) Start(ctx context.Context, getterUpdater ipam.CiliumNodeGetterUpdater) (allocator.NodeEventHandler, error) {
	log.Info("Starting Volcengine ENI allocator...")

	var metric ipam.MetricsAPI = new(ipamMetrics.NoOpMetrics)
	cfg := operatorOption.Config
	if cfg.EnableMetrics {
		metric = ipamMetrics.NewPrometheusMetrics(metrics.Namespace, operatorMetrics.Registry)
	}

	im := eni.NewInstancesManager(a.client)
	nm, err := ipam.NewNodeManager(im, getterUpdater, metric, cfg.ParallelAllocWorkers, cfg.VolcengineReleaseExcessIPs, false)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Volcengine node manager: %w", err)
	}

	if cfg.VolcengineENIGCInterval > 0 {
		eni.StartENIGarbageCollector(ctx, a.client, eni.GarbageCollectionParams{
			RunInterval:    cfg.EndpointGCInterval,
			MaxPerInterval: defaults.ENIGarbageCollectionMaxPerInterval,
			ENITags:        a.eniGCTags,
		})
	}

	return nm, nm.Start(ctx)
}
