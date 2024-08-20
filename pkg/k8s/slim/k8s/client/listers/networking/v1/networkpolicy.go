// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by lister-gen. DO NOT EDIT.

package v1

import (
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// NetworkPolicyLister helps list NetworkPolicies.
// All objects returned here must be treated as read-only.
type NetworkPolicyLister interface {
	// List lists all NetworkPolicies in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.NetworkPolicy, err error)
	// NetworkPolicies returns an object that can list and get NetworkPolicies.
	NetworkPolicies(namespace string) NetworkPolicyNamespaceLister
	NetworkPolicyListerExpansion
}

// networkPolicyLister implements the NetworkPolicyLister interface.
type networkPolicyLister struct {
	listers.ResourceIndexer[*v1.NetworkPolicy]
}

// NewNetworkPolicyLister returns a new NetworkPolicyLister.
func NewNetworkPolicyLister(indexer cache.Indexer) NetworkPolicyLister {
	return &networkPolicyLister{listers.New[*v1.NetworkPolicy](indexer, v1.Resource("networkpolicy"))}
}

// NetworkPolicies returns an object that can list and get NetworkPolicies.
func (s *networkPolicyLister) NetworkPolicies(namespace string) NetworkPolicyNamespaceLister {
	return networkPolicyNamespaceLister{listers.NewNamespaced[*v1.NetworkPolicy](s.ResourceIndexer, namespace)}
}

// NetworkPolicyNamespaceLister helps list and get NetworkPolicies.
// All objects returned here must be treated as read-only.
type NetworkPolicyNamespaceLister interface {
	// List lists all NetworkPolicies in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.NetworkPolicy, err error)
	// Get retrieves the NetworkPolicy from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1.NetworkPolicy, error)
	NetworkPolicyNamespaceListerExpansion
}

// networkPolicyNamespaceLister implements the NetworkPolicyNamespaceLister
// interface.
type networkPolicyNamespaceLister struct {
	listers.ResourceIndexer[*v1.NetworkPolicy]
}
