// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeNamespaces implements NamespaceInterface
type FakeNamespaces struct {
	Fake *FakeCoreV1
}

var namespacesResource = v1.SchemeGroupVersion.WithResource("namespaces")

var namespacesKind = v1.SchemeGroupVersion.WithKind("Namespace")

// Get takes name of the namespace, and returns the corresponding namespace object, and an error if there is any.
func (c *FakeNamespaces) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.Namespace, err error) {
	emptyResult := &v1.Namespace{}
	obj, err := c.Fake.
		Invokes(testing.NewRootGetActionWithOptions(namespacesResource, name, options), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.Namespace), err
}

// List takes label and field selectors, and returns the list of Namespaces that match those selectors.
func (c *FakeNamespaces) List(ctx context.Context, opts metav1.ListOptions) (result *v1.NamespaceList, err error) {
	emptyResult := &v1.NamespaceList{}
	obj, err := c.Fake.
		Invokes(testing.NewRootListActionWithOptions(namespacesResource, namespacesKind, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.NamespaceList{ListMeta: obj.(*v1.NamespaceList).ListMeta}
	for _, item := range obj.(*v1.NamespaceList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested namespaces.
func (c *FakeNamespaces) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchActionWithOptions(namespacesResource, opts))
}

// Create takes the representation of a namespace and creates it.  Returns the server's representation of the namespace, and an error, if there is any.
func (c *FakeNamespaces) Create(ctx context.Context, namespace *v1.Namespace, opts metav1.CreateOptions) (result *v1.Namespace, err error) {
	emptyResult := &v1.Namespace{}
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateActionWithOptions(namespacesResource, namespace, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.Namespace), err
}

// Update takes the representation of a namespace and updates it. Returns the server's representation of the namespace, and an error, if there is any.
func (c *FakeNamespaces) Update(ctx context.Context, namespace *v1.Namespace, opts metav1.UpdateOptions) (result *v1.Namespace, err error) {
	emptyResult := &v1.Namespace{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateActionWithOptions(namespacesResource, namespace, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.Namespace), err
}

// Delete takes name of the namespace and deletes it. Returns an error if one occurs.
func (c *FakeNamespaces) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(namespacesResource, name, opts), &v1.Namespace{})
	return err
}

// Patch applies the patch and returns the patched namespace.
func (c *FakeNamespaces) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.Namespace, err error) {
	emptyResult := &v1.Namespace{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(namespacesResource, name, pt, data, opts, subresources...), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.Namespace), err
}
