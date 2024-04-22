//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha2

import (
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/gateway-api/apis/v1beta1"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GRPCBackendRef) DeepCopyInto(out *GRPCBackendRef) {
	*out = *in
	in.BackendRef.DeepCopyInto(&out.BackendRef)
	if in.Filters != nil {
		in, out := &in.Filters, &out.Filters
		*out = make([]GRPCRouteFilter, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GRPCBackendRef.
func (in *GRPCBackendRef) DeepCopy() *GRPCBackendRef {
	if in == nil {
		return nil
	}
	out := new(GRPCBackendRef)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GRPCHeaderMatch) DeepCopyInto(out *GRPCHeaderMatch) {
	*out = *in
	if in.Type != nil {
		in, out := &in.Type, &out.Type
		*out = new(v1beta1.HeaderMatchType)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GRPCHeaderMatch.
func (in *GRPCHeaderMatch) DeepCopy() *GRPCHeaderMatch {
	if in == nil {
		return nil
	}
	out := new(GRPCHeaderMatch)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GRPCMethodMatch) DeepCopyInto(out *GRPCMethodMatch) {
	*out = *in
	if in.Type != nil {
		in, out := &in.Type, &out.Type
		*out = new(GRPCMethodMatchType)
		**out = **in
	}
	if in.Service != nil {
		in, out := &in.Service, &out.Service
		*out = new(string)
		**out = **in
	}
	if in.Method != nil {
		in, out := &in.Method, &out.Method
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GRPCMethodMatch.
func (in *GRPCMethodMatch) DeepCopy() *GRPCMethodMatch {
	if in == nil {
		return nil
	}
	out := new(GRPCMethodMatch)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GRPCRoute) DeepCopyInto(out *GRPCRoute) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GRPCRoute.
func (in *GRPCRoute) DeepCopy() *GRPCRoute {
	if in == nil {
		return nil
	}
	out := new(GRPCRoute)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *GRPCRoute) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GRPCRouteFilter) DeepCopyInto(out *GRPCRouteFilter) {
	*out = *in
	if in.RequestHeaderModifier != nil {
		in, out := &in.RequestHeaderModifier, &out.RequestHeaderModifier
		*out = new(v1beta1.HTTPHeaderFilter)
		(*in).DeepCopyInto(*out)
	}
	if in.ResponseHeaderModifier != nil {
		in, out := &in.ResponseHeaderModifier, &out.ResponseHeaderModifier
		*out = new(v1beta1.HTTPHeaderFilter)
		(*in).DeepCopyInto(*out)
	}
	if in.RequestMirror != nil {
		in, out := &in.RequestMirror, &out.RequestMirror
		*out = new(v1beta1.HTTPRequestMirrorFilter)
		(*in).DeepCopyInto(*out)
	}
	if in.ExtensionRef != nil {
		in, out := &in.ExtensionRef, &out.ExtensionRef
		*out = new(v1beta1.LocalObjectReference)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GRPCRouteFilter.
func (in *GRPCRouteFilter) DeepCopy() *GRPCRouteFilter {
	if in == nil {
		return nil
	}
	out := new(GRPCRouteFilter)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GRPCRouteList) DeepCopyInto(out *GRPCRouteList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]GRPCRoute, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GRPCRouteList.
func (in *GRPCRouteList) DeepCopy() *GRPCRouteList {
	if in == nil {
		return nil
	}
	out := new(GRPCRouteList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *GRPCRouteList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GRPCRouteMatch) DeepCopyInto(out *GRPCRouteMatch) {
	*out = *in
	if in.Method != nil {
		in, out := &in.Method, &out.Method
		*out = new(GRPCMethodMatch)
		(*in).DeepCopyInto(*out)
	}
	if in.Headers != nil {
		in, out := &in.Headers, &out.Headers
		*out = make([]GRPCHeaderMatch, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GRPCRouteMatch.
func (in *GRPCRouteMatch) DeepCopy() *GRPCRouteMatch {
	if in == nil {
		return nil
	}
	out := new(GRPCRouteMatch)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GRPCRouteRule) DeepCopyInto(out *GRPCRouteRule) {
	*out = *in
	if in.Matches != nil {
		in, out := &in.Matches, &out.Matches
		*out = make([]GRPCRouteMatch, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Filters != nil {
		in, out := &in.Filters, &out.Filters
		*out = make([]GRPCRouteFilter, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.BackendRefs != nil {
		in, out := &in.BackendRefs, &out.BackendRefs
		*out = make([]GRPCBackendRef, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GRPCRouteRule.
func (in *GRPCRouteRule) DeepCopy() *GRPCRouteRule {
	if in == nil {
		return nil
	}
	out := new(GRPCRouteRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GRPCRouteSpec) DeepCopyInto(out *GRPCRouteSpec) {
	*out = *in
	in.CommonRouteSpec.DeepCopyInto(&out.CommonRouteSpec)
	if in.Hostnames != nil {
		in, out := &in.Hostnames, &out.Hostnames
		*out = make([]v1beta1.Hostname, len(*in))
		copy(*out, *in)
	}
	if in.Rules != nil {
		in, out := &in.Rules, &out.Rules
		*out = make([]GRPCRouteRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GRPCRouteSpec.
func (in *GRPCRouteSpec) DeepCopy() *GRPCRouteSpec {
	if in == nil {
		return nil
	}
	out := new(GRPCRouteSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GRPCRouteStatus) DeepCopyInto(out *GRPCRouteStatus) {
	*out = *in
	in.RouteStatus.DeepCopyInto(&out.RouteStatus)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GRPCRouteStatus.
func (in *GRPCRouteStatus) DeepCopy() *GRPCRouteStatus {
	if in == nil {
		return nil
	}
	out := new(GRPCRouteStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Gateway) DeepCopyInto(out *Gateway) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Gateway.
func (in *Gateway) DeepCopy() *Gateway {
	if in == nil {
		return nil
	}
	out := new(Gateway)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Gateway) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GatewayClass) DeepCopyInto(out *GatewayClass) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GatewayClass.
func (in *GatewayClass) DeepCopy() *GatewayClass {
	if in == nil {
		return nil
	}
	out := new(GatewayClass)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *GatewayClass) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GatewayClassList) DeepCopyInto(out *GatewayClassList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]GatewayClass, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GatewayClassList.
func (in *GatewayClassList) DeepCopy() *GatewayClassList {
	if in == nil {
		return nil
	}
	out := new(GatewayClassList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *GatewayClassList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GatewayList) DeepCopyInto(out *GatewayList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Gateway, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GatewayList.
func (in *GatewayList) DeepCopy() *GatewayList {
	if in == nil {
		return nil
	}
	out := new(GatewayList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *GatewayList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HTTPRoute) DeepCopyInto(out *HTTPRoute) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HTTPRoute.
func (in *HTTPRoute) DeepCopy() *HTTPRoute {
	if in == nil {
		return nil
	}
	out := new(HTTPRoute)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *HTTPRoute) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HTTPRouteList) DeepCopyInto(out *HTTPRouteList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]HTTPRoute, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HTTPRouteList.
func (in *HTTPRouteList) DeepCopy() *HTTPRouteList {
	if in == nil {
		return nil
	}
	out := new(HTTPRouteList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *HTTPRouteList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyTargetReference) DeepCopyInto(out *PolicyTargetReference) {
	*out = *in
	if in.Namespace != nil {
		in, out := &in.Namespace, &out.Namespace
		*out = new(v1beta1.Namespace)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyTargetReference.
func (in *PolicyTargetReference) DeepCopy() *PolicyTargetReference {
	if in == nil {
		return nil
	}
	out := new(PolicyTargetReference)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ReferenceGrant) DeepCopyInto(out *ReferenceGrant) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ReferenceGrant.
func (in *ReferenceGrant) DeepCopy() *ReferenceGrant {
	if in == nil {
		return nil
	}
	out := new(ReferenceGrant)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ReferenceGrant) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ReferenceGrantList) DeepCopyInto(out *ReferenceGrantList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ReferenceGrant, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ReferenceGrantList.
func (in *ReferenceGrantList) DeepCopy() *ReferenceGrantList {
	if in == nil {
		return nil
	}
	out := new(ReferenceGrantList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ReferenceGrantList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TCPRoute) DeepCopyInto(out *TCPRoute) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TCPRoute.
func (in *TCPRoute) DeepCopy() *TCPRoute {
	if in == nil {
		return nil
	}
	out := new(TCPRoute)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TCPRoute) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TCPRouteList) DeepCopyInto(out *TCPRouteList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]TCPRoute, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TCPRouteList.
func (in *TCPRouteList) DeepCopy() *TCPRouteList {
	if in == nil {
		return nil
	}
	out := new(TCPRouteList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TCPRouteList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TCPRouteRule) DeepCopyInto(out *TCPRouteRule) {
	*out = *in
	if in.BackendRefs != nil {
		in, out := &in.BackendRefs, &out.BackendRefs
		*out = make([]v1beta1.BackendRef, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TCPRouteRule.
func (in *TCPRouteRule) DeepCopy() *TCPRouteRule {
	if in == nil {
		return nil
	}
	out := new(TCPRouteRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TCPRouteSpec) DeepCopyInto(out *TCPRouteSpec) {
	*out = *in
	in.CommonRouteSpec.DeepCopyInto(&out.CommonRouteSpec)
	if in.Rules != nil {
		in, out := &in.Rules, &out.Rules
		*out = make([]TCPRouteRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TCPRouteSpec.
func (in *TCPRouteSpec) DeepCopy() *TCPRouteSpec {
	if in == nil {
		return nil
	}
	out := new(TCPRouteSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TCPRouteStatus) DeepCopyInto(out *TCPRouteStatus) {
	*out = *in
	in.RouteStatus.DeepCopyInto(&out.RouteStatus)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TCPRouteStatus.
func (in *TCPRouteStatus) DeepCopy() *TCPRouteStatus {
	if in == nil {
		return nil
	}
	out := new(TCPRouteStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLSRoute) DeepCopyInto(out *TLSRoute) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLSRoute.
func (in *TLSRoute) DeepCopy() *TLSRoute {
	if in == nil {
		return nil
	}
	out := new(TLSRoute)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TLSRoute) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLSRouteList) DeepCopyInto(out *TLSRouteList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]TLSRoute, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLSRouteList.
func (in *TLSRouteList) DeepCopy() *TLSRouteList {
	if in == nil {
		return nil
	}
	out := new(TLSRouteList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *TLSRouteList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLSRouteRule) DeepCopyInto(out *TLSRouteRule) {
	*out = *in
	if in.BackendRefs != nil {
		in, out := &in.BackendRefs, &out.BackendRefs
		*out = make([]v1beta1.BackendRef, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLSRouteRule.
func (in *TLSRouteRule) DeepCopy() *TLSRouteRule {
	if in == nil {
		return nil
	}
	out := new(TLSRouteRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLSRouteSpec) DeepCopyInto(out *TLSRouteSpec) {
	*out = *in
	in.CommonRouteSpec.DeepCopyInto(&out.CommonRouteSpec)
	if in.Hostnames != nil {
		in, out := &in.Hostnames, &out.Hostnames
		*out = make([]v1beta1.Hostname, len(*in))
		copy(*out, *in)
	}
	if in.Rules != nil {
		in, out := &in.Rules, &out.Rules
		*out = make([]TLSRouteRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLSRouteSpec.
func (in *TLSRouteSpec) DeepCopy() *TLSRouteSpec {
	if in == nil {
		return nil
	}
	out := new(TLSRouteSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TLSRouteStatus) DeepCopyInto(out *TLSRouteStatus) {
	*out = *in
	in.RouteStatus.DeepCopyInto(&out.RouteStatus)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TLSRouteStatus.
func (in *TLSRouteStatus) DeepCopy() *TLSRouteStatus {
	if in == nil {
		return nil
	}
	out := new(TLSRouteStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UDPRoute) DeepCopyInto(out *UDPRoute) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UDPRoute.
func (in *UDPRoute) DeepCopy() *UDPRoute {
	if in == nil {
		return nil
	}
	out := new(UDPRoute)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *UDPRoute) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UDPRouteList) DeepCopyInto(out *UDPRouteList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]UDPRoute, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UDPRouteList.
func (in *UDPRouteList) DeepCopy() *UDPRouteList {
	if in == nil {
		return nil
	}
	out := new(UDPRouteList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *UDPRouteList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UDPRouteRule) DeepCopyInto(out *UDPRouteRule) {
	*out = *in
	if in.BackendRefs != nil {
		in, out := &in.BackendRefs, &out.BackendRefs
		*out = make([]v1beta1.BackendRef, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UDPRouteRule.
func (in *UDPRouteRule) DeepCopy() *UDPRouteRule {
	if in == nil {
		return nil
	}
	out := new(UDPRouteRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UDPRouteSpec) DeepCopyInto(out *UDPRouteSpec) {
	*out = *in
	in.CommonRouteSpec.DeepCopyInto(&out.CommonRouteSpec)
	if in.Rules != nil {
		in, out := &in.Rules, &out.Rules
		*out = make([]UDPRouteRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UDPRouteSpec.
func (in *UDPRouteSpec) DeepCopy() *UDPRouteSpec {
	if in == nil {
		return nil
	}
	out := new(UDPRouteSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UDPRouteStatus) DeepCopyInto(out *UDPRouteStatus) {
	*out = *in
	in.RouteStatus.DeepCopyInto(&out.RouteStatus)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UDPRouteStatus.
func (in *UDPRouteStatus) DeepCopy() *UDPRouteStatus {
	if in == nil {
		return nil
	}
	out := new(UDPRouteStatus)
	in.DeepCopyInto(out)
	return out
}
