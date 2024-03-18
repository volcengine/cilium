// Code generated by volcengine with private/model/cli/gen-api/main.go. DO NOT EDIT.

package ecs

import (
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/request"
	"github.com/volcengine/volcengine-go-sdk/volcengine/response"
	"github.com/volcengine/volcengine-go-sdk/volcengine/volcengineutil"
)

const opDeleteDedicatedHostClusterCommon = "DeleteDedicatedHostCluster"

// DeleteDedicatedHostClusterCommonRequest generates a "volcengine/request.Request" representing the
// client's request for the DeleteDedicatedHostClusterCommon operation. The "output" return
// value will be populated with the DeleteDedicatedHostClusterCommon request's response once the request completes
// successfully.
//
// Use "Send" method on the returned DeleteDedicatedHostClusterCommon Request to send the API call to the service.
// the "output" return value is not valid until after DeleteDedicatedHostClusterCommon Send returns without error.
//
// See DeleteDedicatedHostClusterCommon for more information on using the DeleteDedicatedHostClusterCommon
// API call, and error handling.
//
//	// Example sending a request using the DeleteDedicatedHostClusterCommonRequest method.
//	req, resp := client.DeleteDedicatedHostClusterCommonRequest(params)
//
//	err := req.Send()
//	if err == nil { // resp is now filled
//	    fmt.Println(resp)
//	}
func (c *ECS) DeleteDedicatedHostClusterCommonRequest(input *map[string]interface{}) (req *request.Request, output *map[string]interface{}) {
	op := &request.Operation{
		Name:       opDeleteDedicatedHostClusterCommon,
		HTTPMethod: "GET",
		HTTPPath:   "/",
	}

	if input == nil {
		input = &map[string]interface{}{}
	}

	output = &map[string]interface{}{}
	req = c.newRequest(op, input, output)

	return
}

// DeleteDedicatedHostClusterCommon API operation for ECS.
//
// Returns volcengineerr.Error for service API and SDK errors. Use runtime type assertions
// with volcengineerr.Error's Code and Message methods to get detailed information about
// the error.
//
// See the VOLCENGINE API reference guide for ECS's
// API operation DeleteDedicatedHostClusterCommon for usage and error information.
func (c *ECS) DeleteDedicatedHostClusterCommon(input *map[string]interface{}) (*map[string]interface{}, error) {
	req, out := c.DeleteDedicatedHostClusterCommonRequest(input)
	return out, req.Send()
}

// DeleteDedicatedHostClusterCommonWithContext is the same as DeleteDedicatedHostClusterCommon with the addition of
// the ability to pass a context and additional request options.
//
// See DeleteDedicatedHostClusterCommon for details on how to use this API operation.
//
// The context must be non-nil and will be used for request cancellation. If the context is nil a panic will occur.
// In the future the SDK may create sub-contexts for http.Requests. See https://golang.org/pkg/context/
// for more information on using Contexts.
func (c *ECS) DeleteDedicatedHostClusterCommonWithContext(ctx volcengine.Context, input *map[string]interface{}, opts ...request.Option) (*map[string]interface{}, error) {
	req, out := c.DeleteDedicatedHostClusterCommonRequest(input)
	req.SetContext(ctx)
	req.ApplyOptions(opts...)
	return out, req.Send()
}

const opDeleteDedicatedHostCluster = "DeleteDedicatedHostCluster"

// DeleteDedicatedHostClusterRequest generates a "volcengine/request.Request" representing the
// client's request for the DeleteDedicatedHostCluster operation. The "output" return
// value will be populated with the DeleteDedicatedHostClusterCommon request's response once the request completes
// successfully.
//
// Use "Send" method on the returned DeleteDedicatedHostClusterCommon Request to send the API call to the service.
// the "output" return value is not valid until after DeleteDedicatedHostClusterCommon Send returns without error.
//
// See DeleteDedicatedHostCluster for more information on using the DeleteDedicatedHostCluster
// API call, and error handling.
//
//	// Example sending a request using the DeleteDedicatedHostClusterRequest method.
//	req, resp := client.DeleteDedicatedHostClusterRequest(params)
//
//	err := req.Send()
//	if err == nil { // resp is now filled
//	    fmt.Println(resp)
//	}
func (c *ECS) DeleteDedicatedHostClusterRequest(input *DeleteDedicatedHostClusterInput) (req *request.Request, output *DeleteDedicatedHostClusterOutput) {
	op := &request.Operation{
		Name:       opDeleteDedicatedHostCluster,
		HTTPMethod: "GET",
		HTTPPath:   "/",
	}

	if input == nil {
		input = &DeleteDedicatedHostClusterInput{}
	}

	output = &DeleteDedicatedHostClusterOutput{}
	req = c.newRequest(op, input, output)

	return
}

// DeleteDedicatedHostCluster API operation for ECS.
//
// Returns volcengineerr.Error for service API and SDK errors. Use runtime type assertions
// with volcengineerr.Error's Code and Message methods to get detailed information about
// the error.
//
// See the VOLCENGINE API reference guide for ECS's
// API operation DeleteDedicatedHostCluster for usage and error information.
func (c *ECS) DeleteDedicatedHostCluster(input *DeleteDedicatedHostClusterInput) (*DeleteDedicatedHostClusterOutput, error) {
	req, out := c.DeleteDedicatedHostClusterRequest(input)
	return out, req.Send()
}

// DeleteDedicatedHostClusterWithContext is the same as DeleteDedicatedHostCluster with the addition of
// the ability to pass a context and additional request options.
//
// See DeleteDedicatedHostCluster for details on how to use this API operation.
//
// The context must be non-nil and will be used for request cancellation. Ifthe context is nil a panic will occur.
// In the future the SDK may create sub-contexts for http.Requests. See https://golang.org/pkg/context/
// for more information on using Contexts.
func (c *ECS) DeleteDedicatedHostClusterWithContext(ctx volcengine.Context, input *DeleteDedicatedHostClusterInput, opts ...request.Option) (*DeleteDedicatedHostClusterOutput, error) {
	req, out := c.DeleteDedicatedHostClusterRequest(input)
	req.SetContext(ctx)
	req.ApplyOptions(opts...)
	return out, req.Send()
}

type DeleteDedicatedHostClusterInput struct {
	_ struct{} `type:"structure"`

	ClientToken *string `type:"string"`

	DedicatedHostClusterId *string `type:"string"`
}

// String returns the string representation
func (s DeleteDedicatedHostClusterInput) String() string {
	return volcengineutil.Prettify(s)
}

// GoString returns the string representation
func (s DeleteDedicatedHostClusterInput) GoString() string {
	return s.String()
}

// SetClientToken sets the ClientToken field's value.
func (s *DeleteDedicatedHostClusterInput) SetClientToken(v string) *DeleteDedicatedHostClusterInput {
	s.ClientToken = &v
	return s
}

// SetDedicatedHostClusterId sets the DedicatedHostClusterId field's value.
func (s *DeleteDedicatedHostClusterInput) SetDedicatedHostClusterId(v string) *DeleteDedicatedHostClusterInput {
	s.DedicatedHostClusterId = &v
	return s
}

type DeleteDedicatedHostClusterOutput struct {
	_ struct{} `type:"structure"`

	Metadata *response.ResponseMetadata
}

// String returns the string representation
func (s DeleteDedicatedHostClusterOutput) String() string {
	return volcengineutil.Prettify(s)
}

// GoString returns the string representation
func (s DeleteDedicatedHostClusterOutput) GoString() string {
	return s.String()
}
