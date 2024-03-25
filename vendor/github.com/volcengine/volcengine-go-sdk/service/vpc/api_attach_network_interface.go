// Code generated by volcengine with private/model/cli/gen-api/main.go. DO NOT EDIT.

package vpc

import (
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/request"
	"github.com/volcengine/volcengine-go-sdk/volcengine/response"
	"github.com/volcengine/volcengine-go-sdk/volcengine/volcengineutil"
)

const opAttachNetworkInterfaceCommon = "AttachNetworkInterface"

// AttachNetworkInterfaceCommonRequest generates a "volcengine/request.Request" representing the
// client's request for the AttachNetworkInterfaceCommon operation. The "output" return
// value will be populated with the AttachNetworkInterfaceCommon request's response once the request completes
// successfully.
//
// Use "Send" method on the returned AttachNetworkInterfaceCommon Request to send the API call to the service.
// the "output" return value is not valid until after AttachNetworkInterfaceCommon Send returns without error.
//
// See AttachNetworkInterfaceCommon for more information on using the AttachNetworkInterfaceCommon
// API call, and error handling.
//
//    // Example sending a request using the AttachNetworkInterfaceCommonRequest method.
//    req, resp := client.AttachNetworkInterfaceCommonRequest(params)
//
//    err := req.Send()
//    if err == nil { // resp is now filled
//        fmt.Println(resp)
//    }
func (c *VPC) AttachNetworkInterfaceCommonRequest(input *map[string]interface{}) (req *request.Request, output *map[string]interface{}) {
	op := &request.Operation{
		Name:       opAttachNetworkInterfaceCommon,
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

// AttachNetworkInterfaceCommon API operation for VPC.
//
// Returns volcengineerr.Error for service API and SDK errors. Use runtime type assertions
// with volcengineerr.Error's Code and Message methods to get detailed information about
// the error.
//
// See the VOLCENGINE API reference guide for VPC's
// API operation AttachNetworkInterfaceCommon for usage and error information.
func (c *VPC) AttachNetworkInterfaceCommon(input *map[string]interface{}) (*map[string]interface{}, error) {
	req, out := c.AttachNetworkInterfaceCommonRequest(input)
	return out, req.Send()
}

// AttachNetworkInterfaceCommonWithContext is the same as AttachNetworkInterfaceCommon with the addition of
// the ability to pass a context and additional request options.
//
// See AttachNetworkInterfaceCommon for details on how to use this API operation.
//
// The context must be non-nil and will be used for request cancellation. If the context is nil a panic will occur.
// In the future the SDK may create sub-contexts for http.Requests. See https://golang.org/pkg/context/
// for more information on using Contexts.
func (c *VPC) AttachNetworkInterfaceCommonWithContext(ctx volcengine.Context, input *map[string]interface{}, opts ...request.Option) (*map[string]interface{}, error) {
	req, out := c.AttachNetworkInterfaceCommonRequest(input)
	req.SetContext(ctx)
	req.ApplyOptions(opts...)
	return out, req.Send()
}

const opAttachNetworkInterface = "AttachNetworkInterface"

// AttachNetworkInterfaceRequest generates a "volcengine/request.Request" representing the
// client's request for the AttachNetworkInterface operation. The "output" return
// value will be populated with the AttachNetworkInterfaceCommon request's response once the request completes
// successfully.
//
// Use "Send" method on the returned AttachNetworkInterfaceCommon Request to send the API call to the service.
// the "output" return value is not valid until after AttachNetworkInterfaceCommon Send returns without error.
//
// See AttachNetworkInterface for more information on using the AttachNetworkInterface
// API call, and error handling.
//
//    // Example sending a request using the AttachNetworkInterfaceRequest method.
//    req, resp := client.AttachNetworkInterfaceRequest(params)
//
//    err := req.Send()
//    if err == nil { // resp is now filled
//        fmt.Println(resp)
//    }
func (c *VPC) AttachNetworkInterfaceRequest(input *AttachNetworkInterfaceInput) (req *request.Request, output *AttachNetworkInterfaceOutput) {
	op := &request.Operation{
		Name:       opAttachNetworkInterface,
		HTTPMethod: "GET",
		HTTPPath:   "/",
	}

	if input == nil {
		input = &AttachNetworkInterfaceInput{}
	}

	output = &AttachNetworkInterfaceOutput{}
	req = c.newRequest(op, input, output)

	return
}

// AttachNetworkInterface API operation for VPC.
//
// Returns volcengineerr.Error for service API and SDK errors. Use runtime type assertions
// with volcengineerr.Error's Code and Message methods to get detailed information about
// the error.
//
// See the VOLCENGINE API reference guide for VPC's
// API operation AttachNetworkInterface for usage and error information.
func (c *VPC) AttachNetworkInterface(input *AttachNetworkInterfaceInput) (*AttachNetworkInterfaceOutput, error) {
	req, out := c.AttachNetworkInterfaceRequest(input)
	return out, req.Send()
}

// AttachNetworkInterfaceWithContext is the same as AttachNetworkInterface with the addition of
// the ability to pass a context and additional request options.
//
// See AttachNetworkInterface for details on how to use this API operation.
//
// The context must be non-nil and will be used for request cancellation. Ifthe context is nil a panic will occur.
// In the future the SDK may create sub-contexts for http.Requests. See https://golang.org/pkg/context/
// for more information on using Contexts.
func (c *VPC) AttachNetworkInterfaceWithContext(ctx volcengine.Context, input *AttachNetworkInterfaceInput, opts ...request.Option) (*AttachNetworkInterfaceOutput, error) {
	req, out := c.AttachNetworkInterfaceRequest(input)
	req.SetContext(ctx)
	req.ApplyOptions(opts...)
	return out, req.Send()
}

type AttachNetworkInterfaceInput struct {
	_ struct{} `type:"structure"`

	// InstanceId is a required field
	InstanceId *string `type:"string" required:"true"`

	// NetworkInterfaceId is a required field
	NetworkInterfaceId *string `type:"string" required:"true"`
}

// String returns the string representation
func (s AttachNetworkInterfaceInput) String() string {
	return volcengineutil.Prettify(s)
}

// GoString returns the string representation
func (s AttachNetworkInterfaceInput) GoString() string {
	return s.String()
}

// Validate inspects the fields of the type to determine if they are valid.
func (s *AttachNetworkInterfaceInput) Validate() error {
	invalidParams := request.ErrInvalidParams{Context: "AttachNetworkInterfaceInput"}
	if s.InstanceId == nil {
		invalidParams.Add(request.NewErrParamRequired("InstanceId"))
	}
	if s.NetworkInterfaceId == nil {
		invalidParams.Add(request.NewErrParamRequired("NetworkInterfaceId"))
	}

	if invalidParams.Len() > 0 {
		return invalidParams
	}
	return nil
}

// SetInstanceId sets the InstanceId field's value.
func (s *AttachNetworkInterfaceInput) SetInstanceId(v string) *AttachNetworkInterfaceInput {
	s.InstanceId = &v
	return s
}

// SetNetworkInterfaceId sets the NetworkInterfaceId field's value.
func (s *AttachNetworkInterfaceInput) SetNetworkInterfaceId(v string) *AttachNetworkInterfaceInput {
	s.NetworkInterfaceId = &v
	return s
}

type AttachNetworkInterfaceOutput struct {
	_ struct{} `type:"structure"`

	Metadata *response.ResponseMetadata

	RequestId *string `type:"string"`
}

// String returns the string representation
func (s AttachNetworkInterfaceOutput) String() string {
	return volcengineutil.Prettify(s)
}

// GoString returns the string representation
func (s AttachNetworkInterfaceOutput) GoString() string {
	return s.String()
}

// SetRequestId sets the RequestId field's value.
func (s *AttachNetworkInterfaceOutput) SetRequestId(v string) *AttachNetworkInterfaceOutput {
	s.RequestId = &v
	return s
}
