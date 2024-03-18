// Code generated by volcengine with private/model/cli/gen-api/main.go. DO NOT EDIT.

package ecs

import (
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/request"
	"github.com/volcengine/volcengine-go-sdk/volcengine/response"
	"github.com/volcengine/volcengine-go-sdk/volcengine/volcengineutil"
)

const opCreateSubscriptionCommon = "CreateSubscription"

// CreateSubscriptionCommonRequest generates a "volcengine/request.Request" representing the
// client's request for the CreateSubscriptionCommon operation. The "output" return
// value will be populated with the CreateSubscriptionCommon request's response once the request completes
// successfully.
//
// Use "Send" method on the returned CreateSubscriptionCommon Request to send the API call to the service.
// the "output" return value is not valid until after CreateSubscriptionCommon Send returns without error.
//
// See CreateSubscriptionCommon for more information on using the CreateSubscriptionCommon
// API call, and error handling.
//
//	// Example sending a request using the CreateSubscriptionCommonRequest method.
//	req, resp := client.CreateSubscriptionCommonRequest(params)
//
//	err := req.Send()
//	if err == nil { // resp is now filled
//	    fmt.Println(resp)
//	}
func (c *ECS) CreateSubscriptionCommonRequest(input *map[string]interface{}) (req *request.Request, output *map[string]interface{}) {
	op := &request.Operation{
		Name:       opCreateSubscriptionCommon,
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

// CreateSubscriptionCommon API operation for ECS.
//
// Returns volcengineerr.Error for service API and SDK errors. Use runtime type assertions
// with volcengineerr.Error's Code and Message methods to get detailed information about
// the error.
//
// See the VOLCENGINE API reference guide for ECS's
// API operation CreateSubscriptionCommon for usage and error information.
func (c *ECS) CreateSubscriptionCommon(input *map[string]interface{}) (*map[string]interface{}, error) {
	req, out := c.CreateSubscriptionCommonRequest(input)
	return out, req.Send()
}

// CreateSubscriptionCommonWithContext is the same as CreateSubscriptionCommon with the addition of
// the ability to pass a context and additional request options.
//
// See CreateSubscriptionCommon for details on how to use this API operation.
//
// The context must be non-nil and will be used for request cancellation. If the context is nil a panic will occur.
// In the future the SDK may create sub-contexts for http.Requests. See https://golang.org/pkg/context/
// for more information on using Contexts.
func (c *ECS) CreateSubscriptionCommonWithContext(ctx volcengine.Context, input *map[string]interface{}, opts ...request.Option) (*map[string]interface{}, error) {
	req, out := c.CreateSubscriptionCommonRequest(input)
	req.SetContext(ctx)
	req.ApplyOptions(opts...)
	return out, req.Send()
}

const opCreateSubscription = "CreateSubscription"

// CreateSubscriptionRequest generates a "volcengine/request.Request" representing the
// client's request for the CreateSubscription operation. The "output" return
// value will be populated with the CreateSubscriptionCommon request's response once the request completes
// successfully.
//
// Use "Send" method on the returned CreateSubscriptionCommon Request to send the API call to the service.
// the "output" return value is not valid until after CreateSubscriptionCommon Send returns without error.
//
// See CreateSubscription for more information on using the CreateSubscription
// API call, and error handling.
//
//	// Example sending a request using the CreateSubscriptionRequest method.
//	req, resp := client.CreateSubscriptionRequest(params)
//
//	err := req.Send()
//	if err == nil { // resp is now filled
//	    fmt.Println(resp)
//	}
func (c *ECS) CreateSubscriptionRequest(input *CreateSubscriptionInput) (req *request.Request, output *CreateSubscriptionOutput) {
	op := &request.Operation{
		Name:       opCreateSubscription,
		HTTPMethod: "GET",
		HTTPPath:   "/",
	}

	if input == nil {
		input = &CreateSubscriptionInput{}
	}

	output = &CreateSubscriptionOutput{}
	req = c.newRequest(op, input, output)

	return
}

// CreateSubscription API operation for ECS.
//
// Returns volcengineerr.Error for service API and SDK errors. Use runtime type assertions
// with volcengineerr.Error's Code and Message methods to get detailed information about
// the error.
//
// See the VOLCENGINE API reference guide for ECS's
// API operation CreateSubscription for usage and error information.
func (c *ECS) CreateSubscription(input *CreateSubscriptionInput) (*CreateSubscriptionOutput, error) {
	req, out := c.CreateSubscriptionRequest(input)
	return out, req.Send()
}

// CreateSubscriptionWithContext is the same as CreateSubscription with the addition of
// the ability to pass a context and additional request options.
//
// See CreateSubscription for details on how to use this API operation.
//
// The context must be non-nil and will be used for request cancellation. Ifthe context is nil a panic will occur.
// In the future the SDK may create sub-contexts for http.Requests. See https://golang.org/pkg/context/
// for more information on using Contexts.
func (c *ECS) CreateSubscriptionWithContext(ctx volcengine.Context, input *CreateSubscriptionInput, opts ...request.Option) (*CreateSubscriptionOutput, error) {
	req, out := c.CreateSubscriptionRequest(input)
	req.SetContext(ctx)
	req.ApplyOptions(opts...)
	return out, req.Send()
}

type CreateSubscriptionInput struct {
	_ struct{} `type:"structure"`

	EventTypes []*string `type:"list"`

	Type *string `type:"string"`
}

// String returns the string representation
func (s CreateSubscriptionInput) String() string {
	return volcengineutil.Prettify(s)
}

// GoString returns the string representation
func (s CreateSubscriptionInput) GoString() string {
	return s.String()
}

// SetEventTypes sets the EventTypes field's value.
func (s *CreateSubscriptionInput) SetEventTypes(v []*string) *CreateSubscriptionInput {
	s.EventTypes = v
	return s
}

// SetType sets the Type field's value.
func (s *CreateSubscriptionInput) SetType(v string) *CreateSubscriptionInput {
	s.Type = &v
	return s
}

type CreateSubscriptionOutput struct {
	_ struct{} `type:"structure"`

	Metadata *response.ResponseMetadata

	SubscriptionId *string `type:"string"`
}

// String returns the string representation
func (s CreateSubscriptionOutput) String() string {
	return volcengineutil.Prettify(s)
}

// GoString returns the string representation
func (s CreateSubscriptionOutput) GoString() string {
	return s.String()
}

// SetSubscriptionId sets the SubscriptionId field's value.
func (s *CreateSubscriptionOutput) SetSubscriptionId(v string) *CreateSubscriptionOutput {
	s.SubscriptionId = &v
	return s
}
