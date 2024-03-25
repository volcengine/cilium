// Code generated by volcengine with private/model/cli/gen-api/main.go. DO NOT EDIT.

package vpc

import (
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/request"
	"github.com/volcengine/volcengine-go-sdk/volcengine/response"
	"github.com/volcengine/volcengine-go-sdk/volcengine/volcengineutil"
)

const opDescribeNetworkAclsCommon = "DescribeNetworkAcls"

// DescribeNetworkAclsCommonRequest generates a "volcengine/request.Request" representing the
// client's request for the DescribeNetworkAclsCommon operation. The "output" return
// value will be populated with the DescribeNetworkAclsCommon request's response once the request completes
// successfully.
//
// Use "Send" method on the returned DescribeNetworkAclsCommon Request to send the API call to the service.
// the "output" return value is not valid until after DescribeNetworkAclsCommon Send returns without error.
//
// See DescribeNetworkAclsCommon for more information on using the DescribeNetworkAclsCommon
// API call, and error handling.
//
//    // Example sending a request using the DescribeNetworkAclsCommonRequest method.
//    req, resp := client.DescribeNetworkAclsCommonRequest(params)
//
//    err := req.Send()
//    if err == nil { // resp is now filled
//        fmt.Println(resp)
//    }
func (c *VPC) DescribeNetworkAclsCommonRequest(input *map[string]interface{}) (req *request.Request, output *map[string]interface{}) {
	op := &request.Operation{
		Name:       opDescribeNetworkAclsCommon,
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

// DescribeNetworkAclsCommon API operation for VPC.
//
// Returns volcengineerr.Error for service API and SDK errors. Use runtime type assertions
// with volcengineerr.Error's Code and Message methods to get detailed information about
// the error.
//
// See the VOLCENGINE API reference guide for VPC's
// API operation DescribeNetworkAclsCommon for usage and error information.
func (c *VPC) DescribeNetworkAclsCommon(input *map[string]interface{}) (*map[string]interface{}, error) {
	req, out := c.DescribeNetworkAclsCommonRequest(input)
	return out, req.Send()
}

// DescribeNetworkAclsCommonWithContext is the same as DescribeNetworkAclsCommon with the addition of
// the ability to pass a context and additional request options.
//
// See DescribeNetworkAclsCommon for details on how to use this API operation.
//
// The context must be non-nil and will be used for request cancellation. If the context is nil a panic will occur.
// In the future the SDK may create sub-contexts for http.Requests. See https://golang.org/pkg/context/
// for more information on using Contexts.
func (c *VPC) DescribeNetworkAclsCommonWithContext(ctx volcengine.Context, input *map[string]interface{}, opts ...request.Option) (*map[string]interface{}, error) {
	req, out := c.DescribeNetworkAclsCommonRequest(input)
	req.SetContext(ctx)
	req.ApplyOptions(opts...)
	return out, req.Send()
}

const opDescribeNetworkAcls = "DescribeNetworkAcls"

// DescribeNetworkAclsRequest generates a "volcengine/request.Request" representing the
// client's request for the DescribeNetworkAcls operation. The "output" return
// value will be populated with the DescribeNetworkAclsCommon request's response once the request completes
// successfully.
//
// Use "Send" method on the returned DescribeNetworkAclsCommon Request to send the API call to the service.
// the "output" return value is not valid until after DescribeNetworkAclsCommon Send returns without error.
//
// See DescribeNetworkAcls for more information on using the DescribeNetworkAcls
// API call, and error handling.
//
//    // Example sending a request using the DescribeNetworkAclsRequest method.
//    req, resp := client.DescribeNetworkAclsRequest(params)
//
//    err := req.Send()
//    if err == nil { // resp is now filled
//        fmt.Println(resp)
//    }
func (c *VPC) DescribeNetworkAclsRequest(input *DescribeNetworkAclsInput) (req *request.Request, output *DescribeNetworkAclsOutput) {
	op := &request.Operation{
		Name:       opDescribeNetworkAcls,
		HTTPMethod: "GET",
		HTTPPath:   "/",
	}

	if input == nil {
		input = &DescribeNetworkAclsInput{}
	}

	output = &DescribeNetworkAclsOutput{}
	req = c.newRequest(op, input, output)

	return
}

// DescribeNetworkAcls API operation for VPC.
//
// Returns volcengineerr.Error for service API and SDK errors. Use runtime type assertions
// with volcengineerr.Error's Code and Message methods to get detailed information about
// the error.
//
// See the VOLCENGINE API reference guide for VPC's
// API operation DescribeNetworkAcls for usage and error information.
func (c *VPC) DescribeNetworkAcls(input *DescribeNetworkAclsInput) (*DescribeNetworkAclsOutput, error) {
	req, out := c.DescribeNetworkAclsRequest(input)
	return out, req.Send()
}

// DescribeNetworkAclsWithContext is the same as DescribeNetworkAcls with the addition of
// the ability to pass a context and additional request options.
//
// See DescribeNetworkAcls for details on how to use this API operation.
//
// The context must be non-nil and will be used for request cancellation. Ifthe context is nil a panic will occur.
// In the future the SDK may create sub-contexts for http.Requests. See https://golang.org/pkg/context/
// for more information on using Contexts.
func (c *VPC) DescribeNetworkAclsWithContext(ctx volcengine.Context, input *DescribeNetworkAclsInput, opts ...request.Option) (*DescribeNetworkAclsOutput, error) {
	req, out := c.DescribeNetworkAclsRequest(input)
	req.SetContext(ctx)
	req.ApplyOptions(opts...)
	return out, req.Send()
}

type DescribeNetworkAclsInput struct {
	_ struct{} `type:"structure"`

	MaxResults *int64 `min:"1" max:"100" type:"integer"`

	NetworkAclIds []*string `type:"list"`

	NetworkAclName *string `type:"string"`

	NextToken *string `type:"string"`

	PageNumber *int64 `type:"integer"`

	PageSize *int64 `max:"100" type:"integer"`

	ProjectName *string `type:"string"`

	SubnetId *string `type:"string"`

	VpcId *string `type:"string"`
}

// String returns the string representation
func (s DescribeNetworkAclsInput) String() string {
	return volcengineutil.Prettify(s)
}

// GoString returns the string representation
func (s DescribeNetworkAclsInput) GoString() string {
	return s.String()
}

// Validate inspects the fields of the type to determine if they are valid.
func (s *DescribeNetworkAclsInput) Validate() error {
	invalidParams := request.ErrInvalidParams{Context: "DescribeNetworkAclsInput"}
	if s.MaxResults != nil && *s.MaxResults < 1 {
		invalidParams.Add(request.NewErrParamMinValue("MaxResults", 1))
	}
	if s.MaxResults != nil && *s.MaxResults > 100 {
		invalidParams.Add(request.NewErrParamMaxValue("MaxResults", 100))
	}
	if s.PageSize != nil && *s.PageSize > 100 {
		invalidParams.Add(request.NewErrParamMaxValue("PageSize", 100))
	}

	if invalidParams.Len() > 0 {
		return invalidParams
	}
	return nil
}

// SetMaxResults sets the MaxResults field's value.
func (s *DescribeNetworkAclsInput) SetMaxResults(v int64) *DescribeNetworkAclsInput {
	s.MaxResults = &v
	return s
}

// SetNetworkAclIds sets the NetworkAclIds field's value.
func (s *DescribeNetworkAclsInput) SetNetworkAclIds(v []*string) *DescribeNetworkAclsInput {
	s.NetworkAclIds = v
	return s
}

// SetNetworkAclName sets the NetworkAclName field's value.
func (s *DescribeNetworkAclsInput) SetNetworkAclName(v string) *DescribeNetworkAclsInput {
	s.NetworkAclName = &v
	return s
}

// SetNextToken sets the NextToken field's value.
func (s *DescribeNetworkAclsInput) SetNextToken(v string) *DescribeNetworkAclsInput {
	s.NextToken = &v
	return s
}

// SetPageNumber sets the PageNumber field's value.
func (s *DescribeNetworkAclsInput) SetPageNumber(v int64) *DescribeNetworkAclsInput {
	s.PageNumber = &v
	return s
}

// SetPageSize sets the PageSize field's value.
func (s *DescribeNetworkAclsInput) SetPageSize(v int64) *DescribeNetworkAclsInput {
	s.PageSize = &v
	return s
}

// SetProjectName sets the ProjectName field's value.
func (s *DescribeNetworkAclsInput) SetProjectName(v string) *DescribeNetworkAclsInput {
	s.ProjectName = &v
	return s
}

// SetSubnetId sets the SubnetId field's value.
func (s *DescribeNetworkAclsInput) SetSubnetId(v string) *DescribeNetworkAclsInput {
	s.SubnetId = &v
	return s
}

// SetVpcId sets the VpcId field's value.
func (s *DescribeNetworkAclsInput) SetVpcId(v string) *DescribeNetworkAclsInput {
	s.VpcId = &v
	return s
}

type DescribeNetworkAclsOutput struct {
	_ struct{} `type:"structure"`

	Metadata *response.ResponseMetadata

	NetworkAcls []*NetworkAclForDescribeNetworkAclsOutput `type:"list"`

	NextToken *string `type:"string"`

	PageNumber *int64 `type:"integer"`

	PageSize *int64 `type:"integer"`

	RequestId *string `type:"string"`

	TotalCount *int64 `type:"integer"`
}

// String returns the string representation
func (s DescribeNetworkAclsOutput) String() string {
	return volcengineutil.Prettify(s)
}

// GoString returns the string representation
func (s DescribeNetworkAclsOutput) GoString() string {
	return s.String()
}

// SetNetworkAcls sets the NetworkAcls field's value.
func (s *DescribeNetworkAclsOutput) SetNetworkAcls(v []*NetworkAclForDescribeNetworkAclsOutput) *DescribeNetworkAclsOutput {
	s.NetworkAcls = v
	return s
}

// SetNextToken sets the NextToken field's value.
func (s *DescribeNetworkAclsOutput) SetNextToken(v string) *DescribeNetworkAclsOutput {
	s.NextToken = &v
	return s
}

// SetPageNumber sets the PageNumber field's value.
func (s *DescribeNetworkAclsOutput) SetPageNumber(v int64) *DescribeNetworkAclsOutput {
	s.PageNumber = &v
	return s
}

// SetPageSize sets the PageSize field's value.
func (s *DescribeNetworkAclsOutput) SetPageSize(v int64) *DescribeNetworkAclsOutput {
	s.PageSize = &v
	return s
}

// SetRequestId sets the RequestId field's value.
func (s *DescribeNetworkAclsOutput) SetRequestId(v string) *DescribeNetworkAclsOutput {
	s.RequestId = &v
	return s
}

// SetTotalCount sets the TotalCount field's value.
func (s *DescribeNetworkAclsOutput) SetTotalCount(v int64) *DescribeNetworkAclsOutput {
	s.TotalCount = &v
	return s
}

type EgressAclEntryForDescribeNetworkAclsOutput struct {
	_ struct{} `type:"structure"`

	Description *string `type:"string"`

	DestinationCidrIp *string `type:"string"`

	NetworkAclEntryId *string `type:"string"`

	NetworkAclEntryName *string `type:"string"`

	Policy *string `type:"string"`

	Port *string `type:"string"`

	Priority *int64 `type:"integer"`

	Protocol *string `type:"string"`
}

// String returns the string representation
func (s EgressAclEntryForDescribeNetworkAclsOutput) String() string {
	return volcengineutil.Prettify(s)
}

// GoString returns the string representation
func (s EgressAclEntryForDescribeNetworkAclsOutput) GoString() string {
	return s.String()
}

// SetDescription sets the Description field's value.
func (s *EgressAclEntryForDescribeNetworkAclsOutput) SetDescription(v string) *EgressAclEntryForDescribeNetworkAclsOutput {
	s.Description = &v
	return s
}

// SetDestinationCidrIp sets the DestinationCidrIp field's value.
func (s *EgressAclEntryForDescribeNetworkAclsOutput) SetDestinationCidrIp(v string) *EgressAclEntryForDescribeNetworkAclsOutput {
	s.DestinationCidrIp = &v
	return s
}

// SetNetworkAclEntryId sets the NetworkAclEntryId field's value.
func (s *EgressAclEntryForDescribeNetworkAclsOutput) SetNetworkAclEntryId(v string) *EgressAclEntryForDescribeNetworkAclsOutput {
	s.NetworkAclEntryId = &v
	return s
}

// SetNetworkAclEntryName sets the NetworkAclEntryName field's value.
func (s *EgressAclEntryForDescribeNetworkAclsOutput) SetNetworkAclEntryName(v string) *EgressAclEntryForDescribeNetworkAclsOutput {
	s.NetworkAclEntryName = &v
	return s
}

// SetPolicy sets the Policy field's value.
func (s *EgressAclEntryForDescribeNetworkAclsOutput) SetPolicy(v string) *EgressAclEntryForDescribeNetworkAclsOutput {
	s.Policy = &v
	return s
}

// SetPort sets the Port field's value.
func (s *EgressAclEntryForDescribeNetworkAclsOutput) SetPort(v string) *EgressAclEntryForDescribeNetworkAclsOutput {
	s.Port = &v
	return s
}

// SetPriority sets the Priority field's value.
func (s *EgressAclEntryForDescribeNetworkAclsOutput) SetPriority(v int64) *EgressAclEntryForDescribeNetworkAclsOutput {
	s.Priority = &v
	return s
}

// SetProtocol sets the Protocol field's value.
func (s *EgressAclEntryForDescribeNetworkAclsOutput) SetProtocol(v string) *EgressAclEntryForDescribeNetworkAclsOutput {
	s.Protocol = &v
	return s
}

type IngressAclEntryForDescribeNetworkAclsOutput struct {
	_ struct{} `type:"structure"`

	Description *string `type:"string"`

	NetworkAclEntryId *string `type:"string"`

	NetworkAclEntryName *string `type:"string"`

	Policy *string `type:"string"`

	Port *string `type:"string"`

	Priority *int64 `type:"integer"`

	Protocol *string `type:"string"`

	SourceCidrIp *string `type:"string"`
}

// String returns the string representation
func (s IngressAclEntryForDescribeNetworkAclsOutput) String() string {
	return volcengineutil.Prettify(s)
}

// GoString returns the string representation
func (s IngressAclEntryForDescribeNetworkAclsOutput) GoString() string {
	return s.String()
}

// SetDescription sets the Description field's value.
func (s *IngressAclEntryForDescribeNetworkAclsOutput) SetDescription(v string) *IngressAclEntryForDescribeNetworkAclsOutput {
	s.Description = &v
	return s
}

// SetNetworkAclEntryId sets the NetworkAclEntryId field's value.
func (s *IngressAclEntryForDescribeNetworkAclsOutput) SetNetworkAclEntryId(v string) *IngressAclEntryForDescribeNetworkAclsOutput {
	s.NetworkAclEntryId = &v
	return s
}

// SetNetworkAclEntryName sets the NetworkAclEntryName field's value.
func (s *IngressAclEntryForDescribeNetworkAclsOutput) SetNetworkAclEntryName(v string) *IngressAclEntryForDescribeNetworkAclsOutput {
	s.NetworkAclEntryName = &v
	return s
}

// SetPolicy sets the Policy field's value.
func (s *IngressAclEntryForDescribeNetworkAclsOutput) SetPolicy(v string) *IngressAclEntryForDescribeNetworkAclsOutput {
	s.Policy = &v
	return s
}

// SetPort sets the Port field's value.
func (s *IngressAclEntryForDescribeNetworkAclsOutput) SetPort(v string) *IngressAclEntryForDescribeNetworkAclsOutput {
	s.Port = &v
	return s
}

// SetPriority sets the Priority field's value.
func (s *IngressAclEntryForDescribeNetworkAclsOutput) SetPriority(v int64) *IngressAclEntryForDescribeNetworkAclsOutput {
	s.Priority = &v
	return s
}

// SetProtocol sets the Protocol field's value.
func (s *IngressAclEntryForDescribeNetworkAclsOutput) SetProtocol(v string) *IngressAclEntryForDescribeNetworkAclsOutput {
	s.Protocol = &v
	return s
}

// SetSourceCidrIp sets the SourceCidrIp field's value.
func (s *IngressAclEntryForDescribeNetworkAclsOutput) SetSourceCidrIp(v string) *IngressAclEntryForDescribeNetworkAclsOutput {
	s.SourceCidrIp = &v
	return s
}

type NetworkAclForDescribeNetworkAclsOutput struct {
	_ struct{} `type:"structure"`

	CreationTime *string `type:"string"`

	Description *string `type:"string"`

	EgressAclEntries []*EgressAclEntryForDescribeNetworkAclsOutput `type:"list"`

	IngressAclEntries []*IngressAclEntryForDescribeNetworkAclsOutput `type:"list"`

	NetworkAclId *string `type:"string"`

	NetworkAclName *string `type:"string"`

	ProjectName *string `type:"string"`

	Resources []*ResourceForDescribeNetworkAclsOutput `type:"list"`

	Status *string `type:"string"`

	UpdateTime *string `type:"string"`

	VpcId *string `type:"string"`
}

// String returns the string representation
func (s NetworkAclForDescribeNetworkAclsOutput) String() string {
	return volcengineutil.Prettify(s)
}

// GoString returns the string representation
func (s NetworkAclForDescribeNetworkAclsOutput) GoString() string {
	return s.String()
}

// SetCreationTime sets the CreationTime field's value.
func (s *NetworkAclForDescribeNetworkAclsOutput) SetCreationTime(v string) *NetworkAclForDescribeNetworkAclsOutput {
	s.CreationTime = &v
	return s
}

// SetDescription sets the Description field's value.
func (s *NetworkAclForDescribeNetworkAclsOutput) SetDescription(v string) *NetworkAclForDescribeNetworkAclsOutput {
	s.Description = &v
	return s
}

// SetEgressAclEntries sets the EgressAclEntries field's value.
func (s *NetworkAclForDescribeNetworkAclsOutput) SetEgressAclEntries(v []*EgressAclEntryForDescribeNetworkAclsOutput) *NetworkAclForDescribeNetworkAclsOutput {
	s.EgressAclEntries = v
	return s
}

// SetIngressAclEntries sets the IngressAclEntries field's value.
func (s *NetworkAclForDescribeNetworkAclsOutput) SetIngressAclEntries(v []*IngressAclEntryForDescribeNetworkAclsOutput) *NetworkAclForDescribeNetworkAclsOutput {
	s.IngressAclEntries = v
	return s
}

// SetNetworkAclId sets the NetworkAclId field's value.
func (s *NetworkAclForDescribeNetworkAclsOutput) SetNetworkAclId(v string) *NetworkAclForDescribeNetworkAclsOutput {
	s.NetworkAclId = &v
	return s
}

// SetNetworkAclName sets the NetworkAclName field's value.
func (s *NetworkAclForDescribeNetworkAclsOutput) SetNetworkAclName(v string) *NetworkAclForDescribeNetworkAclsOutput {
	s.NetworkAclName = &v
	return s
}

// SetProjectName sets the ProjectName field's value.
func (s *NetworkAclForDescribeNetworkAclsOutput) SetProjectName(v string) *NetworkAclForDescribeNetworkAclsOutput {
	s.ProjectName = &v
	return s
}

// SetResources sets the Resources field's value.
func (s *NetworkAclForDescribeNetworkAclsOutput) SetResources(v []*ResourceForDescribeNetworkAclsOutput) *NetworkAclForDescribeNetworkAclsOutput {
	s.Resources = v
	return s
}

// SetStatus sets the Status field's value.
func (s *NetworkAclForDescribeNetworkAclsOutput) SetStatus(v string) *NetworkAclForDescribeNetworkAclsOutput {
	s.Status = &v
	return s
}

// SetUpdateTime sets the UpdateTime field's value.
func (s *NetworkAclForDescribeNetworkAclsOutput) SetUpdateTime(v string) *NetworkAclForDescribeNetworkAclsOutput {
	s.UpdateTime = &v
	return s
}

// SetVpcId sets the VpcId field's value.
func (s *NetworkAclForDescribeNetworkAclsOutput) SetVpcId(v string) *NetworkAclForDescribeNetworkAclsOutput {
	s.VpcId = &v
	return s
}

type ResourceForDescribeNetworkAclsOutput struct {
	_ struct{} `type:"structure"`

	ResourceId *string `type:"string"`

	Status *string `type:"string"`
}

// String returns the string representation
func (s ResourceForDescribeNetworkAclsOutput) String() string {
	return volcengineutil.Prettify(s)
}

// GoString returns the string representation
func (s ResourceForDescribeNetworkAclsOutput) GoString() string {
	return s.String()
}

// SetResourceId sets the ResourceId field's value.
func (s *ResourceForDescribeNetworkAclsOutput) SetResourceId(v string) *ResourceForDescribeNetworkAclsOutput {
	s.ResourceId = &v
	return s
}

// SetStatus sets the Status field's value.
func (s *ResourceForDescribeNetworkAclsOutput) SetStatus(v string) *ResourceForDescribeNetworkAclsOutput {
	s.Status = &v
	return s
}
