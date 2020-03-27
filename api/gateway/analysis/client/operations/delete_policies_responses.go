// Code generated by go-swagger; DO NOT EDIT.

// Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
// Copyright (C) 2020 Panther Labs Inc
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/panther-labs/panther/api/gateway/analysis/models"
)

// DeletePoliciesReader is a Reader for the DeletePolicies structure.
type DeletePoliciesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeletePoliciesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeletePoliciesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeletePoliciesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewDeletePoliciesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewDeletePoliciesOK creates a DeletePoliciesOK with default headers values
func NewDeletePoliciesOK() *DeletePoliciesOK {
	return &DeletePoliciesOK{}
}

/*DeletePoliciesOK handles this case with default header values.

OK
*/
type DeletePoliciesOK struct {
}

func (o *DeletePoliciesOK) Error() string {
	return fmt.Sprintf("[POST /delete][%d] deletePoliciesOK ", 200)
}

func (o *DeletePoliciesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewDeletePoliciesBadRequest creates a DeletePoliciesBadRequest with default headers values
func NewDeletePoliciesBadRequest() *DeletePoliciesBadRequest {
	return &DeletePoliciesBadRequest{}
}

/*DeletePoliciesBadRequest handles this case with default header values.

Bad request
*/
type DeletePoliciesBadRequest struct {
	Payload *models.Error
}

func (o *DeletePoliciesBadRequest) Error() string {
	return fmt.Sprintf("[POST /delete][%d] deletePoliciesBadRequest  %+v", 400, o.Payload)
}

func (o *DeletePoliciesBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *DeletePoliciesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeletePoliciesInternalServerError creates a DeletePoliciesInternalServerError with default headers values
func NewDeletePoliciesInternalServerError() *DeletePoliciesInternalServerError {
	return &DeletePoliciesInternalServerError{}
}

/*DeletePoliciesInternalServerError handles this case with default header values.

Internal server error
*/
type DeletePoliciesInternalServerError struct {
}

func (o *DeletePoliciesInternalServerError) Error() string {
	return fmt.Sprintf("[POST /delete][%d] deletePoliciesInternalServerError ", 500)
}

func (o *DeletePoliciesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
