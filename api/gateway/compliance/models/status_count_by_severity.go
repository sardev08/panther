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

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// StatusCountBySeverity status count by severity
//
// swagger:model StatusCountBySeverity
type StatusCountBySeverity struct {

	// critical
	Critical *StatusCount `json:"critical,omitempty"`

	// high
	High *StatusCount `json:"high,omitempty"`

	// info
	Info *StatusCount `json:"info,omitempty"`

	// low
	Low *StatusCount `json:"low,omitempty"`

	// medium
	Medium *StatusCount `json:"medium,omitempty"`
}

// Validate validates this status count by severity
func (m *StatusCountBySeverity) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCritical(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateHigh(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInfo(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLow(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMedium(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *StatusCountBySeverity) validateCritical(formats strfmt.Registry) error {

	if swag.IsZero(m.Critical) { // not required
		return nil
	}

	if m.Critical != nil {
		if err := m.Critical.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("critical")
			}
			return err
		}
	}

	return nil
}

func (m *StatusCountBySeverity) validateHigh(formats strfmt.Registry) error {

	if swag.IsZero(m.High) { // not required
		return nil
	}

	if m.High != nil {
		if err := m.High.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("high")
			}
			return err
		}
	}

	return nil
}

func (m *StatusCountBySeverity) validateInfo(formats strfmt.Registry) error {

	if swag.IsZero(m.Info) { // not required
		return nil
	}

	if m.Info != nil {
		if err := m.Info.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("info")
			}
			return err
		}
	}

	return nil
}

func (m *StatusCountBySeverity) validateLow(formats strfmt.Registry) error {

	if swag.IsZero(m.Low) { // not required
		return nil
	}

	if m.Low != nil {
		if err := m.Low.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("low")
			}
			return err
		}
	}

	return nil
}

func (m *StatusCountBySeverity) validateMedium(formats strfmt.Registry) error {

	if swag.IsZero(m.Medium) { // not required
		return nil
	}

	if m.Medium != nil {
		if err := m.Medium.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("medium")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *StatusCountBySeverity) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *StatusCountBySeverity) UnmarshalBinary(b []byte) error {
	var res StatusCountBySeverity
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
