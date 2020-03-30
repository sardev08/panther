package zeeklogs

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"net"

	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

var ZeekSSHDesc = `Zeek SSH connections
Reference: https://docs.zeek.org/en/current/scripts/base/protocols/ssh/main.zeek.html#type-SSH::Info`

// nolint:lll
type ZeekSSH struct {
	Ts        *timestamp.UnixFloat `json:"ts" validate:"required" description:"Time when the SSH connection began."`
	UID       *string              `json:"uid" validate:"required" description:"Unique ID for the connection."`
	IDOrigH   *string              `json:"id.orig_h" validate:"required" description:"The originator’s IP address."`
	IDOrigP   *uint16              `json:"id.orig_p" validate:"required" description:"The originator’s port number."`
	IDRespH   *string              `json:"id.resp_h" validate:"required" description:"The responder’s IP address."`
	IDRespP   *uint16              `json:"id.resp_p" validate:"required" description:"The responder’s port number."`
	Version   *uint64              `json:"version" validate:"required" description:"SSH major version (1 or 2)"`
	Direction *string              `json:"direction,omitempty" description:"Direction of the connection. If the client was a local host logging into an external host, this would be OUTBOUND. INBOUND would be set for the opposite situation."`
	Client    *string              `json:"client,omitempty" description:"The client’s version string."`
	parsers.PantherLog
}

// ZeekSSHParser parses zeek ssh logs
type ZeekSSHParser struct{}

func (p *ZeekSSHParser) New() parsers.LogParser {
	return &ZeekSSHParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *ZeekSSHParser) Parse(log string) []*parsers.PantherLog {
	ZeekSSH := &ZeekSSH{}

	err := jsoniter.UnmarshalFromString(log, ZeekSSH)
	if err != nil {
		zap.L().Debug("failed to parse log", zap.Error(err))
		return nil
	}

	ZeekSSH.updatePantherFields(p)

	if err := parsers.Validator.Struct(ZeekSSH); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}

	return ZeekSSH.Logs()
}

// LogType returns the log type supported by this parser
func (p *ZeekSSHParser) LogType() string {
	return "Zeek.SSH"
}

func (event *ZeekSSH) updatePantherFields(p *ZeekSSHParser) {
	event.SetCoreFields(p.LogType(), (*timestamp.RFC3339)(event.Ts), event)
	if event.IDOrigH != nil {
		// The hostname should be a FQDN, but may also be an IP address. Check for IP, otherwise
		// add as a domain name. https://tools.ietf.org/html/rfc3164#section-6.2.4
		hostname := *event.IDOrigH
		if net.ParseIP(hostname) != nil {
			event.AppendAnyIPAddresses(hostname)
		} else {
			event.AppendAnyDomainNames(hostname)
		}
	}

	if event.IDRespH != nil {
		hostname := *event.IDRespH
		if net.ParseIP(hostname) != nil {
			event.AppendAnyIPAddresses(hostname)
		} else {
			event.AppendAnyDomainNames(hostname)
		}
	}
}
