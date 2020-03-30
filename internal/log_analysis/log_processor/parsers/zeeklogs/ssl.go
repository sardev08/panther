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

var ZeekSSLDesc = `Zeek SSL/TLS handshake info
Reference: https://docs.zeek.org/en/current/scripts/base/protocols/ssl/main.zeek.html#type-SSL::Info`

// nolint:lll
type ZeekSSL struct {
	Ts          *timestamp.UnixFloat `json:"ts" validate:"required" description:"Time when the SSL connection was first detected."`
	UID         *string              `json:"uid" validate:"required" description:"Unique ID for the connection."`
	IDOrigH     *string              `json:"id.orig_h" validate:"required" description:"The originator’s IP address."`
	IDOrigP     *uint16              `json:"id.orig_p" validate:"required" description:"The originator’s port number."`
	IDRespH     *string              `json:"id.resp_h" validate:"required" description:"The responder’s IP address."`
	IDRespP     *uint16              `json:"id.resp_p" validate:"required" description:"The responder’s port number."`
	Version     *string              `json:"version,omitempty" description:"SSL/TLS version that the server chose."`
	Cipher      *string              `json:"cipher,omitempty" description:"SSL/TLS cipher suite that the server chose."`
	Resumed     *bool                `json:"resumed,omitempty" description:"Flag to indicate if the session was resumed reusing the key material exchanged in an earlier connection."`
	Established *bool                `json:"established,omitempty" description:"Flag to indicate if this ssl session has been established successfully, or if it was aborted during the handshake."`
	parsers.PantherLog
}

// ZeekSSLParser parses zeek ssh logs
type ZeekSSLParser struct{}

func (p *ZeekSSLParser) New() parsers.LogParser {
	return &ZeekSSLParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *ZeekSSLParser) Parse(log string) []*parsers.PantherLog {
	ZeekSSL := &ZeekSSL{}

	err := jsoniter.UnmarshalFromString(log, ZeekSSL)
	if err != nil {
		zap.L().Debug("failed to parse log", zap.Error(err))
		return nil
	}

	ZeekSSL.updatePantherFields(p)

	if err := parsers.Validator.Struct(ZeekSSL); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}

	return ZeekSSL.Logs()
}

// LogType returns the log type supported by this parser
func (p *ZeekSSLParser) LogType() string {
	return "Zeek.SSL"
}

func (event *ZeekSSL) updatePantherFields(p *ZeekSSLParser) {
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
