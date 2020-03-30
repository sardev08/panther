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

var ZeekHTTPDesc = `Zeek HTTP requests and replies
Reference: https://docs.zeek.org/en/current/scripts/base/protocols/http/main.zeek.html#type-HTTP::Info`

// nolint:lll
type ZeekHTTP struct {
	Ts              *timestamp.UnixFloat `json:"ts" validate:"required" description:" Timestamp for when the request happened."`
	UID             *string              `json:"uid" validate:"required" description:"Unique ID for the connection."`
	IDOrigH         *string              `json:"id.orig_h" validate:"required" description:"The originator’s IP address."`
	IDOrigP         *uint16              `json:"id.orig_p" validate:"required" description:"The originator’s port number."`
	IDRespH         *string              `json:"id.resp_h" validate:"required" description:"The responder’s IP address."`
	IDRespP         *uint16              `json:"id.resp_p" validate:"required" description:"The responder’s port number."`
	TransDepth      *uint64              `json:"trans_depth"  validate:"required" description:"Represents the pipelined depth into the connection of this request/response transaction."`
	Method          *string              `json:"method,omitempty" description:"Verb used in the HTTP request (GET, POST, HEAD, etc.)."`
	Host            *string              `json:"host,omitempty" description:"Value of the HOST header."`
	URI             *string              `json:"uri,omitempty" description:"URI used in the request."`
	Referrer        *string              `json:"referrer,omitempty" description:"Value of the “referer” header."`
	Version         *string              `json:"version,omitempty" description:"Value of the version portion of the request."`
	UserAgent       *string              `json:"user_agent,omitempty" description:"Value of the User-Agent header from the client."`
	Origin          *string              `json:"origin,omitempty" description:"Value of the Origin header from the client."`
	RequestBodyLen  *uint64              `json:"request_body_len,omitempty" description:"Actual uncompressed content size of the data transferred from the client."`
	ResponseBodyLen *uint64              `json:"response_body_len,omitempty" description:"Actual uncompressed content size of the data transferred from the server."`
	StatusCode      *uint                `json:"status_code,omitempty" description:"Status code returned by the server."`
	StatusMsg       *string              `json:"status_msg,omitempty" description:"Status message returned by the server."`
	RespFuids       []string             `json:"resp_fuids,omitempty" description:"An ordered array of file unique IDs."`
	RespMimeTypes   []string             `json:"resp_mime_types,omitempty" description:"An ordered array of mime types."`
	Tags            []string             `json:"tags,omitempty" description:"A set of indicators of various attributes discovered and related to a particular request/response pair."`
	parsers.PantherLog
}

// ZeekHTTPParser parses zeek ssh logs
type ZeekHTTPParser struct{}

func (p *ZeekHTTPParser) New() parsers.LogParser {
	return &ZeekHTTPParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *ZeekHTTPParser) Parse(log string) []*parsers.PantherLog {
	ZeekHTTP := &ZeekHTTP{}
	err := jsoniter.UnmarshalFromString(log, ZeekHTTP)
	if err != nil {
		zap.L().Debug("failed to parse log", zap.Error(err))
		return nil
	}

	ZeekHTTP.updatePantherFields(p)

	if err := parsers.Validator.Struct(ZeekHTTP); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}

	return ZeekHTTP.Logs()
}

// LogType returns the log type supported by this parser
func (p *ZeekHTTPParser) LogType() string {
	return "Zeek.HTTP"
}

func (event *ZeekHTTP) updatePantherFields(p *ZeekHTTPParser) {
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
