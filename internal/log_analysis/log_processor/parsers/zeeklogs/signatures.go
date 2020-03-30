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
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

var ZeekSignaturesDesc = `Zeek Signature matches
Reference: https://docs.zeek.org/en/current/scripts/base/frameworks/signatures/main.zeek.html#type-Signatures::Info`

// nolint:lll
type ZeekSignatures struct {
	Ts        *timestamp.UnixFloat `json:"ts" validate:"required" description:"The network time at which a signature matching type of event to be logged has occurred."`
	UID       *string              `json:"uid,omitempty"  description:"A unique identifier of the connection which triggered the signature match event."`
	SrcAddr   *string
	SrcPort   *uint16
	DstAddr   *string
	DstPort   *uint16
	Note      *string
	SigID     *string
	EventMsg  *string
	SubMsg    *string
	SigCount  *uint64
	HostCount *uint64
	parsers.PantherLog
}

// ZeekSignaturesParser parses zeek ssh logs
type ZeekSignaturesParser struct{}

func (p *ZeekSignaturesParser) New() parsers.LogParser {
	return &ZeekSignaturesParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *ZeekSignaturesParser) Parse(log string) []*parsers.PantherLog {
	ZeekSignatures := &ZeekSignatures{}

	err := jsoniter.UnmarshalFromString(log, ZeekSignatures)
	if err != nil {
		zap.L().Debug("failed to parse log", zap.Error(err))
		return nil
	}

	ZeekSignatures.updatePantherFields(p)

	if err := parsers.Validator.Struct(ZeekSignatures); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}

	return ZeekSignatures.Logs()
}

// LogType returns the log type supported by this parser
func (p *ZeekSignaturesParser) LogType() string {
	return "Zeek.SSL"
}

func (event *ZeekSignatures) updatePantherFields(p *ZeekSignaturesParser) {
	// event.SetCoreFields(p.LogType(), (*timestamp.RFC3339)(event.Ts), event)
	// if event.IDOrigH != nil {
	// 	// The hostname should be a FQDN, but may also be an IP address. Check for IP, otherwise
	// 	// add as a domain name. https://tools.ietf.org/html/rfc3164#section-6.2.4
	// 	hostname := *event.IDOrigH
	// 	if net.ParseIP(hostname) != nil {
	// 		event.AppendAnyIPAddresses(hostname)
	// 	} else {
	// 		event.AppendAnyDomainNames(hostname)
	// 	}
	// }

	// if event.IDRespH != nil {
	// 	hostname := *event.IDRespH
	// 	if net.ParseIP(hostname) != nil {
	// 		event.AppendAnyIPAddresses(hostname)
	// 	} else {
	// 		event.AppendAnyDomainNames(hostname)
	// 	}
	// }
}
