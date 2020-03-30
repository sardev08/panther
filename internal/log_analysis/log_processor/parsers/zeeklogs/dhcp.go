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

var ZeekDHCPDesc = `Zeek DHCP leases
Reference: https://docs.zeek.org/en/current/scripts/base/protocols/dhcp/main.zeek.html#type-DHCP::Info`

// nolint:lll
type ZeekDHCP struct {
	Ts             *timestamp.UnixFloat `json:"ts" validate:"required" description:"The earliest time at which a DHCP message over the associated connection is observed."`
	UIDs           []string
	ClientAddr     *string
	ServerAddr     *string
	ClientPort     *uint16
	ServerPort     *uint16
	MAC            *string
	HostName       *string
	ClientFQDN     *string
	Domain         *string
	RequestedAddr  *string
	AssignedAddr   *string
	LeaseTime      *float64
	ClientMessage  *string
	ServerMessage  *string
	MsgTypes       []string
	Duration       float64
	ClientChaddr   *string
	ClientSoftware *string
	ServerSoftware *string
	LastMessageTs  *timestamp.UnixFloat
	CircuitID      *string
	AgentRemoteID  *string
	SubscriberID   *string
	parsers.PantherLog
}

// ZeekDHCPParser parses zeek ssh logs
type ZeekDHCPParser struct{}

func (p *ZeekDHCPParser) New() parsers.LogParser {
	return &ZeekDHCPParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *ZeekDHCPParser) Parse(log string) []*parsers.PantherLog {
	ZeekDHCP := &ZeekDHCP{}

	err := jsoniter.UnmarshalFromString(log, ZeekDHCP)
	if err != nil {
		zap.L().Debug("failed to parse log", zap.Error(err))
		return nil
	}

	ZeekDHCP.updatePantherFields(p)

	if err := parsers.Validator.Struct(ZeekDHCP); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}

	return ZeekDHCP.Logs()
}

// LogType returns the log type supported by this parser
func (p *ZeekDHCPParser) LogType() string {
	return "Zeek.SSL"
}

func (event *ZeekDHCP) updatePantherFields(p *ZeekDHCPParser) {
	event.SetCoreFields(p.LogType(), (*timestamp.RFC3339)(event.Ts), event)
}
