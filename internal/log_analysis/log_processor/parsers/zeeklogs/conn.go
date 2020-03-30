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

var ZeekConnDesc = `TCP/UDP/ICMP connections
Reference: https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info`

// nolint:lll
type ZeekConn struct {
	Ts                 *timestamp.UnixFloat `json:"ts" validate:"required" description:"This is the time of the first packet."`
	UID                *string              `json:"uid" validate:"required" description:"Unique ID for the connection."`
	IDOrigH            *string              `json:"id.orig_h" validate:"required" description:"The originator’s IP address."`
	IDOrigP            *uint16              `json:"id.orig_p" validate:"required" description:"The originator’s port number."`
	IDRespH            *string              `json:"id.resp_h" validate:"required" description:"The responder’s IP address."`
	IDRespP            *uint16              `json:"id.resp_p" validate:"required" description:"The responder’s port number."`
	Proto              *string              `json:"proto" validate:"required" description:"The transport layer protocol of the connection."`
	Service            *string              `json:"service,omitempty" description:"An identification of an application protocol being sent over the connection."`
	Duration           *float64             `json:"duration,omitempty" description:"How long the connection lasted."`
	OrigBytes          *uint64              `json:"orig_bytes,omitempty" description:"The number of payload bytes the originator sent."`
	RespBytes          *uint64              `json:"resp_bytes,omitempty" description:"The number of payload bytes the responder sent."`
	ConnState          *string              `json:"conn_state,omitempty" description:"Connection state"`
	LocalOrig          *bool                `json:"local_orig,omitempty" description:"If the connection is originated locally."`
	LocalResp          *bool                `json:"local_resp,omitempty" description:"If the connection is responded to locally."`
	MissedBytes        *uint64              `json:"missed_bytes,omitempty" description:"Indicates the number of bytes missed in content gaps, which is representative of packet loss."`
	History            *string              `json:"history,omitempty" description:"Records the state history of connections as a string of letters."`
	OrigPkts           *uint64              `json:"orig_pkts,omitempty" description:"Number of packets that the originator sent."`
	OrigIPBytes        *uint64              `json:"orig_ip_bytes,omitempty" description:"Number of IP level bytes that the originator sent."`
	RespPkts           *uint64              `json:"resp_pkts,omitempty" description:"Number of packets that the responder sent. "`
	RespIPBytes        *uint64              `json:"resp_ip_bytes,omitempty" description:"Number of IP level bytes that the responder sent"`
	TunnelParents      []string             `json:"tunnel_parents,omitempty" description:"If this connection was over a tunnel, indicate the uid values for any encapsulating parent connections used over the lifetime of this inner connection."`
	OrigL2Addr         *string              `json:"orig_l2_addr,omitempty" description:"Link-layer address of the originator, if available."`
	RespL2Addr         *string              `json:"resp_l2_addr,omitempty" description:"Link-layer address of the responder, if available."`
	VLAN               *int64               `json:"vlan,omitempty" description:"The outer VLAN for this connection, if applicable."`
	InnerVLAN          *int64               `json:"inner_vlan,omitempty" description:"The inner VLAN for this connection, if applicable."`
	SpeculativeService *string              `json:"speculative_service,omitempty" description:"Protocol that was determined by a matching signature after the beginning of a connection."`
	parsers.PantherLog
}

// ZeekConnParser parses zeek ssh logs
type ZeekConnParser struct{}

func (p *ZeekConnParser) New() parsers.LogParser {
	return &ZeekConnParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *ZeekConnParser) Parse(log string) []*parsers.PantherLog {
	ZeekConn := &ZeekConn{}

	err := jsoniter.UnmarshalFromString(log, ZeekConn)
	if err != nil {
		zap.L().Debug("failed to parse log", zap.Error(err))
		return nil
	}

	ZeekConn.updatePantherFields(p)

	if err := parsers.Validator.Struct(ZeekConn); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}

	return ZeekConn.Logs()
}

// LogType returns the log type supported by this parser
func (p *ZeekConnParser) LogType() string {
	return "Zeek.Conn"
}

func (event *ZeekConn) updatePantherFields(p *ZeekConnParser) {
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
