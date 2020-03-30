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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestZeekConn(t *testing.T) {
	// nolint:lll
	log := `{ "ts": 1541001600.580233, "uid": "CWUxtPxLqZGZgy0c4", "id.orig_h": "172.16.2.16", "id.orig_p": 42576, "id.resp_h": "172.16.0.2", 
	"id.resp_p": 53, "proto": "udp", "service": "dns", "duration": 0.001355, "orig_bytes": 0, "resp_bytes": 97, 
	"conn_state": "SHR", "local_orig": true, "local_resp": true, "missed_bytes": 0, "history": "Cd", "orig_pkts": 0, "orig_ip_bytes": 0, "resp_pkts": 1, "resp_ip_bytes": 125, "tunnel_parents": [] }`
	expectedTime := time.Date(2018, 10, 31, 16, 0, 0, 580233097, time.UTC)
	expectedEvent := &ZeekConn{
		Ts:            (*timestamp.UnixFloat)(&expectedTime),
		UID:           aws.String("CWUxtPxLqZGZgy0c4"),
		IDOrigH:       aws.String("172.16.2.16"),
		IDOrigP:       aws.Uint16(42576),
		IDRespH:       aws.String("172.16.0.2"),
		IDRespP:       aws.Uint16(53),
		Proto:         aws.String("udp"),
		Service:       aws.String("dns"),
		Duration:      aws.Float64(0.001355),
		OrigBytes:     aws.Uint64(0),
		RespBytes:     aws.Uint64(97),
		ConnState:     aws.String("SHR"),
		LocalOrig:     aws.Bool(true),
		LocalResp:     aws.Bool(true),
		MissedBytes:   aws.Uint64(0),
		History:       aws.String("Cd"),
		OrigPkts:      aws.Uint64(0),
		OrigIPBytes:   aws.Uint64(0),
		RespPkts:      aws.Uint64(1),
		RespIPBytes:   aws.Uint64(125),
		TunnelParents: []string{},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("Zeek.Conn")
	expectedEvent.AppendAnyIPAddressPtrs(expectedEvent.IDOrigH)
	expectedEvent.AppendAnyIPAddressPtrs(expectedEvent.IDRespH)
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkZeekConn(t, log, expectedEvent)
}

func TestZeekConnType(t *testing.T) {
	parser := &ZeekConnParser{}
	require.Equal(t, "Zeek.Conn", parser.LogType())
}

func checkZeekConn(t *testing.T, log string, expectedEvent *ZeekConn) {
	expectedEvent.SetEvent(expectedEvent)
	parser := &ZeekConnParser{}
	testutil.EqualPantherLog(t, expectedEvent.Log(), parser.Parse(log))
}
