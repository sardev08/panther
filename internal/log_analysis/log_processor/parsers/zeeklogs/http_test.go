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

func TestZeekHTTP(t *testing.T) {
	// nolint:lll
	log := `{"ts":1541001600.580233,"uid":"CWUxtPxLqZGZgy0c4","id.orig_h":"172.16.2.16","id.orig_p":33386,"id.resp_h":"172.16.0.2","id.resp_p":80,"trans_depth":1,"version":"1.0","request_body_len":0,"response_body_len":11,"status_code":200,"status_msg":"OK","tags":[],"resp_fuids":["F4UfmS2fe3jrKfoO6k"],"resp_mime_types":["text/plain"]}`
	expectedTime := time.Date(2018, 10, 31, 16, 0, 0, 580233097, time.UTC)
	expectedEvent := &ZeekHTTP{
		Ts:              (*timestamp.UnixFloat)(&expectedTime),
		UID:             aws.String("CWUxtPxLqZGZgy0c4"),
		IDOrigH:         aws.String("172.16.2.16"),
		IDOrigP:         aws.Uint16(33386),
		IDRespH:         aws.String("172.16.0.2"),
		IDRespP:         aws.Uint16(80),
		TransDepth:      aws.Uint64(1),
		Version:         aws.String("1.0"),
		RequestBodyLen:  aws.Uint64(0),
		ResponseBodyLen: aws.Uint64(11),
		StatusCode:      aws.Uint(200),
		StatusMsg:       aws.String("OK"),
		Tags:            []string{},
		RespFuids:       []string{"F4UfmS2fe3jrKfoO6k"},
		RespMimeTypes:   []string{"text/plain"},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("Zeek.HTTP")
	expectedEvent.AppendAnyIPAddressPtrs(expectedEvent.IDOrigH)
	expectedEvent.AppendAnyIPAddressPtrs(expectedEvent.IDRespH)
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkZeekHTTP(t, log, expectedEvent)
}

func TestZeekHTTPType(t *testing.T) {
	parser := &ZeekHTTPParser{}
	require.Equal(t, "Zeek.HTTP", parser.LogType())
}

func checkZeekHTTP(t *testing.T, log string, expectedEvent *ZeekHTTP) {
	expectedEvent.SetEvent(expectedEvent)
	parser := &ZeekHTTPParser{}

	testutil.EqualPantherLog(t, expectedEvent.Log(), parser.Parse(log))
}
