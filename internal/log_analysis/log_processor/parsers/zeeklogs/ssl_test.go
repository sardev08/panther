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

func TestZeekSSL(t *testing.T) {
	// nolint:lll
	log := `{"ts":1541001600.580233,"uid":"CWUxtPxLqZGZgy0c4","id.orig_h":"172.16.2.16","id.orig_p":48684,"id.resp_h":"172.16.0.2","id.resp_p":443,"version":"TLSv12","cipher":"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA","resumed":false,"established":false}`

	expectedTime := time.Date(2018, 10, 31, 16, 0, 0, 580233097, time.UTC)
	expectedEvent := &ZeekSSL{
		Ts:          (*timestamp.UnixFloat)(&expectedTime),
		UID:         aws.String("CWUxtPxLqZGZgy0c4"),
		IDOrigH:     aws.String("172.16.2.16"),
		IDOrigP:     aws.Uint16(48684),
		IDRespH:     aws.String("172.16.0.2"),
		IDRespP:     aws.Uint16(443),
		Version:     aws.String("TLSv12"),
		Cipher:      aws.String("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
		Resumed:     aws.Bool(false),
		Established: aws.Bool(false),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("Zeek.SSL")
	expectedEvent.AppendAnyIPAddressPtrs(expectedEvent.IDOrigH)
	expectedEvent.AppendAnyIPAddressPtrs(expectedEvent.IDRespH)
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkZeekSSL(t, log, expectedEvent)
}

func TestZeekSSLType(t *testing.T) {
	parser := &ZeekSSLParser{}
	require.Equal(t, "Zeek.SSL", parser.LogType())
}

func checkZeekSSL(t *testing.T, log string, expectedEvent *ZeekSSL) {
	expectedEvent.SetEvent(expectedEvent)
	parser := &ZeekSSLParser{}

	testutil.EqualPantherLog(t, expectedEvent.Log(), parser.Parse(log))
}
