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

func TestZeekSSH(t *testing.T) {
	// nolint:lll
	log := `{"ts":1541001600.580233,"uid":"C5mnOU2AFRTW9h5oF6","id.orig_h":"172.16.2.16","id.orig_p":60180,"id.resp_h":"172.16.0.2","id.resp_p":22,"version":2,"direction":"INBOUND","client":"SSH-2.0-OpenSSH_7.6"}`

	expectedTime := time.Date(2018, 10, 31, 16, 0, 0, 580233097, time.UTC)
	expectedEvent := &ZeekSSH{
		Ts:        (*timestamp.UnixFloat)(&expectedTime),
		UID:       aws.String("C5mnOU2AFRTW9h5oF6"),
		IDOrigH:   aws.String("172.16.2.16"),
		IDOrigP:   aws.Uint16(60180),
		IDRespH:   aws.String("172.16.0.2"),
		IDRespP:   aws.Uint16(22),
		Version:   aws.Uint64(2),
		Direction: aws.String("INBOUND"),
		Client:    aws.String("SSH-2.0-OpenSSH_7.6"),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("Zeek.SSH")
	expectedEvent.AppendAnyIPAddressPtrs(expectedEvent.IDOrigH)
	expectedEvent.AppendAnyIPAddressPtrs(expectedEvent.IDRespH)
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkZeekSSH(t, log, expectedEvent)
}

func TestZeekSSHType(t *testing.T) {
	parser := &ZeekSSHParser{}
	require.Equal(t, "Zeek.SSH", parser.LogType())
}

func checkZeekSSH(t *testing.T, log string, expectedEvent *ZeekSSH) {
	expectedEvent.SetEvent(expectedEvent)
	parser := &ZeekSSHParser{}

	testutil.EqualPantherLog(t, expectedEvent.Log(), parser.Parse(log))
}
