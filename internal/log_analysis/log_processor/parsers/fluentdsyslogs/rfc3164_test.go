package fluentdsyslogs

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/stretchr/testify/require"
)

func TestRFC3164(t *testing.T) {
	// nolint:lll
	log := `{"pri":6,"host":"ip-172-31-84-73","pid":"11111","ident":"sudo","message":"pam_unix(sudo:session): session closed for user root","tag":"syslog.authpriv.info","time":"2020-03-23 16:14:06 +0000"}`

	expectedTime := time.Date(2020, 3, 23, 16, 14, 6, 0, time.UTC)
	expectedRFC3164 := &RFC3164{
		Priority:  aws.Uint8(6),
		Hostname:  aws.String("ip-172-31-84-73"),
		Ident:     aws.String("sudo"),
		ProcID:    aws.String("11111"),
		Message:   aws.String("pam_unix(sudo:session): session closed for user root"),
		Tag:       aws.String("syslog.authpriv.info"),
		Timestamp: (*timestamp.FluentdTimestamp)(&expectedTime),
	}

	// panther fields
	expectedRFC3164.PantherLogType = aws.String("Fluentd.Syslog3164")
	expectedRFC3164.AppendAnyDomainNamePtrs(expectedRFC3164.Hostname)
	expectedRFC3164.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	checkRFC3164(t, log, expectedRFC3164)
}

func TestRFC3164TypeType(t *testing.T) {
	parser := &RFC3164Parser{}
	require.Equal(t, "Fluentd.Syslog3164", parser.LogType())
}

func checkRFC3164(t *testing.T, log string, expectedRFC3164 *RFC3164) {
	expectedRFC3164.SetEvent(expectedRFC3164)
	parser := &RFC3164Parser{}
	testutil.EqualPantherLog(t, expectedRFC3164.Log(), parser.Parse(log))
}
