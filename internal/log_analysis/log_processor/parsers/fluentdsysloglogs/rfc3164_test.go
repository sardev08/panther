package fluentdsysloglogs

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/stretchr/testify/require"
)

func TestRFC3164(t *testing.T) {
	log := `{"pri": 6, "host": "192.168.0.1", "ident": "fluentd", "pid": "11111", "message": "[error] Syslog test"}`

	expectedRFC3164 := &RFC3164{
		Priority: aws.Uint8(8),
		Hostname: aws.String("192.168.0.1"),
		Ident:    aws.String("fluentd"),
		ProcID:   aws.String("11111"),
		Message:  aws.String("[error] Syslog test"),
	}

	// panther fields
	expectedRFC3164.PantherLogType = aws.String("Fluentd.Syslog3164")
	checkRFC3164(t, log, expectedRFC3164)
}

func TestRFC3164TypeType(t *testing.T) {
	parser := &RFC3164Parser{}
	require.Equal(t, "Fluentd.Syslog3164", parser.LogType())
}

func checkRFC3164(t *testing.T, log string, expectedRFC3164 *RFC3164) {
	parser := &RFC3164Parser{}
	testutil.EqualPantherLog(t, expectedRFC3164.Log(), parser.Parse(log))
}
