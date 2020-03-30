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

var TracerouteDesc = `Zeek Traceroute detection
Reference: https://docs.zeek.org/en/current/scripts/policy/misc/detect-traceroute/main.zeek.html#type-Traceroute::Info`

// nolint:lll
type Traceroute struct {
	Ts    *timestamp.UnixFloat `json:"ts" validate:"required" description:"Timestamp"`
	Src   *string              `json:"src" validate:"required" description:"Address initiating the traceroute."`
	Dst   *string              `json:"dst" validate:"required" description:"Destination address of the traceroute."`
	Proto *string              `json:"proto" validate:"required" description:"Protocol used for the traceroute."`
	parsers.PantherLog
}

// TracerouteParser parses zeek ssh logs
type TracerouteParser struct{}

func (p *TracerouteParser) New() parsers.LogParser {
	return &TracerouteParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *TracerouteParser) Parse(log string) []*parsers.PantherLog {
	Traceroute := &Traceroute{}

	err := jsoniter.UnmarshalFromString(log, Traceroute)
	if err != nil {
		zap.L().Debug("failed to parse log", zap.Error(err))
		return nil
	}

	Traceroute.updatePantherFields(p)

	if err := parsers.Validator.Struct(Traceroute); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}

	return Traceroute.Logs()
}

// LogType returns the log type supported by this parser
func (p *TracerouteParser) LogType() string {
	return "Zeek.Traceroute"
}

func (event *Traceroute) updatePantherFields(p *TracerouteParser) {
	event.SetCoreFields(p.LogType(), (*timestamp.RFC3339)(event.Ts), event)
}
