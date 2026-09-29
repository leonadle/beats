// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package mysql

import (
	"bytes"
	"encoding/binary"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/packetbeat/pb"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

const (
	clientConnectWithDB    uint32 = 1 << 3
	clientSSL              uint32 = 1 << 11
	clientSecureConnection uint32 = 1 << 15
	clientPluginAuth       uint32 = 1 << 19
	clientConnectAttrs     uint32 = 1 << 20
	clientPluginAuthLenenc uint32 = 1 << 21
	maxAuthPrefix                 = 16 * 1024
	maxIdentityName               = 128
	maxIdentityEntries            = 65536
	authTimeout                   = 30 * time.Second
)

func toolOrUnknown(tool string) string {
	if tool == "" {
		return "UNKNOWN"
	}
	return tool
}

// Attribute cursors only reference the bounded handshake prefix. Authentication
// response bytes are skipped, never copied into connection state or events.
func skipNull(data []byte, off int) (int, bool) {
	if off < 0 || off >= len(data) {
		return off, false
	}
	end := bytes.IndexByte(data[off:], 0)
	return off + end + 1, end >= 0
}

func authLength(data []byte, off int) (int, int, bool) {
	if off < 0 || off >= len(data) {
		return 0, off, false
	}
	marker := data[off]
	off++
	var size uint64
	switch {
	case marker < 0xfb:
		size = uint64(marker)
	case marker == 0xfc && len(data)-off >= 2:
		size = uint64(binary.LittleEndian.Uint16(data[off:]))
		off += 2
	case marker == 0xfd && len(data)-off >= 3:
		size = uint64(leUint24(data[off : off+3]))
		off += 3
	case marker == 0xfe && len(data)-off >= 8:
		size = binary.LittleEndian.Uint64(data[off:])
		off += 8
	default:
		return 0, off, false
	}
	if size > uint64(len(data)-off) {
		return 0, off, false
	}
	return int(size), off, true
}

func parseClientTool(raw []byte) string {
	if len(raw) > maxAuthPrefix {
		raw = raw[:maxAuthPrefix]
	}
	capabilities, ok := parseHandshakeResponseCapabilities(raw)
	if !ok || capabilities&clientConnectAttrs == 0 || len(raw) <= 36 {
		return "UNKNOWN"
	}
	off, ok := skipNull(raw, 36)
	if !ok {
		return "UNKNOWN"
	}
	switch {
	case capabilities&clientPluginAuthLenenc != 0:
		length, start, valid := authLength(raw, off)
		if !valid {
			return "UNKNOWN"
		}
		off = start + length
	case capabilities&clientSecureConnection != 0:
		if off >= len(raw) || int(raw[off]) > len(raw)-off-1 {
			return "UNKNOWN"
		}
		off += 1 + int(raw[off])
	default:
		off, ok = skipNull(raw, off)
		if !ok {
			return "UNKNOWN"
		}
	}
	if capabilities&clientConnectWithDB != 0 {
		off, ok = skipNull(raw, off)
		if !ok {
			return "UNKNOWN"
		}
	}
	if capabilities&clientPluginAuth != 0 {
		off, ok = skipNull(raw, off)
		if !ok {
			return "UNKNOWN"
		}
	}
	length, start, ok := authLength(raw, off)
	if !ok {
		return "UNKNOWN"
	}
	attrs := raw[start : start+length]
	var program, driver string
	for off = 0; off < len(attrs); {
		keyLen, keyStart, valid := authLength(attrs, off)
		if !valid {
			return "UNKNOWN"
		}
		valueLen, valueStart, valid := authLength(attrs, keyStart+keyLen)
		if !valid {
			return "UNKNOWN"
		}
		key := attrs[keyStart : keyStart+keyLen]
		value := attrs[valueStart : valueStart+valueLen]
		if bytes.Equal(key, []byte("program_name")) {
			program = normalizeTool(value)
		} else if bytes.Equal(key, []byte("_client_name")) {
			driver = normalizeTool(value)
		}
		off = valueStart + valueLen
	}
	if program != "" {
		return program
	}
	return toolOrUnknown(driver)
}

func normalizeTool(value []byte) string {
	if len(value) > maxIdentityName || !utf8.Valid(value) {
		return ""
	}
	for _, r := range string(value) {
		if unicode.IsControl(r) {
			return ""
		}
	}
	tool := strings.ToUpper(strings.TrimSpace(string(value)))
	if len(tool) > maxIdentityName {
		return ""
	}
	return tool
}

func (mysql *mysqlPlugin) handleAuthentication(tuple *common.TCPTuple, stream *mysqlStream, raw []byte) {
	auth, message := stream.auth, stream.message
	if auth == nil {
		return
	}
	key := mysql.authenticatedUserKey(tuple)
	if message.isServerGreeting {
		mysql.authenticatedUsers.Delete(key)
		*auth = mysqlAuthState{
			awaitingHandshakeResponse: true, nextSequence: message.seq + 1,
			authStarted: message.ts, collectClientInfo: mysql.clientInfoEnabled,
		}
		return
	}
	if message.isHandshakeResponse {
		if auth.clientCapabilities&clientSSL != 0 && int(message.packetLength) == 32 {
			auth.encrypted = true
			auth.username, auth.clientTool = "", ""
			return
		}
		if len(raw) <= 36 || bytes.IndexByte(raw[36:], 0) < 0 || bytes.IndexByte(raw[36:], 0) > maxIdentityName {
			auth.pending, auth.blocked = false, true
			auth.username, auth.clientTool = "", ""
			return
		}
		auth.pending = true
		auth.nextSequence = message.seq + 1
		auth.authStarted = message.ts
		return
	}
	// COM_CHANGE_USER is not an initial login. Do not attribute later SQL to
	// the previous account when account switching has not been decoded.
	if stream.isClient && message.seq == 0 && message.typ == 0x11 && !message.isAuthPacket {
		mysql.authenticatedUsers.Delete(key)
		auth.username, auth.clientTool = "", ""
		auth.blocked = true
		return
	}
	if !message.isAuthPacket || auth.blocked || (!auth.pending && !auth.awaitingHandshakeResponse) {
		return
	}
	if message.seq != auth.nextSequence || message.ts.Sub(auth.authStarted) > authTimeout {
		auth.pending, auth.awaitingHandshakeResponse, auth.blocked = false, false, true
		auth.username, auth.clientTool = "", ""
		mysql.authenticatedUsers.Delete(key)
		return
	}
	auth.nextSequence++
	if stream.isClient {
		return
	}
	if len(raw) <= 4 {
		return
	}
	payload := raw[4:]
	var code uint16
	var errorInfo string
	switch payload[0] {
	case 0x00:
		// A final protocol-41 OK includes both length-encoded integers and
		// status/warnings. A caching_sha2 fast-auth marker (01 03) is not OK.
		_, off, complete, err := readLinteger(payload, 1)
		if err != nil || !complete {
			return
		}
		_, off, complete, err = readLinteger(payload, off)
		if err != nil || !complete || len(payload)-off < 4 {
			return
		}
	case 0xff:
		if len(payload) < 3 {
			return
		}
		code = binary.LittleEndian.Uint16(payload[1:3])
		off := 3
		if len(payload) > 3 && payload[3] == '#' {
			if len(payload) < 9 {
				return
			}
			off = 9
		}
		errorInfo = strings.ToValidUTF8(string(payload[off:min(len(payload), off+2048)]), "?")
	case 0xfe, 0x01, 0x02:
		return // AuthSwitchRequest, AuthMoreData, AuthNextFactor.
	default:
		return
	}
	success := payload[0] == 0x00
	if (success && mysql.loginSuccess) || (!success && mysql.loginFailure) {
		mysql.publishLogin(tuple, auth, message.ts, success, code, errorInfo)
	}
	auth.pending, auth.awaitingHandshakeResponse = false, false
	if !success {
		mysql.authenticatedUsers.Delete(key)
		auth.username, auth.clientTool = "", ""
		auth.blocked = true
	}
}

func (mysql *mysqlPlugin) publishLogin(tuple *common.TCPTuple, auth *mysqlAuthState, end time.Time, success bool, code uint16, errorInfo string) {
	if mysql.results == nil {
		return
	}
	source, destination := common.MakeEndpointPair(tuple.BaseTuple, nil)
	if mysql.isServerPort(tuple.SrcPort) {
		source, destination = destination, source
	}
	event, fields := pb.NewBeatEvent(auth.authStarted)
	fields.SetSource(&source)
	fields.SetDestination(&destination)
	fields.Event.Dataset, fields.Event.Action = "mysql", "login"
	fields.Event.Category = []string{"authentication"}
	fields.Event.Type = []string{"start"}
	fields.Event.Start, fields.Event.End = auth.authStarted, end
	fields.Network.Transport, fields.Network.Protocol = "tcp", "mysql"
	event.Fields["type"], event.Fields["method"] = "mysql", "LOGIN"
	event.Fields["status"] = common.OK_STATUS
	if auth.username != "" {
		event.Fields["user"] = mapstr.M{"name": auth.username}
		fields.AddUser(auth.username)
	}
	mysqlFields := mapstr.M{}
	if mysql.clientInfoEnabled {
		mysqlFields["client"] = mapstr.M{"tool": toolOrUnknown(auth.clientTool)}
	}
	if !success {
		event.Fields["status"] = common.ERROR_STATUS
		mysqlFields["error_code"], mysqlFields["error_message"] = code, errorInfo
	}
	if len(mysqlFields) > 0 {
		event.Fields["mysql"] = mysqlFields
	}
	mysql.results(event)
}
