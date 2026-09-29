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

//go:build !integration

package mysql

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/beats/v7/packetbeat/protos"
	"github.com/elastic/beats/v7/packetbeat/protos/tcp"
)

func deprecatedEOFPacket(seq byte, payload []byte) []byte {
	packet := make([]byte, 4, 4+len(payload))
	packet[0] = byte(len(payload))
	packet[1] = byte(len(payload) >> 8)
	packet[2] = byte(len(payload) >> 16)
	packet[3] = seq
	return append(packet, payload...)
}

func deprecatedEOFRequest(query string) []byte {
	return deprecatedEOFPacket(0, append([]byte{mysqlCmdQuery}, []byte(query)...))
}

func deprecatedEOFColumn(schema, table, name string) []byte {
	var payload []byte
	appendString := func(value string) {
		payload = append(payload, byte(len(value)))
		payload = append(payload, value...)
	}
	appendString("def")
	appendString(schema)
	appendString(table)
	appendString(table)
	appendString(name)
	appendString(name)
	payload = append(payload,
		0x0c,
		0x21, 0x00,
		0x0b, 0x00, 0x00, 0x00,
		0x03,
		0x00, 0x00,
		0x00,
		0x00, 0x00,
	)
	return payload
}

func deprecatedEOFResult(schema, table string) []byte {
	var response []byte
	response = append(response, deprecatedEOFPacket(1, []byte{1})...)
	response = append(response, deprecatedEOFPacket(2, deprecatedEOFColumn(schema, table, "id"))...)
	// CLIENT_DEPRECATE_EOF omits the metadata EOF packet.
	response = append(response, deprecatedEOFPacket(3, []byte{1, '1'})...)
	// Result-set OK packet uses the EOF-compatible 0xfe header.
	response = append(response, deprecatedEOFPacket(4, []byte{0xfe, 0, 0, 0x02, 0, 0, 0})...)
	return response
}

func TestMySQLParserClientDeprecateEOFOmitsMetadataTerminator(t *testing.T) {
	stream := newTestMySQLStream(deprecatedEOFResult("t591", "sale"), false)
	stream.auth = &mysqlAuthState{clientCapabilities: clientDeprecateEOF}

	ok, complete := mysqlMessageParser(stream)
	assert.True(t, ok)
	assert.True(t, complete)
	assert.Equal(t, 1, stream.message.numberOfFields)
	assert.Equal(t, 1, stream.message.numberOfRows)
	assert.Equal(t, "t591.sale", stream.message.tables)
}

func TestConsecutiveQueriesClientDeprecateEOFStayPaired(t *testing.T) {
	store := &eventStore{}
	mysql := mysqlModForTests(store)
	t.Cleanup(mysql.Close)
	tuple := testTCPTuple()
	private := protos.ProtocolData(mysqlPrivateData{
		auth: &mysqlAuthState{clientCapabilities: clientDeprecateEOF},
	})
	now := time.Date(2026, 9, 20, 8, 9, 0, 0, time.UTC)

	send := func(dir uint8, payload []byte, at time.Time) {
		private = mysql.Parse(&protos.Packet{Payload: payload, Ts: at}, tuple, dir, private)
	}

	saleQuery := "select /* pair_sale */ * from t591.sale limit 10"
	usersQuery := "select /* pair_users */ * from t591.users limit 10"
	send(tcp.TCPDirectionOriginal, deprecatedEOFRequest(saleQuery), now)
	send(tcp.TCPDirectionReverse, deprecatedEOFResult("t591", "sale"), now.Add(time.Millisecond))
	send(tcp.TCPDirectionOriginal, deprecatedEOFRequest(usersQuery), now.Add(time.Second))
	send(tcp.TCPDirectionReverse, deprecatedEOFResult("t591", "users"), now.Add(time.Second+time.Millisecond))

	if assert.Len(t, store.events, 2) {
		assert.Equal(t, saleQuery, store.events[0].Fields["query"])
		assert.Equal(t, "t591.sale", store.events[0].Fields["path"])
		assert.Equal(t, usersQuery, store.events[1].Fields["query"])
		assert.Equal(t, "t591.users", store.events[1].Fields["path"])
	}
}

func TestParseHandshakeResponseCapabilities(t *testing.T) {
	payload := make([]byte, 32)
	binary.LittleEndian.PutUint32(payload[:4], clientDeprecateEOF|0x200)
	raw := deprecatedEOFPacket(1, payload)

	capabilities, ok := parseHandshakeResponseCapabilities(raw)
	assert.True(t, ok)
	assert.NotZero(t, capabilities&clientDeprecateEOF)

	_, ok = parseHandshakeResponseCapabilities(raw[:7])
	assert.False(t, ok)
}
