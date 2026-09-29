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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/libbeat/common"
)

func TestAuthenticatedUserKeySurvivesTCPStreamRecreation(t *testing.T) {
	mysql := mysqlPlugin{ports: []int{3306}}
	client := net.ParseIP("192.0.2.10").To4()
	server := net.ParseIP("192.0.2.20").To4()
	newTuple := func(src net.IP, srcPort uint16, dst net.IP, dstPort uint16, streamID uint32) common.TCPTuple {
		ipPort := common.NewIPPortTuple(4, src, srcPort, dst, dstPort)
		return common.TCPTupleFromIPPort(&ipPort, streamID)
	}

	first := newTuple(client, 45000, server, 3306, 1)
	recreated := newTuple(client, 45000, server, 3306, 99)
	reverse := newTuple(server, 3306, client, 45000, 100)

	want := mysql.authenticatedUserKey(&first)
	if got := mysql.authenticatedUserKey(&recreated); got != want {
		t.Fatalf("TCP StreamID must not change authenticated user key")
	}
	if got := mysql.authenticatedUserKey(&reverse); got != want {
		t.Fatalf("packet direction must not change authenticated user key")
	}
}

func TestLargeResponseMessageKeepsBoundedPrefixAndPacketBoundary(t *testing.T) {
	for _, kind := range []struct {
		name   string
		prefix []byte
	}{
		{"ok", []byte{0, 0, 0, 2, 0, 0, 0}},
		{"error", []byte{0xff, 0x15, 4, '#', 'H', 'Y', '0', '0', '0'}},
		{"ignored", []byte{0x11}},
	} {
		t.Run(kind.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte{'x'}, 4<<20)
			copy(payload, kind.prefix)
			wire := mysqlWirePacket(1, payload)
			next := mysqlWirePacket(1, []byte{0, 0, 0, 2, 0, 0, 0})
			stream := newTestMySQLStream(nil, false)
			const chunkSize = 16 << 10
			for offset := 0; offset < len(wire); {
				end := min(offset+chunkSize, len(wire))
				stream.data = append(stream.data, wire[offset:end]...)
				last := end == len(wire)
				if last {
					stream.data = append(stream.data, next...)
				}
				ok, complete := mysqlMessageParser(stream)
				require.True(t, ok, "valid length-framed response must remain parseable")
				require.Equal(t, last, complete, "do not complete before all declared bytes have arrived")
				require.LessOrEqual(t, len(stream.data), maxPayloadSize+len(next), "partial response must not retain its entire payload")
				require.Less(t, cap(stream.data), 3*maxPayloadSize, "backing allocation must also remain bounded")
				offset = end
			}
			assert.Equal(t, uint64(len(wire)), stream.message.size, "wire byte accounting includes discarded bytes")
			assert.True(t, stream.message.isTruncated, "bounded payload must be marked truncated")
			assert.Equal(t, next, stream.data[stream.parseOffset:], "coalesced next response must remain intact")
			stream.prepareForNewMessage()
			stream.message = &mysqlMessage{}
			ok, complete := mysqlMessageParser(stream)
			assert.True(t, ok, "next response must still parse")
			assert.True(t, complete, "next response must complete independently")
		})
	}
}

func TestLargeSQLRequestIsNotCompacted(t *testing.T) {
	payload := append([]byte{mysqlCmdQuery}, bytes.Repeat([]byte{'q'}, 2*maxPayloadSize)...)
	wire := mysqlWirePacket(0, payload)
	stream := newTestMySQLStream(wire, true)
	ok, complete := mysqlMessageParser(stream)
	require.True(t, ok, "large SQL request must parse")
	require.True(t, complete, "large SQL request must complete")
	assert.Equal(t, string(payload[1:]), stream.message.query, "response limits must never truncate SQL text")
	assert.False(t, stream.message.isTruncated, "client payload must not be discarded")
}

func TestShortResponseDoesNotReadCoalescedNextPacket(t *testing.T) {
	for _, payload := range [][]byte{{0}, {0, 0}, {0xff, 1, 0}} {
		wire := mysqlWirePacket(1, payload)
		wire = append(wire, mysqlWirePacket(1, []byte{0, 0, 0, 2, 0, 0, 0})...)
		stream := newTestMySQLStream(wire, false)
		ok, complete := mysqlMessageParser(stream)
		assert.False(t, ok, "a complete but malformed response must be rejected without borrowing next-packet bytes")
		assert.False(t, complete, "a malformed response must not become a transaction")
	}
}

func TestTwelveByteOKIsNotMistakenForPrepareResponse(t *testing.T) {
	payload := append([]byte{0, 0, 0, 2, 0, 0, 0}, []byte("hello")...)
	stream := newTestMySQLStream(mysqlWirePacket(1, payload), false)
	stream.auth.lastCommand = mysqlCmdQuery
	ok, complete := mysqlMessageParser(stream)
	require.True(t, ok, "ordinary OK with an info string must parse")
	assert.True(t, complete, "ordinary OK must not await prepared-statement metadata")
	assert.Zero(t, stream.message.statementID, "ordinary OK must not create a prepared statement")
}

func TestPrepareWithNoMetadataCompletes(t *testing.T) {
	payload := make([]byte, 12)
	payload[1] = 1
	stream := newTestMySQLStream(mysqlWirePacket(1, payload), false)
	stream.auth.lastCommand = mysqlCmdStmtPrepare
	ok, complete := mysqlMessageParser(stream)
	require.True(t, ok, "PREPARE_OK with no metadata must parse")
	assert.True(t, complete, "zero-field zero-parameter prepare must not pin a stream waiting forever")
	assert.Equal(t, 1, stream.message.statementID, "prepare statement ID must be preserved")
}

func TestPrepareForNewMessageReleasesConsumedBuffer(t *testing.T) {
	const bufferSize = 1 << 20
	stream := mysqlStream{
		data:        make([]byte, bufferSize),
		parseOffset: bufferSize,
	}
	stream.prepareForNewMessage()
	if stream.data != nil {
		t.Fatalf("fully consumed buffer was retained: len=%d cap=%d", len(stream.data), cap(stream.data))
	}

	stream.data = make([]byte, bufferSize)
	copy(stream.data[bufferSize-4:], "tail")
	stream.parseOffset = bufferSize - 4
	stream.prepareForNewMessage()
	if got := string(stream.data); got != "tail" {
		t.Fatalf("unconsumed bytes changed: got %q", got)
	}
	if cap(stream.data) >= bufferSize {
		t.Fatalf("partial packet retained the consumed %d-byte backing buffer", bufferSize)
	}
}

func TestCompactParsedResponseReleasesConsumedBuffer(t *testing.T) {
	const captured = "captured-response"
	const tail = "next-packet"
	bufferSize := 2 * mysqlStreamCompactThreshold
	data := make([]byte, bufferSize)
	copy(data, captured)
	copy(data[bufferSize-len(tail):], tail)
	parseOffset := bufferSize - len(tail)
	message := &mysqlMessage{end: len(captured)}
	stream := mysqlStream{
		data:        data,
		parseOffset: parseOffset,
		parseState:  mysqlStateEatRows,
		message:     message,
	}

	stream.compactParsedResponse()

	if got, want := string(stream.data), captured+tail; got != want {
		t.Fatalf("retained bytes changed: got %q, want %q", got, want)
	}
	if cap(stream.data) >= mysqlStreamCompactThreshold {
		t.Fatalf("compaction retained a large backing buffer: cap=%d", cap(stream.data))
	}
	if got, want := stream.parseOffset, message.end; got != want {
		t.Fatalf("parse offset=%d, want %d", got, want)
	}
}

func TestConnectionTimeoutOnlyRetainsReassemblyForTransaction(t *testing.T) {
	mysql := mysqlPlugin{
		transactionTimeout: 10 * time.Second,
		connectionTimeout:  8 * time.Hour,
	}
	if got, want := mysql.ConnectionTimeout(), mysql.transactionTimeout; got != want {
		t.Fatalf("TCP reassembly timeout=%s, want %s", got, want)
	}
}
