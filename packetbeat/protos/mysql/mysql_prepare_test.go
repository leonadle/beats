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
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

//go:build !integration

package mysql

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func prepareResponse(id uint32, params, columns uint16, deprecatedEOF bool) []byte {
	header := make([]byte, 12)
	binary.LittleEndian.PutUint32(header[1:], id)
	binary.LittleEndian.PutUint16(header[5:], columns)
	binary.LittleEndian.PutUint16(header[7:], params)
	response := mysqlWirePacket(1, header)
	seq := byte(2)
	for _, count := range []uint16{params, columns} {
		for range count {
			response = append(response, mysqlWirePacket(seq, deprecatedEOFColumn("test", "userData", "userId"))...)
			seq++
		}
		if count > 0 && !deprecatedEOF {
			response = append(response, mysqlWirePacket(seq, []byte{0xfe, 0, 0, 2, 0})...)
			seq++
		}
	}
	return response
}

func prepareExecuteRequest(id uint32, newTypes bool) []byte {
	payload := make([]byte, 10)
	payload[0] = mysqlCmdStmtExecute
	binary.LittleEndian.PutUint32(payload[1:], id)
	payload[6] = 1               // iteration count
	payload = append(payload, 0) // null bitmap
	if newTypes {
		payload = append(payload, 1, 3, 0) // new parameter type: signed LONG
	} else {
		payload = append(payload, 0)
	}
	payload = append(payload, 2, 0, 0, 0)
	return mysqlWirePacket(0, payload)
}

func TestPrepareMetadataDoesNotBecomeResultRows(t *testing.T) {
	for _, deprecated := range []bool{false, true} {
		for _, counts := range [][2]uint16{{0, 0}, {1, 0}, {0, 2}, {2, 3}} {
			t.Run(fmt.Sprintf("deprecated=%v/params=%d/columns=%d", deprecated, counts[0], counts[1]), func(t *testing.T) {
				response := prepareResponse(166, counts[0], counts[1], deprecated)
				stream := newTestMySQLStream(nil, false)
				stream.auth.lastCommand = mysqlCmdStmtPrepare
				if deprecated {
					stream.auth.clientCapabilities |= clientDeprecateEOF
				}
				// Every header and metadata payload may span TCP segments.
				for i, b := range response {
					stream.data = append(stream.data, b)
					ok, complete := mysqlMessageParser(stream)
					require.True(t, ok, "PREPARE metadata byte %d must parse", i)
					assert.Equal(t, i == len(response)-1, complete, "wait for all metadata, byte %d", i)
				}
				assert.Equal(t, 166, stream.message.statementID, "decode fixed-width statement ID")
				assert.Equal(t, int(counts[0]), stream.message.numberOfParams, "parameter count")
				assert.Equal(t, int(counts[1]), stream.message.numberOfFields, "column count")
				assert.Zero(t, stream.message.affectedRows, "PREPARE has no affected rows")
				assert.Zero(t, stream.message.numberOfRows, "metadata is not a result set")
				assert.Equal(t, uint64(len(response)), stream.message.size, "include all metadata in wire size")
			})
		}
	}
}

func TestPrepareMetadataCompactionAndGaps(t *testing.T) {
	response := prepareResponse(166, 4096, 1024, false)
	stream := newTestMySQLStream(response, false)
	stream.auth.lastCommand = mysqlCmdStmtPrepare
	ok, complete := mysqlMessageParser(stream)
	require.True(t, ok, "large parameter and column metadata must parse")
	require.True(t, complete, "consume both metadata blocks and their EOFs")
	assert.Equal(t, uint64(len(response)), stream.message.size, "compaction preserves total wire size")
	assert.Less(t, len(stream.data), mysqlStreamCompactThreshold+1024, "do not retain consumed metadata")
	assert.Zero(t, stream.message.numberOfRows, "metadata never counts as result rows")

	stream = newTestMySQLStream(response[:16], false)
	stream.auth.lastCommand = mysqlCmdStmtPrepare
	ok, complete = mysqlMessageParser(stream)
	require.True(t, ok, "PREPARE header must parse before metadata arrives")
	require.False(t, complete, "metadata is still missing")
	mysql := mysqlModForTests(nil)
	t.Cleanup(mysql.Close)
	assert.False(t, mysql.messageGap(stream, 10), "a gap must not complete or cache partial PREPARE metadata")
}

func TestPreparePublishesOnlyExecuteEvents(t *testing.T) {
	for _, deprecated := range []bool{false, true} {
		for _, id := range []uint32{0, 1, 17, 166, 250, 251, 252, 253, 254, 255, 256, 65536, 0xffffffff} {
			t.Run(fmt.Sprintf("deprecated=%v/id=%d", deprecated, id), func(t *testing.T) {
				h := newAuthHarness(t)
				h.m.loginSuccess = false
				h.start()
				h.ok(2)
				if deprecated {
					h.private.(mysqlPrivateData).auth.clientCapabilities |= clientDeprecateEOF
				}
				sql := "UPDATE test.userData SET money = money + 1 WHERE userId = ?"
				h.send(true, mysqlWirePacket(0, append([]byte{mysqlCmdStmtPrepare}, sql...)))
				response := prepareResponse(id, 1, 0, deprecated)
				for i := 0; i < len(response); i += 3 {
					h.send(false, response[i:min(i+3, len(response))])
				}
				assert.Empty(t, h.store.events, "successful PREPARE must never be an access event")
				assert.Nil(t, h.m.getTransaction(testTCPTuple().Hashable()), "PREPARE transaction is complete")
				stmt := h.m.getStmtsMap(testTCPTuple().Hashable())[int(id)]
				require.NotNil(t, stmt, "PREPARE must still populate the SQL cache")
				assert.Equal(t, sql, stmt.query, "cache original SQL")
				for i, affected := range []byte{1, 0} {
					h.send(true, prepareExecuteRequest(id, i == 0))
					h.send(false, mysqlWirePacket(1, []byte{0, affected, 0, 2, 0, 0, 0}))
					require.Len(t, h.store.events, i+1, "one access event per execution, no extra PREPARE event")
					fields := h.store.events[i].Fields
					assertField(t, fields, "query", sql)
					assertField(t, fields, "method", "UPDATE")
					assertField(t, fields, "event.action", "query")
					assertField(t, fields, "mysql.affected_rows", uint64(affected))
					assertField(t, fields, "user.name", "audit_test")
					assert.Equal(t, []string{"2"}, fields["params"], "parameter types survive statement reuse")
				}
				closePayload := make([]byte, 5)
				closePayload[0] = mysqlCmdStmtClose
				binary.LittleEndian.PutUint32(closePayload[1:], id)
				h.send(true, mysqlWirePacket(0, closePayload))
				assert.NotContains(t, h.m.getStmtsMap(testTCPTuple().Hashable()), int(id), "CLOSE evicts cached SQL")
				assert.Len(t, h.store.events, 2, "CLOSE must not publish an access event")
			})
		}
	}
}

func TestFailedPrepareRemainsAuditable(t *testing.T) {
	h := newAuthHarness(t)
	h.m.loginSuccess = false
	h.start()
	h.ok(2)
	sql := "UPDATE test.userData SET missing_column = ? WHERE userId = ?"
	h.send(true, mysqlWirePacket(0, append([]byte{mysqlCmdStmtPrepare}, sql...)))
	h.send(false, mysqlWirePacket(1, append([]byte{0xff, 0x1e, 0x04}, []byte("#42S22Unknown column")...)))
	require.Len(t, h.store.events, 1, "failed PREPARE must retain its audit event")
	fields := h.store.events[0].Fields
	assertField(t, fields, "query", sql)
	assertField(t, fields, "event.action", "prepare")
	assertField(t, fields, "status", "Error")
	assertField(t, fields, "mysql.error_code", uint16(1054))
	_, err := fields.GetValue("mysql.affected_rows")
	assert.Error(t, err, "failed PREPARE has no affected-row value")
	assert.Empty(t, h.m.getStmtsMap(testTCPTuple().Hashable()), "failed PREPARE must not cache a statement")
	h.query("UPDATE test.userData SET money = money + 1 WHERE userId = 2")
	require.Len(t, h.store.events, 2, "normal queries must still parse after a PREPARE failure")
	assertField(t, h.store.events[1].Fields, "event.action", "query")
}
