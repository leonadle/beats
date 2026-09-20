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
	"net"
	"testing"
	"time"

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
