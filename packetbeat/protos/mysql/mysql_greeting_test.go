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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/packetbeat/protos"
	"github.com/elastic/beats/v7/packetbeat/protos/tcp"
)

func TestResultSequenceWrapDoesNotClearUsername(t *testing.T) {
	for _, columns := range []int{9, 10} {
		for _, deprecatedEOF := range []bool{false, true} {
			t.Run(fmt.Sprintf("columns=%d/deprecatedEOF=%v", columns, deprecatedEOF), func(t *testing.T) {
				store := &eventStore{}
				plugin := mysqlModForTests(store)
				t.Cleanup(plugin.Close)
				tuple := testTCPTuple()
				auth := &mysqlAuthState{username: "audit_reader"}
				if deprecatedEOF {
					auth.clientCapabilities = clientDeprecateEOF
				}
				var private protos.ProtocolData = mysqlPrivateData{auth: auth}
				send := func(dir uint8, payload []byte) {
					private = plugin.Parse(&protos.Packet{Payload: payload, Ts: time.Now()}, tuple, dir, private)
				}
				send(tcp.TCPDirectionOriginal, deprecatedEOFRequest("SELECT sequence_wrap"))
				seq := byte(1)
				var response []byte
				packet := func(payload []byte) {
					response = append(response, deprecatedEOFPacket(seq, payload)...)
					seq++
				}
				packet([]byte{byte(columns)})
				for range columns {
					packet(deprecatedEOFColumn("test", "rows", "value"))
				}
				if !deprecatedEOF {
					packet([]byte{0xfe, 0, 0, 2, 0})
				}
				row := make([]byte, 0, columns*2)
				for range columns {
					row = append(row, 1, '1')
				}
				for seq != 0 {
					packet(row)
				}
				if deprecatedEOF {
					packet([]byte{0xfe, 0, 0, 2, 0, 0, 0})
				} else {
					packet([]byte{0xfe, 0, 0, 2, 0})
				}
				send(tcp.TCPDirectionReverse, response)
				assert.Equal(t, "audit_reader", auth.username, "a result ending at sequence zero must not reset authentication")
				send(tcp.TCPDirectionOriginal, deprecatedEOFRequest("SELECT after_wrap"))
				send(tcp.TCPDirectionReverse, deprecatedEOFPacket(1, []byte{0, 0, 0, 2, 0, 0, 0}))
				require.Len(t, store.events, 2, "both transactions must publish")
				for _, event := range store.events {
					username, err := event.Fields.GetValue("user.name")
					assert.NoError(t, err, "both transactions must retain user.name")
					assert.Equal(t, "audit_reader", username, "later SQL must keep the same identity")
				}
			})
		}
	}
}
