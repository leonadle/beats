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

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/packetbeat/protos"
	"github.com/elastic/beats/v7/packetbeat/protos/tcp"
	"github.com/elastic/elastic-agent-libs/logp"
)

type usernameTestProtocols struct {
	protos.Protocols
	plugin *mysqlPlugin
}

func (p usernameTestProtocols) GetAllTCP() map[protos.Protocol]protos.TCPPlugin {
	return map[protos.Protocol]protos.TCPPlugin{protos.Lookup("mysql"): p.plugin}
}

func (p usernameTestProtocols) GetTCP(proto protos.Protocol) protos.TCPPlugin {
	return p.plugin
}

func TestMySQLUsernameThroughTCPGap(t *testing.T) {
	store := &eventStore{}
	plugin := mysqlModForTests(store)
	t.Cleanup(plugin.Close)
	transport, err := tcp.NewTCP(usernameTestProtocols{plugin: plugin}, t.Name(), "test", 0, logp.NewNopLogger())
	require.NoError(t, err, "create the real TCP rssembly layer")
	client := net.ParseIP("192.0.2.1").To4()
	server := net.ParseIP("192.0.2.2").To4()
	clientPort := uint16(45000)
	sequence := [2]uint32{100, 1000}
	send := func(reverse bool, payload []byte) {
		dir := 0
		source, destination := client, server
		srcPort, dstPort := clientPort, uint16(serverPort)
		if reverse {
			dir = 1
			source, destination = server, client
			srcPort, dstPort = dstPort, srcPort
		}
		packet := &protos.Packet{Ts: time.Now(), Tuple: common.NewIPPortTuple(4, source, srcPort, destination, dstPort), Payload: payload}
		transport.Process(nil, &layers.TCP{Seq: sequence[dir], SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort)}, packet)
		sequence[dir] += uint32(len(payload))
	}
	send(false, nil)
	send(true, mysqlWirePacket(0, []byte{0x0a, 0x00}))
	handshake := mysqlHandshakeResponsePacket("audit_reader")
	send(false, handshake[:4])
	send(false, handshake[4:])
	okPacket := mysqlWirePacket(1, []byte{0, 0, 0, 2, 0, 0, 0})
	query := func(sql string) {
		send(false, mysqlWirePacket(0, append([]byte{mysqlCmdQuery}, []byte(sql)...)))
		send(true, okPacket)
	}
	query("SELECT 1")
	// Leave an incomplete request, then skip bytes to force TCP.GapInStream.
	incomplete := mysqlWirePacket(0, append([]byte{mysqlCmdQuery}, []byte("SELECT missing_bytes")...))
	send(false, incomplete[:6])
	sequence[0] += uint32(len(incomplete) - 6)
	query("SELECT 2")
	require.Len(t, store.events, 2, "both complete queries should publish after actual TCP gap handling")
	for _, event := range store.events {
		username, err := event.Fields.GetValue("user.name")
		assert.NoError(t, err, "each event should retain user.name")
		assert.Equal(t, "audit_reader", username, "TCP recovery must retain this connection's username")
	}

	// A different TCP connection must not inherit a previous connection's identity.
	clientPort++
	sequence = [2]uint32{100, 1000}
	send(false, nil)
	query("SELECT 3")
	require.Len(t, store.events, 3, "midstream connection should publish its SQL")
	_, err = store.events[2].Fields.GetValue("user.name")
	assert.Error(t, err, "a connection without a captured handshake must not borrow a username")
	send(true, mysqlWirePacket(0, []byte{0x0a, 0x00}))
	send(false, mysqlHandshakeResponsePacket("other_reader"))
	query("SELECT 4")
	require.Len(t, store.events, 4, "new authenticated connection should publish")
	username, err := store.events[3].Fields.GetValue("user.name")
	assert.NoError(t, err, "new connection should have its own identity")
	assert.Equal(t, "other_reader", username, "identities must be isolated by connection")
}
