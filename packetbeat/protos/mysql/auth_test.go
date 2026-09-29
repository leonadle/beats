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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/packetbeat/protos"
	"github.com/elastic/beats/v7/packetbeat/protos/tcp"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

func clientInfoHandshake(caps uint32, attrs ...string) []byte {
	p := make([]byte, 32)
	binary.LittleEndian.PutUint32(p, caps|1<<9)
	p = append(p, []byte("audit_test\x00")...)
	// Empty synthetic auth data, never a real password or hash.
	p = append(p, 0)
	if caps&clientConnectWithDB != 0 {
		p = append(p, []byte("example\x00")...)
	}
	if caps&clientPluginAuth != 0 {
		p = append(p, []byte("mysql_native_password\x00")...)
	}
	var kv []byte
	for _, value := range attrs {
		kv = append(kv, byte(len(value)))
		kv = append(kv, value...)
	}
	if caps&clientConnectAttrs != 0 {
		p = append(p, byte(len(kv)))
		p = append(p, kv...)
	}
	return mysqlWirePacket(1, p)
}

func assertField(t *testing.T, event mapstr.M, path string, want interface{}) {
	t.Helper()
	got, err := event.GetValue(path)
	assert.NoError(t, err, "expected field %s", path)
	assert.Equal(t, want, got, "unexpected %s", path)
}

func TestClientToolAttributes(t *testing.T) {
	for _, authMode := range []uint32{0, clientSecureConnection, clientPluginAuthLenenc} {
		caps := clientConnectAttrs | clientConnectWithDB | clientPluginAuth | authMode
		assert.Equal(t, "MYSQLND", parseClientTool(clientInfoHandshake(caps, "_client_name", "mysqlnd")), "driver fallback")
		assert.Equal(t, "MYSQL", parseClientTool(clientInfoHandshake(caps, "_client_name", "mysqlnd", "program_name", "mysql")), "program takes precedence")
		assert.Equal(t, "UNKNOWN", parseClientTool(clientInfoHandshake(caps)), "no attributes is unknown")
		for _, bad := range []string{"", "bad\x00name", "bad\nname", "\xff", strings.Repeat("a", 129)} {
			assert.Equal(t, "UNKNOWN", parseClientTool(clientInfoHandshake(caps, "_client_name", bad)), "invalid tool must not leak into events")
		}
		full := clientInfoHandshake(caps, "_client_name", "mysqlnd")
		for i := 0; i < len(full); i++ {
			assert.Equal(t, "UNKNOWN", parseClientTool(full[:i]), "truncated handshake at %d", i)
		}
	}
	assert.Equal(t, "UNKNOWN", parseClientTool(clientInfoHandshake(0)), "client without attributes")
}

func TestLoginConfig(t *testing.T) {
	c := defaultConfig
	assert.False(t, c.Login.Enabled, "login opt-in")
	assert.False(t, c.ClientInfo.Enabled, "client info opt-in")
	assert.NoError(t, c.Validate(), "defaults must be valid")
	c.Login.Enabled = true
	c.Login.Outcomes = nil
	assert.Error(t, c.Validate(), "enabled empty outcomes rejected")
	c.Login.Outcomes = []string{"OK"}
	assert.Error(t, c.Validate(), "status is not a config outcome")
	c.Login.Outcomes = []string{"failure"}
	assert.NoError(t, c.Validate(), "failure-only supported")
}

func TestLoginConfigUnpack(t *testing.T) {
	for _, outcomes := range [][]string{{"failure"}, {"success"}, {"success", "failure"}, {}, {"Error"}} {
		cfg, err := conf.NewConfigFrom(map[string]interface{}{
			"login":       map[string]interface{}{"enabled": true, "outcomes": outcomes},
			"client_info": map[string]interface{}{"enabled": true},
		})
		require.NoError(t, err, "construct config")
		c := defaultConfig
		err = cfg.Unpack(&c)
		if len(outcomes) == 0 || outcomes[0] == "Error" {
			assert.Error(t, err, "invalid outcomes must fail config unpack")
			continue
		}
		require.NoError(t, err, "unpack valid config")
		assert.Equal(t, outcomes, c.Login.Outcomes, "configured list replaces defaults")
		p := &mysqlPlugin{}
		p.setFromConfig(&c)
		assert.True(t, p.clientInfoEnabled, "client tool config is applied")
		assert.Equal(t, len(outcomes) == 2 || outcomes[0] == "success", p.loginSuccess, "success selection")
		assert.Equal(t, len(outcomes) == 2 || outcomes[0] == "failure", p.loginFailure, "failure selection")
	}
}

func TestAuthenticationBoundsAndInvalidation(t *testing.T) {
	h := newAuthHarness(t)
	h.start()
	large := mysqlWirePacket(2, append([]byte{1}, make([]byte, 1<<20)...))
	for i := 0; i < len(large); i += 4096 {
		h.send(false, large[i:min(i+4096, len(large))])
	}
	assert.Empty(t, h.store.events, "large intermediate packet does not emit login")
	h.ok(3)
	require.Len(t, h.store.events, 1, "bounded auth packet retains framing")
	h.send(true, mysqlWirePacket(0, []byte{0x11, 'x', 0}))
	assert.Zero(t, h.m.authenticatedUsers.Size(), "COM_CHANGE_USER evicts old identity")
	h.query("SELECT 1")
	require.Len(t, h.store.events, 2, "query still parsed after unsupported change user")
	_, err := h.store.events[1].Fields.GetValue("user.name")
	assert.Error(t, err, "do not misattribute a switched session")
	h.start()
	h.ok(2)
	require.Len(t, h.store.events, 3, "new greeting resets blocked auth state")
}

func BenchmarkClientToolAttributes(b *testing.B) {
	frame := clientInfoHandshake(clientSecureConnection|clientConnectAttrs, "_client_name", "mysqlnd")
	b.ReportAllocs()
	for b.Loop() {
		parseClientTool(frame)
	}
}

// authHarness feeds synthetic MySQL frames through the real protocol entry point.
type authHarness struct {
	m       *mysqlPlugin
	store   *eventStore
	private protos.ProtocolData
	ts      time.Time
}

func newAuthHarness(t *testing.T) *authHarness {
	s := &eventStore{}
	m := mysqlModForTests(s)
	t.Cleanup(m.Close)
	m.loginSuccess, m.loginFailure, m.clientInfoEnabled = true, true, true
	return &authHarness{m: m, store: s, ts: time.Unix(1700000000, 0)}
}

func (h *authHarness) send(client bool, frame []byte) {
	dir := uint8(tcp.TCPDirectionReverse)
	if client {
		dir = tcp.TCPDirectionOriginal
	}
	h.ts = h.ts.Add(time.Millisecond)
	h.private = h.m.Parse(&protos.Packet{Ts: h.ts, Payload: frame}, testTCPTuple(), dir, h.private)
}

func (h *authHarness) start() {
	h.send(false, mysqlWirePacket(0, []byte{0x0a, 0}))
	frame := clientInfoHandshake(clientSecureConnection|clientConnectAttrs, "_client_name", "mysqlnd")
	h.send(true, frame[:3])
	h.send(true, frame[3:])
}

func (h *authHarness) ok(seq byte) { h.send(false, mysqlWirePacket(seq, []byte{0, 0, 0, 2, 0, 0, 0})) }
func (h *authHarness) fail(seq byte) {
	h.send(false, mysqlWirePacket(seq, append([]byte{0xff, 0x15, 0x04}, []byte("#28000Access denied (synthetic)")...)))
}
func (h *authHarness) query(sql string) {
	h.send(true, mysqlWirePacket(0, append([]byte{mysqlCmdQuery}, sql...)))
	h.ok(1)
}

func TestLoginAndLongConnectionQueries(t *testing.T) {
	h := newAuthHarness(t)
	h.start()
	assert.Empty(t, h.store.events, "handshake alone is not a login result")
	h.ok(2)
	h.query("SELECT 1")
	h.private = nil // TCP reassembly expiration must retain identity and tool.
	h.ts = h.ts.Add(time.Minute)
	h.query("SELECT 2")
	require.Len(t, h.store.events, 3, "one login and two SQL events")
	for i, event := range h.store.events {
		assertField(t, event.Fields, "user.name", "audit_test")
		assertField(t, event.Fields, "mysql.client.tool", "MYSQLND")
		assertField(t, event.Fields, "status", "OK")
		if i == 0 {
			assertField(t, event.Fields, "event.action", "login")
			assertField(t, event.Fields, "method", "LOGIN")
			assert.NotContains(t, event.Fields, "query", "login is not SQL")
		} else {
			assertField(t, event.Fields, "event.action", "query")
		}
	}
	assertField(t, h.store.events[1].Fields, "query", "SELECT 1")
	assertField(t, h.store.events[2].Fields, "query", "SELECT 2")
}

func TestLoginFailureAndOutcomeSelection(t *testing.T) {
	for _, outcome := range []string{"both", "success", "failure", "disabled"} {
		t.Run(outcome, func(t *testing.T) {
			h := newAuthHarness(t)
			h.m.loginSuccess = outcome == "both" || outcome == "success"
			h.m.loginFailure = outcome == "both" || outcome == "failure"
			h.start()
			h.fail(2)
			if h.m.loginFailure {
				require.Len(t, h.store.events, 1, "failure is selected")
				f := h.store.events[0].Fields
				assertField(t, f, "status", "Error")
				assertField(t, f, "mysql.error_code", uint16(1045))
				assertField(t, f, "mysql.error_message", "Access denied (synthetic)")
				assertField(t, f, "user.name", "audit_test")
			} else {
				assert.Empty(t, h.store.events, "failure was filtered before publication")
			}
			assert.Zero(t, h.m.authenticatedUsers.Size(), "failed identity is not cached")
			h.store.events = nil
			h.private = nil
			h.start()
			h.ok(2)
			h.query("SELECT 1")
			want := 1
			if h.m.loginSuccess {
				want++
			}
			require.Len(t, h.store.events, want, "outcomes never filters SQL")
			assertField(t, h.store.events[want-1].Fields, "mysql.client.tool", "MYSQLND")
		})
	}
}

func TestLoginAuthRounds(t *testing.T) {
	for _, mode := range []string{"switch", "fast", "full", "empty"} {
		t.Run(mode, func(t *testing.T) {
			h := newAuthHarness(t)
			h.start()
			seq := byte(2)
			if mode == "switch" || mode == "empty" {
				h.send(false, mysqlWirePacket(seq, []byte("\xfemysql_native_password\x00challenge")))
				seq++
				p := []byte("synthetic-not-secret")
				if mode == "empty" {
					p = nil
				}
				h.send(true, mysqlWirePacket(seq, p))
				seq++
			} else {
				marker := byte(3)
				if mode == "full" {
					marker = 4
				}
				h.send(false, mysqlWirePacket(seq, []byte{1, marker}))
				seq++
				if mode == "full" {
					h.send(true, mysqlWirePacket(seq, []byte{2}))
					seq++
					h.send(false, mysqlWirePacket(seq, []byte("\x01synthetic-key")))
					seq++
					h.send(true, mysqlWirePacket(seq, []byte("synthetic-response")))
					seq++
				}
			}
			assert.Empty(t, h.store.events, "intermediate auth is not a result")
			h.ok(seq)
			require.Len(t, h.store.events, 1, "exactly one final result")
			assertField(t, h.store.events[0].Fields, "status", "OK")
			h.query("SELECT 1")
			require.Len(t, h.store.events, 2, "SQL after multi-round authentication remains aligned")
		})
	}
}

func TestIncompleteAuthenticationDoesNotEmitLogin(t *testing.T) {
	for _, mode := range []string{"gap", "sequence", "timeout", "tls", "missing-final", "midstream"} {
		t.Run(mode, func(t *testing.T) {
			h := newAuthHarness(t)
			if mode == "tls" {
				h.send(false, mysqlWirePacket(0, []byte{10, 0}))
				p := make([]byte, 32)
				binary.LittleEndian.PutUint32(p, clientSSL|1<<9)
				h.send(true, mysqlWirePacket(1, p))
				h.ok(2)
			} else if mode == "midstream" {
				h.query("SELECT 1")
			} else {
				h.start()
				switch mode {
				case "gap":
					h.m.GapInStream(testTCPTuple(), tcp.TCPDirectionReverse, 4, h.private)
					h.ok(2)
				case "sequence":
					h.ok(4)
				case "timeout":
					h.ts = h.ts.Add(time.Minute)
					h.ok(2)
				case "missing-final":
					h.query("SELECT 1")
				}
			}
			for _, event := range h.store.events {
				assertField(t, event.Fields, "event.action", "query")
			}
		})
	}
}

func TestClientInfoDisabled(t *testing.T) {
	h := newAuthHarness(t)
	h.m.clientInfoEnabled = false
	h.start()
	h.ok(2)
	h.query("SELECT 1")
	require.Len(t, h.store.events, 2, "login and SQL still emitted")
	for _, event := range h.store.events {
		_, err := event.Fields.GetValue("mysql.client.tool")
		assert.Error(t, err, "disabled tool must be absent")
	}
}

func FuzzClientTool(f *testing.F) {
	f.Add(clientInfoHandshake(clientSecureConnection|clientConnectAttrs, "_client_name", "mysqlnd"))
	f.Add([]byte{0xfe, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, raw []byte) {
		tool := parseClientTool(raw)
		assert.LessOrEqual(t, len(tool), maxIdentityName, "client tool storage stays bounded")
	})
}
