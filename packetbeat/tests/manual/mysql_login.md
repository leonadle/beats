# MySQL login events and client information

Both features are disabled by default. Enable them independently:

```yaml
packetbeat.protocols:
  - type: mysql
    ports: [3306]
    login:
      enabled: true
      outcomes: [success, failure] # [failure] or [success] also supported
    client_info:
      enabled: true
```

`login.outcomes` selects which observed authentication results to publish. It
does not disable username/client parsing and never filters SQL events. Empty
outcomes with login enabled and unrecognized outcome names are configuration
errors. Existing deployments must explicitly enable the new features.

| Field | Login | SQL |
| --- | --- | --- |
| event.action | login | query |
| method | LOGIN | Existing SQL method |
| status | OK / Error | Existing OK / Error |
| user.name / related.user | Attempted username, if observed | Session username, if observed |
| client.ip / client.port | Client endpoint | Client endpoint |
| server.ip / server.port | Server endpoint | Server endpoint |
| source / destination | Same client/server endpoints | Existing endpoints |
| mysql.client.tool | When client_info.enabled | When client_info.enabled |
| mysql.error_code / mysql.error_message | On server ERR | Existing SQL errors |

Login events use `event.category: [authentication]`, `event.type: [start]` and
contain no SQL `query` or `path`. No `event.outcome` is added. A username on a
failed login is a claimed account, not evidence of an authenticated identity.

## Keep the SQL whitelist without dropping login events

Replace the previous unscoped `drop_event` with this processor. Login events
still pass through all global processors; it is this condition that exempts
them from the SQL whitelist, not a hidden bypass of the processor pipeline.

```yaml
processors:
  - drop_event:
      when:
        and:
          - equals:
              event.action: query
          - not:
              or:
                - equals: {method: SELECT}
                - equals: {method: INSERT}
                - equals: {method: UPDATE}
                - equals: {method: DELETE}
                - equals: {method: REPLACE}
                - equals: {method: CREATE}
                - equals: {method: ALTER}
                - equals: {method: DROP}
                - equals: {method: TRUNCATE}
                - equals: {method: RENAME}
```

## Detection boundaries and resource limits

- Requires captured, unencrypted protocol-41 handshake and final server OK/ERR.
  AuthSwitchRequest, AuthMoreData (including caching_sha2 fast/full auth), and
  AuthNextFactor are intermediate packets, not separate login results.
- No invented failure for FIN/RST, packet loss, timeouts, missing greetings or
  TLS. Connections rejected before a greeting are not covered. Incomplete
  authentication cannot be counted reliably for brute-force detection.
- Initial login only. COM_CHANGE_USER invalidates the old identity; account
  switching is not emitted as a new login and subsequent SQL has no attributed
  user until a new observed login. Midstream captures cannot recover attributes.
- The tool is the trimmed uppercase `program_name`, falling back to
  `_client_name` (e.g. MYSQLND), or UNKNOWN. Clients can omit or forge it; it is
  not a security identity and cannot reliably identify a GUI behind a driver.
- Only those two names are read, up to 128 bytes each, from a bounded 16 KiB
  handshake prefix. No authentication response, password, full attribute map,
  or other client attributes are published or saved in identity state.
- Error text is capped at 2048 bytes before UTF-8 repair. Identity cache is
  capped at 65,536 entries, retaining the existing connection_timeout TTL
  (default 8h). When full, existing entries can refresh, but new identities are
  not retained across TCP reassembly expiration. FIN deletes the entry.
- In-progress authentication is bounded by 30s and may be discarded earlier
  by the TCP transaction_timeout (default 10s) during an idle exchange. This
  never creates a synthetic result. Heavy TCP buffers are not retained for 8h.
- Enabling success events adds approximately one published event per successful
  new connection; failure-only reduces output volume. Attribute parsing occurs
  once per handshake, not once per SQL. Actual overhead depends on workload.
- Brute-force alert thresholds/grouping by client/account belong downstream;
  this change emits evidence and does not perform or block attacks.

## Tests

```sh
go test ./packetbeat/protos/mysql
go test -race ./packetbeat/protos/mysql
go test ./packetbeat/protos/mysql -run '^$' -fuzz '^FuzzClientTool$' -fuzztime=10s
```

`mysql_login_probe.py` exercises isolated synthetic loopback traffic on port
13306. It never connects to a business database or needs real credentials.
Use its `generate` and `verify` subcommands with a Packetbeat capture configured
for `lo`, port 13306, JSON console output, and the settings above. The test
includes a success with two SELECTs and a filtered SET, a failure, an auth
switch, and caching_sha2 fast auth. Run separate captures for outcomes `both`,
`success`, `failure`, and `disabled`, and pass the matching mode to `verify`.

This is protocol/capture/output testing, not validation of actual database
authentication. Real-driver acceptance should start a fresh unencrypted
connection, execute SELECT 1 and SELECT 2, and confirm one login plus two query
events with the same username/tool. Existing connections will not produce a
retroactive login event.

Protocol reference: [MySQL HandshakeResponse41](https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_protocol_connection_phase_packets_protocol_handshake_response.html).
