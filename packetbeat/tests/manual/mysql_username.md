# MySQL username regression checks

The current parser records the database login from a captured, unencrypted
Handshake Response. It attaches user.name and related.user to subsequent SQL
transactions. Start Packetbeat before creating the client connection.

## Automated regression

Run from the repository root:

    go test ./packetbeat/protos/mysql -count=1

TestMySQLUsernameThroughTCPGap exercises the real TCP reassembly layer:
fragmented authentication, a query, an incomplete packet followed by a sequence
gap, and another query. It also checks that an unrelated connection without
an observed handshake cannot borrow the cached identity, and a secoogin
receives its own username.

## Live read-only check

Build with go build -o dist/packetbeat-linux-amd64 ./packetbeat.
Start a separate binary using a temporary home and the following configuration;
replace INTERFACE and CLIENT_IP with the actual capture interface and client IP:

    packetbeat.interfaces.device: INTERFACE
    packetbeat.interfaces.type: af_packet
    packetbeat.interfaces.bpf_filter: tcp port 3306 and host CLIENT_IP
    packetbeat.interfaces.snaplen: 65535
    packetbeat.flows.enabled: false
    packetbeat.protocols:
      - type: mysql
        ports: [3306]
    output.console:
      pretty: false
    logging.level: info

    dist/packetbeat-linux-amd64 -e --strict.perms=false -c /path/to/test.yml --path.home /path/to/temp-home >events.ndjson 2>runtime.log

On a separate client with PyMySQL installed, set MYSQL_PROBE_HOST,
MYSQL_PROBE_USER and MYSQL_PROBE_PASSWORD in the environment. Do not place the
password in this repository. Set PROBE_RUN to a unique alphanumeric identifier,
then run mysql_username_probe.py. The script uses one non-TLS connection in a
read-only transaction, queries only constant markers from t591.users and
t591.sale with LIMIT 1, and rolls back before closing. The default inter-query
delays are 0,1,12,60,1 seconds; PROBE_DELAYS can override them.

After the events have flushed, verify on the capture server:

    python3 packetbeat/tests/manual/verify_mysql_username.py events.ndjson RUN USER --count 5

The verifier checks every expected marker, both username fields, duplicate
and missing events, and a single TCP endpoint pair. It exits nonzero on failure.

## Validation on 2026-09-18

Server: 192.168.8.189:3306, Percona Server 5.7, interface ens33.
Baseline source: 300399eaff. Client: 192.168.22.26. TLS disabled.
Only read-only SELECTs against the two named tables were issued.

- baseline189: MySQL connection 3118715, client port 50816; 4/4 SQL events passed
  with delays 0,1,12,1 seconds.
- long189: MySQL connection 3118734, client port 51042; 5/5 SQL events passed
  with delays 0,1,12,60,1 seconds.
- Every checked event contained user.name=10791 and related.user included 10791.
- The MySQL package tests, including the real TCP gap and identity-isolation
  regression, passed on Linux.

No second-query username loss was reproduced with this baseline. This commit
adds verification coverage and tools; it does not claim a new parser fix.
The 8-hour idle duration was not tested in real time. Existing connections whose
handshake was not captured, encrypted authentication, and unsupported account
changes cannot be inferred by these tests. A missing field in another deployment
still requires correlating the exact connection, binary, capture and raw event.

The connection_timeout setting defaults to 8h in this fork and is separate from
transaction_timeout. The username recovery cache is keyed by TCPTuple.Hashable,
including the stream ID; it is not a global user lookup by IP address.
