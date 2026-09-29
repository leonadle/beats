#!/usr/bin/env python3
# Licensed to Elasticsearch B.V. under one or more contributor license
# agreements. See the NOTICE file distributed with this work for additional
# information regarding copyright ownership. Elasticsearch B.V. licenses this
# file to you under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain a
# copy of the License at http://www.apache.org/licenses/LICENSE-2.0

"""Isolated synthetic MySQL login probe; no database or credentials required."""

import argparse
import collections
import json
import socket
import struct
import threading

USER = "pb_login_probe"
OK = b"\x00\x00\x00\x02\x00\x00\x00"
ERR = b"\xff\x15\x04#28000Synthetic access denied"


def packet(seq, data):
    return struct.pack("<I", len(data))[:3] + bytes([seq]) + data


def read_exact(conn, count):
    result = b""
    while len(result) < count:
        chunk = conn.recv(count - len(result))
        if not chunk:
            raise RuntimeError("unexpected EOF in probe")
        result += chunk
    return result


def read_packet(conn):
    header = read_exact(conn, 4)
    return header[3], read_exact(conn, int.from_bytes(header[:3], "little"))


def handshake():
    caps = (1 << 9) | (1 << 15) | (1 << 20)
    attrs = b"\x0c_client_name\x07mysqlnd"
    return (struct.pack("<I", caps) + bytes(28) + USER.encode() + b"\x00\x00"
            + bytes([len(attrs)]) + attrs)


def generate(port):
    failures = []
    with socket.socket() as listener:
        # Binding fails safely if another service already owns the test port.
        listener.bind(("127.0.0.1", port))
        listener.listen(1)
        listener.settimeout(10)

        def serve():
            try:
                for mode in ("success", "failure", "switch", "fast"):
                    conn, _ = listener.accept()
                    with conn:
                        conn.settimeout(10)
                        conn.sendall(packet(0, b"\x0aSynthetic-probe\x00"))
                        assert read_packet(conn) == (1, handshake())
                        if mode == "failure":
                            conn.sendall(packet(2, ERR))
                            continue
                        seq = 2
                        if mode == "switch":
                            conn.sendall(packet(seq, b"\xfemysql_native_password\x00synthetic"))
                            assert read_packet(conn) == (3, b"")
                            seq = 4
                        elif mode == "fast":
                            conn.sendall(packet(seq, b"\x01\x03"))
                            seq = 3
                        conn.sendall(packet(seq, OK))
                        if mode == "success":
                            for sql in (b"SELECT 1", b"SELECT 2", b"SET @probe = 1"):
                                assert read_packet(conn) == (0, b"\x03" + sql)
                                conn.sendall(packet(1, OK))
            except Exception as exc:
                failures.append(exc)

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        for mode in ("success", "failure", "switch", "fast"):
            with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
                read_packet(conn)
                conn.sendall(packet(1, handshake()))
                _, reply = read_packet(conn)
                if mode == "switch":
                    assert reply[0] == 0xfe
                    conn.sendall(packet(3, b""))
                    _, reply = read_packet(conn)
                elif mode == "fast":
                    assert reply == b"\x01\x03"
                    _, reply = read_packet(conn)
                assert reply == (ERR if mode == "failure" else OK)
                if mode == "success":
                    for sql in (b"SELECT 1", b"SELECT 2", b"SET @probe = 1"):
                        conn.sendall(packet(0, b"\x03" + sql))
                        assert read_packet(conn) == (1, OK)
        server.join(timeout=12)
        if server.is_alive() or failures:
            raise RuntimeError("synthetic server did not complete successfully") from (
                failures[0] if failures else None)
    print("Generated four synthetic connections on loopback; no business database accessed.")


def verify(path, mode):
    events = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("type") == "mysql":
                events.append(event)
    counts = collections.Counter((e["event"]["action"], e["status"]) for e in events)
    expected = {("query", "OK"): 2}
    if mode in ("both", "success"):
        expected[("login", "OK")] = 3
    if mode in ("both", "failure"):
        expected[("login", "Error")] = 1
    assert dict(counts) == expected, "event count/status mismatch: %r" % dict(counts)
    assert [e["query"] for e in events if e["event"]["action"] == "query"] == ["SELECT 1", "SELECT 2"]
    for event in events:
        assert event["user"]["name"] == USER
        assert event["mysql"]["client"]["tool"] == "MYSQLND"
        assert event["client"]["ip"] == "127.0.0.1"
        assert event["server"]["ip"] == "127.0.0.1"
        assert event["client"]["port"] != event["server"]["port"]
        assert event["event"]["end"] >= event["event"]["start"]
        if event["event"]["action"] == "login":
            assert event["method"] == "LOGIN" and "query" not in event
        if event["status"] == "Error":
            assert event["mysql"]["error_code"] == 1045
            assert event["mysql"]["error_message"] == "Synthetic access denied"
    print(json.dumps({"mode": mode, "events": len(events), "passed": True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    gen = commands.add_parser("generate")
    gen.add_argument("--port", type=int, default=13306)
    check = commands.add_parser("verify")
    check.add_argument("path")
    check.add_argument("--mode", choices=("both", "success", "failure", "disabled"), default="both")
    args = parser.parse_args()
    if args.command == "generate":
        generate(args.port)
    else:
        verify(args.path, args.mode)


if __name__ == "__main__":
    main()
