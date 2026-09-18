#!/usr/bin/env python3
# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Verify one probe run in Packetbeat console NDJSON output."""
import argparse
import json

p = argparse.ArgumentParser()
p.add_argument("events")
p.add_argument("run")
p.add_argument("user")
p.add_argument("--count", type=int, default=5)
a = p.parse_args()
expected = {"pb_probe_%s_%d" % (a.run, i) for i in range(1, a.count + 1)}
found = set()
endpoints = set()
with open(a.events) as stream:
    for line in stream:
        e = json.loads(line)
        markers = [m for m in expected if ("'" + m + "'") in e.get("query", "")]
        if not markers:
            continue
        assert e.get("user", {}).get("name") == a.user, e.get("query")
        assert a.user in e.get("related", {}).get("user", []), e.get("query")
        for marker in markers:
            assert marker not in found, "duplicate event: " + marker
            found.add(marker)
        endpoints.add((e["source"]["ip"], e["source"]["port"], e["destination"]["ip"], e["destination"]["port"]))
assert found == expected, "missing markers: " + str(expected - found)
assert len(endpoints) == 1, "queries came from multiple TCP connections"
print("PASS:", a.run, len(found), "SQL events with username on one TCP connection")
