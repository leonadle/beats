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

"""Read-only real-MySQL username probe. Requires PyMySQL on the client."""
import json
import os
import re
import time
import pymysql

run = os.environ.get("PROBE_RUN", str(int(time.time())))
if not re.fullmatch(r"[A-Za-z0-9_]+", run):
    raise ValueError("PROBE_RUN must contain only letters, digits and underscores")
connection = pymysql.connect(
    host=os.environ["MYSQL_PROBE_HOST"],
    port=int(os.environ.get("MYSQL_PROBE_PORT", "3306")),
    user=os.environ["MYSQL_PROBE_USER"],
    password=os.environ["MYSQL_PROBE_PASSWORD"],
    ssl_disabled=True, autocommit=True, connect_timeout=5, read_timeout=10,
)
try:
    with connection.cursor() as cursor:
        cursor.execute("START TRANSACTION READ ONLY")
        print(json.dumps({"run": run, "connection_id": connection.thread_id(),
                          "local_endpoint": connection._sock.getsockname()}), flush=True)
        delays = os.environ.get("PROBE_DELAYS", "0,1,12,60,1").split(",")
        for index, delay in enumerate(delays, 1):
            time.sleep(float(delay))
            table = "users" if index % 2 else "sale"
            marker = "pb_probe_%s_%d" % (run, index)
            cursor.execute("SELECT '%s' AS probe FROM t591.%s LIMIT 1" % (marker, table))
            cursor.fetchall()
            print(json.dumps({"marker": marker, "connection_id": connection.thread_id(),
                              "time": time.time()}), flush=True)
        connection.rollback()
finally:
    connection.close()
