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
	"fmt"
	"time"

	"github.com/elastic/beats/v7/packetbeat/config"
	"github.com/elastic/beats/v7/packetbeat/protos"
	conf "github.com/elastic/elastic-agent-libs/config"
)

type mysqlConfig struct {
	config.ProtocolCommon `config:",inline"`
	MaxRowLength          int                   `config:"max_row_length"`
	MaxRows               int                   `config:"max_rows"`
	StatementTimeout      time.Duration         `config:"statement_timeout"`
	ConnectionTimeout     time.Duration         `config:"connection_timeout"`
	Login                 mysqlLoginConfig      `config:"login"`
	ClientInfo            mysqlClientInfoConfig `config:"client_info"`
}

type mysqlLoginConfig struct {
	Enabled  bool     `config:"enabled"`
	Outcomes []string `config:"outcomes"`
}

type mysqlClientInfoConfig struct {
	Enabled bool `config:"enabled"`
}

// Unpack replaces the outcome list instead of merging it with default entries.
func (c *mysqlLoginConfig) Unpack(from *conf.C) error {
	type loginValues mysqlLoginConfig
	var values loginValues
	if err := from.Unpack(&values); err != nil {
		return err
	}
	if !from.HasField("outcomes") {
		values.Outcomes = []string{"success", "failure"}
	}
	*c = mysqlLoginConfig(values)
	return nil
}

func (c *mysqlConfig) Validate() error {
	if c.Login.Enabled && len(c.Login.Outcomes) == 0 {
		return fmt.Errorf("mysql.login.outcomes must not be empty when login is enabled")
	}
	for _, outcome := range c.Login.Outcomes {
		if outcome != "success" && outcome != "failure" {
			return fmt.Errorf("mysql.login.outcomes must contain only success or failure")
		}
	}
	return nil
}

var defaultConfig = mysqlConfig{
	ProtocolCommon: config.ProtocolCommon{
		TransactionTimeout: protos.DefaultTransactionExpiration,
	},
	MaxRowLength:      1024,
	MaxRows:           10,
	StatementTimeout:  3600 * time.Second,
	ConnectionTimeout: 8 * time.Hour,
	Login:             mysqlLoginConfig{Outcomes: []string{"success", "failure"}},
}
