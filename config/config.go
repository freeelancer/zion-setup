/*
* Copyright (C) 2020 The poly network Authors
* This file is part of The poly network library.
*
* The poly network is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* The poly network is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
* You should have received a copy of the GNU Lesser General Public License
* along with The poly network . If not, see <http://www.gnu.org/licenses/>.
 */
package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/polynetwork/zion-setup/log"
)

// Config config object
type Config struct {
	ZionJsonRpcURL string
	NodeKeyList    []string
	ChainName      string
	ETHConfig      *ETHConfig
	Neo3Config     *Neo3Config
}

type ETHConfig struct {
	ChainId       uint64
	Router        uint64
	Eccd          string
	Eccm          string
	ETHJsonRpcURL string
	ETHPrivateKey string
	//used for Ont chain
	OntRpcURL string
	//used for Ont chain
	OntEpoch uint32
	//used for okex chain
	OKTMRpcURL string
	//used for heimdall and bor
	PolygonHeader string
	//used for bor
	HeimdallChainId uint64
}

type Neo3Config struct {
	Neo3CCMC           string
	Neo3Url            string
	Neo3Wallet         string
	Neo3Pwd            string
	Neo3Magic          uint32
	Neo3AddressVersion byte
	Neo3Epoch          uint32
}

// DefConfig Default config instance
var DefConfig = NewDefaultConfig()
var DefaultConfigFile = "./config.json"

//NewConfig return a Config instance
func NewConfig() *Config {
	return &Config{}
}

func NewDefaultConfig() *Config {
	var config = NewConfig()
	err := config.Init(DefaultConfigFile)
	if err != nil {
		return &Config{}
	}
	return config
}

//Init TestConfig with a config file
func (conf *Config) Init(fileName string) error {
	err := conf.loadConfig(fileName)
	if err != nil {
		return fmt.Errorf("loadConfig error:%s", err)
	}

	return nil
}

/**
Load JSON Configuration
*/
func (conf *Config) loadConfig(fileName string) error {
	data, err := conf.readFile(fileName)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, conf)
	if err != nil {
		return fmt.Errorf("json.Unmarshal TestConfig:%s error:%s", data, err)
	}
	return nil
}

/**
Read  File to bytes
*/
func (conf *Config) readFile(fileName string) ([]byte, error) {
	file, err := os.OpenFile(fileName, os.O_RDONLY, 0666)
	if err != nil {
		return nil, fmt.Errorf("OpenFile %s error %s", fileName, err)
	}
	defer func() {
		err := file.Close()
		if err != nil {
			log.Errorf("File %s close error %s", fileName, err)
		}
	}()
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadAll %s error %s", fileName, err)
	}
	return data, nil
}

/**
Save Configuration To json file
*/
func (conf *Config) Save(fileName string) error {
	data, err := json.MarshalIndent(conf, "", "\t")
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(fileName, data, 0644); err != nil {
		return fmt.Errorf("failed to write conf file: %v", err)
	}
	return nil
}
