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
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/polynetwork/zion-setup/config"
	"github.com/polynetwork/zion-setup/log"
	"github.com/polynetwork/zion-setup/tools/eth"
	"github.com/polynetwork/zion-setup/tools/zion"
)

var (
	method string
	conf   string
)

func init() {
	flag.StringVar(&method, "method", "", "choose a method to run")
	flag.StringVar(&conf, "conf", "./config.json", "configuration file path")

	flag.Parse()
}

func main() {
	log.InitLog(2, os.Stdout)

	err := config.DefConfig.Init(conf)
	if err != nil {
		panic(err)
	}
	z := zion.NewZionTools(config.DefConfig.ZionJsonRpcURL)
	e := eth.NewEthTools(config.DefConfig.ETHConfig.ETHJsonRpcURL)

	switch method {
	case "register_side_chain":
		signerArr := make([]*zion.ZionSigner, 0)
		if len(config.DefConfig.NodeKeyList) != 0 {
			for _, nodeKey := range config.DefConfig.NodeKeyList {
				signer, err := zion.NewZionSigner(nodeKey)
				if err != nil {
					panic(err)
				}
				signerArr = append(signerArr, signer)
			}
		}

		switch config.DefConfig.ChainName {
		case "arbitrum", "optimism", "fantom":
			if zion.RegisterSideChain("registerSideChain", 1, z, signerArr[0]) {
				zion.ApproveRegisterSideChain("approveRegisterSideChain", z, signerArr[1:])
			}
		case "eth", "heco", "bsc", "oec":
			if zion.RegisterSideChain("registerSideChain", 12, z, signerArr[0]) {
				zion.ApproveRegisterSideChain("approveRegisterSideChain", z, signerArr[1:])
			}
		default:
			panic(fmt.Errorf("not supported chain name"))
		}
	case "update_side_chain":
		signerArr := make([]*zion.ZionSigner, 0)
		if len(config.DefConfig.NodeKeyList) != 0 {
			for _, nodeKey := range config.DefConfig.NodeKeyList {
				signer, err := zion.NewZionSigner(nodeKey)
				if err != nil {
					panic(err)
				}
				signerArr = append(signerArr, signer)
			}
		}

		switch config.DefConfig.ChainName {
		case "arbitrum", "optimism", "fantom":
			if zion.RegisterSideChain("updateSideChain", 1, z, signerArr[0]) {
				zion.ApproveRegisterSideChain("approveUpdateSideChain", z, signerArr[1:])
			}
		case "eth", "heco", "bsc", "oec":
			if zion.RegisterSideChain("updateSideChain", 12, z, signerArr[0]) {
				zion.ApproveRegisterSideChain("approveUpdateSideChain", z, signerArr[1:])
			}
		default:
			panic(fmt.Errorf("not supported chain name"))
		}
	case "sync_genesis_header":
		signerArr := make([]*zion.ZionSigner, 0)
		if len(config.DefConfig.NodeKeyList) != 0 {
			for _, nodeKey := range config.DefConfig.NodeKeyList {
				signer, err := zion.NewZionSigner(nodeKey)
				if err != nil {
					panic(err)
				}
				signerArr = append(signerArr, signer)
			}
		}

		switch config.DefConfig.ChainName {
		case "eth", "heco", "bsc", "oec":
			eth.SyncETHToZion(z, e, signerArr)
			eth.SyncZionToETH(z, e)
		}
	default:
		panic(fmt.Errorf("not supported method"))
	}
}
