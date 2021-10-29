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
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/contracts/native/go_abi/side_chain_manager_abi"
	poly_utils "github.com/ethereum/go-ethereum/contracts/native/utils"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/polynetwork/zion-setup/config"
	"github.com/polynetwork/zion-setup/log"
	"github.com/polynetwork/zion-setup/tools/eth"
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
	poly := eth.NewEthTools(config.DefConfig.PolyJsonRpcURL)

	switch method {
	case "register_side_chain":
		signerArr := make([]*eth.EthSigner, 0)
		if len(config.DefConfig.NodeKeyList) != 0 {
			for _, nodeKey := range config.DefConfig.NodeKeyList {
				signer, err := eth.NewEthSigner(nodeKey)
				if err != nil {
					panic(err)
				}
				signerArr = append(signerArr, signer)
			}
		}

		switch config.DefConfig.ChainName {
		case "arbitrum", "optimism", "fantom":
			if RegisterEthChain(1, poly, signerArr[0]) {
				ApproveRegisterSideChain(poly, signerArr[1:])
			}
		case "heco", "bsc", "eth":
			if RegisterEthChain(12, poly, signerArr[0]) {
				ApproveRegisterSideChain(poly, signerArr[1:])
			}
		default:
			panic(fmt.Errorf("not supported chain name"))
		}
	default:
		panic(fmt.Errorf("not supported method"))
	}
}

func RegisterEthChain(blkToWait uint64, poly *eth.ETHTools, signer *eth.EthSigner) bool {
	eccd, err := hex.DecodeString(strings.Replace(config.DefConfig.Eccd, "0x", "", 1))
	if err != nil {
		panic(fmt.Errorf("RegisterEthChain, failed to decode eccd '%s' : %v", config.DefConfig.Eccd, err))
	}
	scmAbi, err := abi.JSON(strings.NewReader(side_chain_manager_abi.SideChainManagerABI))
	if err != nil {
		panic(fmt.Errorf("RegisterEthChain, abi.JSON error:" + err.Error()))
	}
	gasPrice, err := poly.GetEthClient().SuggestGasPrice(context.Background())
	if err != nil {
		panic(fmt.Errorf("RegisterEthChain, get suggest gas price failed error: %s", err.Error()))
	}
	gasPrice = gasPrice.Mul(gasPrice, big.NewInt(1))

	txData, err := scmAbi.Pack("registerSideChain", signer.Address, config.DefConfig.ChainId, uint64(0),
		config.DefConfig.ChainName, blkToWait, eccd, []byte{})
	if err != nil {
		panic(fmt.Errorf("RegisterEthChain, scmAbi.Pack error:" + err.Error()))
	}

	callMsg := ethereum.CallMsg{
		From: signer.Address, To: &poly_utils.SideChainManagerContractAddress, Gas: 0, GasPrice: gasPrice,
		Value: big.NewInt(int64(0)), Data: txData,
	}
	gasLimit, err := poly.GetEthClient().EstimateGas(context.Background(), callMsg)
	if err != nil {
		panic(fmt.Errorf("RegisterEthChain, estimate gas limit error: %s", err.Error()))
	}
	nonce := eth.NewNonceManager(poly.GetEthClient()).GetAddressNonce(signer.Address)
	tx := types.NewTx(&types.LegacyTx{Nonce: nonce, GasPrice: gasPrice, Gas: gasLimit, To: &poly_utils.SideChainManagerContractAddress, Value: big.NewInt(0), Data: txData})
	chainID, err := poly.GetChainID()
	if err != nil {
		panic(fmt.Errorf("RegisterEthChain, get chain id error: %s", err.Error()))
	}
	signedtx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), signer.PrivateKey)
	if err != nil {
		panic(fmt.Errorf("SignTransaction failed:%v", err))
	}
	duration := time.Second * 20
	timerCtx, cancelFunc := context.WithTimeout(context.Background(), duration)
	defer cancelFunc()
	err = poly.GetEthClient().SendTransaction(timerCtx, signedtx)
	if err != nil {
		panic(fmt.Errorf("SendTransaction failed:%v", err))
	}
	txhash := signedtx.Hash()

	isSuccess := poly.WaitTransactionConfirm(txhash)
	if isSuccess {
		log.Infof("successful RegisterVoteChain to poly: (poly_hash: %s, account: %s)", txhash.String(), signer.Address.Hex())
	} else {
		log.Errorf("failed to RegisterVoteChain to poly: (poly_hash: %s, account: %s)", txhash.String(), signer.Address.Hex())
	}
	return true
}

func ApproveRegisterSideChain(poly *eth.ETHTools, signerArr []*eth.EthSigner) {
	scmAbi, err := abi.JSON(strings.NewReader(side_chain_manager_abi.SideChainManagerABI))
	if err != nil {
		panic(fmt.Errorf("ApproveRegisterSideChain, abi.JSON error:" + err.Error()))
	}
	gasPrice, err := poly.GetEthClient().SuggestGasPrice(context.Background())
	if err != nil {
		panic(fmt.Errorf("ApproveRegisterSideChain, get suggest gas price failed error: %s", err.Error()))
	}
	gasPrice = gasPrice.Mul(gasPrice, big.NewInt(1))
	duration := time.Second * 20
	timerCtx, cancelFunc := context.WithTimeout(context.Background(), duration)
	defer cancelFunc()
	for i, signer := range signerArr {
		txData, err := scmAbi.Pack("approveRegisterSideChain", config.DefConfig.ChainId, signer.Address)
		if err != nil {
			panic(fmt.Errorf("ApproveRegisterSideChain, scmAbi.Pack error:" + err.Error()))
		}

		callMsg := ethereum.CallMsg{
			From: signer.Address, To: &poly_utils.SideChainManagerContractAddress, Gas: 0, GasPrice: gasPrice,
			Value: big.NewInt(int64(0)), Data: txData,
		}
		gasLimit, err := poly.GetEthClient().EstimateGas(context.Background(), callMsg)
		if err != nil {
			panic(fmt.Errorf("ApproveRegisterSideChain, estimate gas limit error: %s", err.Error()))
		}
		nonce := eth.NewNonceManager(poly.GetEthClient()).GetAddressNonce(signer.Address)
		tx := types.NewTx(&types.LegacyTx{Nonce: nonce, GasPrice: gasPrice, Gas: gasLimit, To: &poly_utils.SideChainManagerContractAddress, Value: big.NewInt(0), Data: txData})
		chainID, err := poly.GetChainID()
		if err != nil {
			panic(fmt.Errorf("RegisterEthChain, get chain id error: %s", err.Error()))
		}
		signedtx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), signer.PrivateKey)
		if err != nil {
			panic(fmt.Errorf("SignTransaction failed:%v", err))
		}
		err = poly.GetEthClient().SendTransaction(timerCtx, signedtx)
		if err != nil {
			panic(fmt.Errorf("SendTransaction failed:%v", err))
		}
		txhash := signedtx.Hash()
		log.Infof("No%d: successful to approve: ( acc: %s, txhash: %s, chain-id: %d )", i, signer.Address.Hex(), txhash.String(), config.DefConfig.ChainId)
	}
}
