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
package zion

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/contracts/native/go_abi/side_chain_manager_abi"
	"github.com/ethereum/go-ethereum/contracts/native/utils"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/polynetwork/zion-setup/config"
	"github.com/polynetwork/zion-setup/log"
)

func RegisterSideChain(method string, blkToWait uint64, z *ZionTools, signer *ZionSigner) bool {
	eccd, err := hex.DecodeString(strings.Replace(config.DefConfig.ETHConfig.Eccd, "0x", "", 1))
	if err != nil {
		panic(fmt.Errorf("RegisterEthChain, failed to decode eccd '%s' : %v", config.DefConfig.ETHConfig.Eccd, err))
	}
	scmAbi, err := abi.JSON(strings.NewReader(side_chain_manager_abi.SideChainManagerABI))
	if err != nil {
		panic(fmt.Errorf("RegisterEthChain, abi.JSON error:" + err.Error()))
	}
	gasPrice, err := z.GetEthClient().SuggestGasPrice(context.Background())
	if err != nil {
		panic(fmt.Errorf("RegisterEthChain, get suggest gas price failed error: %s", err.Error()))
	}
	gasPrice = gasPrice.Mul(gasPrice, big.NewInt(1))

	txData, err := scmAbi.Pack(method, signer.Address, config.DefConfig.ETHConfig.ChainId, config.DefConfig.ETHConfig.Router,
		config.DefConfig.ChainName, blkToWait, eccd, []byte{})
	if err != nil {
		panic(fmt.Errorf("RegisterEthChain, scmAbi.Pack error:" + err.Error()))
	}

	callMsg := ethereum.CallMsg{
		From: signer.Address, To: &utils.SideChainManagerContractAddress, Gas: 0, GasPrice: gasPrice,
		Value: big.NewInt(int64(0)), Data: txData,
	}
	gasLimit, err := z.GetEthClient().EstimateGas(context.Background(), callMsg)
	if err != nil {
		panic(fmt.Errorf("RegisterEthChain, estimate gas limit error: %s", err.Error()))
	}
	nonce := NewNonceManager(z.GetEthClient()).GetAddressNonce(signer.Address)
	tx := types.NewTx(&types.LegacyTx{Nonce: nonce, GasPrice: gasPrice, Gas: gasLimit, To: &utils.SideChainManagerContractAddress, Value: big.NewInt(0), Data: txData})
	chainID, err := z.GetChainID()
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
	err = z.GetEthClient().SendTransaction(timerCtx, signedtx)
	if err != nil {
		panic(fmt.Errorf("SendTransaction failed:%v", err))
	}
	txhash := signedtx.Hash()

	isSuccess := z.WaitTransactionConfirm(txhash)
	if isSuccess {
		log.Infof("successful RegisterSideChain to zion: (poly_hash: %s, account: %s)", txhash.String(), signer.Address.Hex())
	} else {
		log.Errorf("failed to RegisterSideChain to zion: (poly_hash: %s, account: %s)", txhash.String(), signer.Address.Hex())
	}
	return true
}

func ApproveRegisterSideChain(method string, z *ZionTools, signerArr []*ZionSigner) {
	scmAbi, err := abi.JSON(strings.NewReader(side_chain_manager_abi.SideChainManagerABI))
	if err != nil {
		panic(fmt.Errorf("ApproveRegisterSideChain, abi.JSON error:" + err.Error()))
	}
	gasPrice, err := z.GetEthClient().SuggestGasPrice(context.Background())
	if err != nil {
		panic(fmt.Errorf("ApproveRegisterSideChain, get suggest gas price failed error: %s", err.Error()))
	}
	gasPrice = gasPrice.Mul(gasPrice, big.NewInt(1))
	duration := time.Second * 20
	timerCtx, cancelFunc := context.WithTimeout(context.Background(), duration)
	defer cancelFunc()
	for _, signer := range signerArr {
		txData, err := scmAbi.Pack(method, config.DefConfig.ETHConfig.ChainId, signer.Address)
		if err != nil {
			panic(fmt.Errorf("ApproveRegisterSideChain, scmAbi.Pack error:" + err.Error()))
		}

		callMsg := ethereum.CallMsg{
			From: signer.Address, To: &utils.SideChainManagerContractAddress, Gas: 0, GasPrice: gasPrice,
			Value: big.NewInt(int64(0)), Data: txData,
		}
		gasLimit, err := z.GetEthClient().EstimateGas(context.Background(), callMsg)
		if err != nil {
			panic(fmt.Errorf("ApproveRegisterSideChain, estimate gas limit error: %s", err.Error()))
		}
		nonce := NewNonceManager(z.GetEthClient()).GetAddressNonce(signer.Address)
		tx := types.NewTx(&types.LegacyTx{Nonce: nonce, GasPrice: gasPrice, Gas: gasLimit, To: &utils.SideChainManagerContractAddress, Value: big.NewInt(0), Data: txData})
		chainID, err := z.GetChainID()
		if err != nil {
			panic(fmt.Errorf("RegisterEthChain, get chain id error: %s", err.Error()))
		}
		signedtx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), signer.PrivateKey)
		if err != nil {
			panic(fmt.Errorf("SignTransaction failed:%v", err))
		}
		err = z.GetEthClient().SendTransaction(timerCtx, signedtx)
		if err != nil {
			panic(fmt.Errorf("SendTransaction failed:%v", err))
		}
		txhash := signedtx.Hash()
		isSuccess := z.WaitTransactionConfirm(txhash)
		if isSuccess {
			log.Infof("successful ApproveRegisterSideChain to zion: (poly_hash: %s, account: %s)", txhash.String(), signer.Address.Hex())
		} else {
			log.Errorf("failed to ApproveRegisterSideChain to zion: (poly_hash: %s, account: %s)", txhash.String(), signer.Address.Hex())
		}
	}
}
