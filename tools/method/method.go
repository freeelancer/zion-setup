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
package method

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/KSlashh/poly-abi/abi_1.9.25/ccm"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/contracts/native/go_abi/header_sync_abi"
	"github.com/ethereum/go-ethereum/contracts/native/go_abi/side_chain_manager_abi"
	"github.com/ethereum/go-ethereum/contracts/native/header_sync/bsc"
	"github.com/ethereum/go-ethereum/contracts/native/header_sync/heco"
	"github.com/ethereum/go-ethereum/contracts/native/header_sync/okex"
	"github.com/ethereum/go-ethereum/contracts/native/utils"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/polynetwork/poly/native/service/header_sync/cosmos"
	"github.com/polynetwork/poly/native/service/header_sync/polygon"
	"github.com/polynetwork/zion-setup/config"
	"github.com/polynetwork/zion-setup/log"
	"github.com/polynetwork/zion-setup/tools/eth"
	"github.com/polynetwork/zion-setup/tools/tendermint"
	"github.com/polynetwork/zion-setup/tools/zion"
	"github.com/tendermint/tendermint/rpc/client/http"
)

func RegisterSideChain(method string, chainName string, z *zion.ZionTools, e *eth.ETHTools, signer *zion.ZionSigner) bool {
	var blkToWait uint64
	var extra []byte
	switch chainName {
	case "quorum", "heimdall", "ont":
		blkToWait = 1
	case "eth", "oec", "arbitrum", "optimism", "fantom", "avalanche", "xdai":
		blkToWait = 12
	case "bsc":
		blkToWait = 15
		chainId, err := e.GetChainID()
		if err != nil {
			panic(err)
		}
		ex := bsc.ExtraInfo{
			ChainID: chainId,
		}
		extra, _ = json.Marshal(ex)
	case "heco":
		blkToWait = 21
		chainId, err := e.GetChainID()
		if err != nil {
			panic(err)
		}
		ex := heco.ExtraInfo{
			ChainID: chainId,
			Period:  3,
		}
		extra, _ = json.Marshal(ex)
	case "bor":
		blkToWait = 128
		heimdallPolyChainID := config.DefConfig.ETHConfig.HeimdallChainId
		ex := polygon.ExtraInfo{
			Sprint:              64,
			Period:              2,
			ProducerDelay:       6,
			BackupMultiplier:    2,
			HeimdallPolyChainID: heimdallPolyChainID,
		}
		extra, _ = json.Marshal(ex)

	case "pixie":
		blkToWait = 3
		chainId, err := e.GetChainID() // testnet 666
		if err != nil {
			panic(err)
		}
		ex := heco.ExtraInfo{
			ChainID: chainId,
			Period:  3,
		}
		extra, _ = json.Marshal(ex)

	case "zion":
		blkToWait = 0
		extra = []byte{}

	default:
		panic(fmt.Errorf("not supported chain name"))
	}

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
		chainName, blkToWait, eccd, extra)
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
	nonce := zion.NewNonceManager(z.GetEthClient()).GetAddressNonce(signer.Address)
	tx := types.NewTx(&types.LegacyTx{Nonce: nonce, GasPrice: gasPrice, Gas: gasLimit, To: &utils.SideChainManagerContractAddress, Value: big.NewInt(0), Data: txData})
	chainID, err := z.GetChainID()
	if err != nil {
		panic(fmt.Errorf("RegisterEthChain, get chain id error: %s", err.Error()))
	}
	s := types.LatestSignerForChainID(chainID)
	signedtx, err := types.SignTx(tx, s, signer.PrivateKey)
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

func ApproveRegisterSideChain(method string, z *zion.ZionTools, signerArr []*zion.ZionSigner) {
	scmAbi, err := abi.JSON(strings.NewReader(side_chain_manager_abi.SideChainManagerABI))
	if err != nil {
		panic(fmt.Errorf("ApproveRegisterSideChain, abi.JSON error:" + err.Error()))
	}
	gasPrice, err := z.GetEthClient().SuggestGasPrice(context.Background())
	if err != nil {
		panic(fmt.Errorf("ApproveRegisterSideChain, get suggest gas price failed error: %s", err.Error()))
	}
	gasPrice = gasPrice.Mul(gasPrice, big.NewInt(1))
	duration := time.Second * 300
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
		nonce := zion.NewNonceManager(z.GetEthClient()).GetAddressNonce(signer.Address)
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

func SyncETHToZion(z *zion.ZionTools, e *eth.ETHTools, signerArr []*zion.ZionSigner, chainName string) {
	curr, err := e.GetNodeHeight()
	if err != nil {
		panic(err)
	}
	log.Infof("current height of eth is %d", curr)
	var raw []byte
	switch chainName {
	case "eth":
		hdr, err := e.Get1559BlockHeader(curr)
		if err != nil {
			panic(err)
		}
		raw, err = hdr.MarshalJSON()
		if err != nil {
			panic(err)
		}
	case "bsc":
		epochHeight := curr - curr%200
		pEpochHeight := epochHeight - 200

		hdr, err := e.GetBlockHeader(epochHeight)
		if err != nil {
			panic(err)
		}
		phdr, err := e.GetBlockHeader(pEpochHeight)
		if err != nil {
			panic(err)
		}
		pvalidators, err := bsc.ParseValidators(phdr.Extra[32 : len(phdr.Extra)-65])
		if err != nil {
			panic(err)
		}
		if len(hdr.Extra) <= 65+32 {
			panic(fmt.Sprintf("invalid epoch header at height:%d", epochHeight))
		}
		if len(phdr.Extra) <= 65+32 {
			panic(fmt.Sprintf("invalid epoch header at height:%d", pEpochHeight))
		}
		genesisHeader := bsc.GenesisHeader{Header: *hdr, PrevValidators: []bsc.HeightAndValidators{
			{Height: big.NewInt(int64(pEpochHeight)), Validators: pvalidators},
		}}
		raw, err = json.Marshal(genesisHeader)
		if err != nil {
			panic(err)
		}
	case "heco":
		epochHeight := curr - curr%200
		pEpochHeight := epochHeight - 200

		hdr, err := e.Get1559BlockHeader(epochHeight)
		if err != nil {
			panic(err)
		}
		phdr, err := e.Get1559BlockHeader(pEpochHeight)
		if err != nil {
			panic(err)
		}
		pvalidators, err := heco.ParseValidators(phdr.Extra[32 : len(phdr.Extra)-65])
		if err != nil {
			panic(err)
		}
		if len(hdr.Extra) <= 65+32 {
			panic(fmt.Sprintf("invalid epoch header at height:%d", epochHeight))
		}
		if len(phdr.Extra) <= 65+32 {
			panic(fmt.Sprintf("invalid epoch header at height:%d", pEpochHeight))
		}
		genesisHeader := heco.GenesisHeader{Header: *hdr, PrevValidators: []heco.HeightAndValidators{
			{Height: big.NewInt(int64(pEpochHeight)), Validators: pvalidators},
		}}
		raw, err = json.Marshal(genesisHeader)
		if err != nil {
			panic(err)
		}

	case "pixie":
		var backOffHeight uint64 = 200 * 5

		epochHeight := curr - curr%200 - backOffHeight
		pEpochHeight := epochHeight - 200 - backOffHeight

		hdr, err := e.Get1559BlockHeader(epochHeight)
		if err != nil {
			panic(err)
		}
		phdr, err := e.Get1559BlockHeader(pEpochHeight)
		if err != nil {
			panic(err)
		}

		pvalidators, err := heco.ParseValidators(phdr.Extra[32 : len(phdr.Extra)-65])
		if err != nil {
			panic(err)
		}
		genesisHeader := heco.GenesisHeader{Header: *hdr, PrevValidators: []heco.HeightAndValidators{
			{Height: big.NewInt(int64(pEpochHeight)), Validators: pvalidators},
		}}
		raw, err = json.Marshal(genesisHeader)
		if err != nil {
			panic(err)
		}

	case "zion":
		hdr, err := e.GetZionHeader(curr)
		if err != nil {
			panic(err)
		}
		raw, err = hdr.MarshalJSON()
		if err != nil {
			panic(err)
		}

	case "oec":
		oecCli, err := http.New(config.DefConfig.ETHConfig.OKTMRpcURL, "/websocket")
		if err != nil {
			panic(err)
		}
		codec := okex.NewCDC()
		h := int64(curr)
		res, err := oecCli.Commit(&h)
		if err != nil {
			panic(err)
		}
		vals, err := tendermint.GetValidators(oecCli, h)
		if err != nil {
			panic(err)
		}
		ch := &cosmos.CosmosHeader{
			Header:  *res.Header,
			Commit:  res.Commit,
			Valsets: vals,
		}
		raw, err = codec.MarshalBinaryBare(ch)
		if err != nil {
			panic(err)
		}
	case "quorum":
		hdr, err := e.GetBlockHeader(curr)
		if err != nil {
			panic(err)
		}
		raw, err = hdr.MarshalJSON()
		if err != nil {
			log.Errorf("marshal header failed, err: %s", err)
			return
		}
	case "heimdall", "bor":
		raw, _ = hex.DecodeString(config.DefConfig.ETHConfig.PolygonHeader)
	case "ont":
		//TODO
	default:
		panic(fmt.Errorf("not supported chain name"))
	}

	scmAbi, err := abi.JSON(strings.NewReader(header_sync_abi.HeaderSyncABI))
	if err != nil {
		panic(fmt.Errorf("SyncETHToZion, abi.JSON error:" + err.Error()))
	}
	gasPrice, err := z.GetEthClient().SuggestGasPrice(context.Background())
	if err != nil {
		panic(fmt.Errorf("SyncETHToZion, get suggest gas price failed error: %s", err.Error()))
	}
	gasPrice = gasPrice.Mul(gasPrice, big.NewInt(1))
	txData, err := scmAbi.Pack("syncGenesisHeader", config.DefConfig.ETHConfig.ChainId, raw)
	if err != nil {
		panic(fmt.Errorf("SyncETHToZion, scmAbi.Pack error:" + err.Error()))
	}

	for _, signer := range signerArr {
		callMsg := ethereum.CallMsg{
			From: signer.Address, To: &utils.HeaderSyncContractAddress, Gas: 0, GasPrice: gasPrice,
			Value: big.NewInt(int64(0)), Data: txData,
		}
		gasLimit, err := z.GetEthClient().EstimateGas(context.Background(), callMsg)
		if err != nil {
			panic(fmt.Errorf("SyncETHToZion, estimate gas limit error: %s", err.Error()))
		}
		nonce := zion.NewNonceManager(z.GetEthClient()).GetAddressNonce(signer.Address)
		tx := types.NewTx(&types.LegacyTx{Nonce: nonce, GasPrice: gasPrice, Gas: gasLimit, To: &utils.HeaderSyncContractAddress, Value: big.NewInt(0), Data: txData})
		chainID, err := z.GetChainID()
		if err != nil {
			panic(fmt.Errorf("SyncETHToZion, get chain id error: %s", err.Error()))
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
			log.Infof("successful sync eth genesis header to zion: (poly_hash: %s, account: %s)", txhash.String(), signer.Address.Hex())
		} else {
			log.Errorf("failed to sync eth genesis header to zion: (poly_hash: %s, account: %s)", txhash.String(), signer.Address.Hex())
		}
	}
}

func SyncZionToETH(z *zion.ZionTools, e *eth.ETHTools) {
	signer, err := eth.NewEthSigner(config.DefConfig.ETHConfig.ETHPrivateKey)
	if err != nil {
		panic(err)
	}
	epochInfo, err := z.GetEpochInfo()
	if err != nil {
		panic(fmt.Errorf("SyncZionToETH, GetEpochInfo error: %s", err.Error()))
	}
	rawHeader, _, err := z.GetRawHeaderAndRawSeals(epochInfo.StartHeight - 1)
	if err != nil {
		panic(fmt.Errorf("SyncZionToETH, GetRawHeaderAndRawSeals error: %s", err.Error()))
	}

	contractabi, err := abi.JSON(strings.NewReader(ccm.EthCrossChainManagerImplementationABI))
	if err != nil {
		log.Errorf("SyncZionToETH, abi.JSON error: %v", err)
		return
	}
	txData, err := contractabi.Pack("initGenesisBlock", rawHeader)
	if err != nil {
		log.Errorf("SyncZionToETH, contractabi.Pack error: %v", err)
		return
	}

	gasPrice, err := e.GetEthClient().SuggestGasPrice(context.Background())
	if err != nil {
		panic(fmt.Errorf("SyncZionToETH, get suggest gas price failed error: %s", err.Error()))
	}
	gasPrice = gasPrice.Mul(gasPrice, big.NewInt(1))
	eccm := common.HexToAddress(config.DefConfig.ETHConfig.Eccm)
	callMsg := ethereum.CallMsg{
		From: signer.Address, To: &eccm, Gas: 0, GasPrice: gasPrice,
		Value: big.NewInt(0), Data: txData,
	}
	gasLimit, err := e.GetEthClient().EstimateGas(context.Background(), callMsg)
	if err != nil {
		log.Errorf("SyncZionToETH, estimate gas limit error: %s", err.Error())
		return
	}
	nonce := eth.NewNonceManager(e.GetEthClient()).GetAddressNonce(signer.Address)
	tx := types.NewTx(&types.LegacyTx{Nonce: nonce, GasPrice: gasPrice, Gas: gasLimit, To: &eccm, Value: big.NewInt(0), Data: txData})
	chainID, err := e.GetChainID()
	if err != nil {
		panic(fmt.Errorf("SyncZionToETH, get chain id error: %s", err.Error()))
	}
	signedtx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), signer.PrivateKey)
	if err != nil {
		panic(fmt.Errorf("SignTransaction failed:%v", err))
	}
	duration := time.Second * 20
	timerCtx, cancelFunc := context.WithTimeout(context.Background(), duration)
	defer cancelFunc()
	err = e.GetEthClient().SendTransaction(timerCtx, signedtx)
	if err != nil {
		panic(fmt.Errorf("SendTransaction failed:%v", err))
	}
	e.WaitTransactionConfirm(signedtx.Hash())
	log.Infof("successful to sync zion genesis header to Ethereum: ( txhash: %s )", signedtx.Hash().String())
}
