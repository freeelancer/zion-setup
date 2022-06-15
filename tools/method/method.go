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
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/KSlashh/poly-abi/abi_1.9.25/ccm"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/contracts/native/go_abi/header_sync_abi"
	"github.com/ethereum/go-ethereum/contracts/native/go_abi/side_chain_manager_abi"
	"github.com/ethereum/go-ethereum/contracts/native/governance/node_manager"
	"github.com/ethereum/go-ethereum/contracts/native/header_sync/bsc"
	"github.com/ethereum/go-ethereum/contracts/native/header_sync/heco"
	"github.com/ethereum/go-ethereum/contracts/native/header_sync/okex"
	"github.com/ethereum/go-ethereum/contracts/native/utils"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	block3 "github.com/joeqian10/neo3-gogogo/block"
	crypto3 "github.com/joeqian10/neo3-gogogo/crypto"
	helper3 "github.com/joeqian10/neo3-gogogo/helper"
	io3 "github.com/joeqian10/neo3-gogogo/io"
	rpc3 "github.com/joeqian10/neo3-gogogo/rpc"
	sc3 "github.com/joeqian10/neo3-gogogo/sc"
	tx3 "github.com/joeqian10/neo3-gogogo/tx"
	wallet3 "github.com/joeqian10/neo3-gogogo/wallet"

	ontology_go_sdk "github.com/ontio/ontology-go-sdk"
	"github.com/polynetwork/poly/native/service/header_sync/cosmos"
	"github.com/polynetwork/poly/native/service/header_sync/polygon"
	"github.com/polynetwork/zion-setup/config"
	"github.com/polynetwork/zion-setup/log"
	cosmos2 "github.com/polynetwork/zion-setup/tools/cosmos"
	"github.com/polynetwork/zion-setup/tools/eth"
	"github.com/polynetwork/zion-setup/tools/neo3"
	"github.com/polynetwork/zion-setup/tools/tendermint"
	"github.com/polynetwork/zion-setup/tools/zion"
	"github.com/tendermint/tendermint/rpc/client/http"
)

var zeroGasPrice = big.NewInt(0)

func RegisterSideChain(method string, chainName string, z *zion.ZionTools, e *eth.ETHTools, signer *zion.ZionSigner) bool {
	var blkToWait uint64
	var extra, eccd []byte
	var err error
	switch chainName {
	case "quorum", "heimdall", "ont":
		blkToWait = 1
		eccd, err = hex.DecodeString(strings.Replace(config.DefConfig.ETHConfig.Eccd, "0x", "", 1))
		if err != nil {
			panic(fmt.Errorf("RegisterEthChain, failed to decode eccd '%s' : %v", config.DefConfig.ETHConfig.Eccd, err))
		}
	case "eth", "oec", "arbitrum", "optimism", "fantom", "avalanche", "xdai":
		blkToWait = 12
		eccd, err = hex.DecodeString(strings.Replace(config.DefConfig.ETHConfig.Eccd, "0x", "", 1))
		if err != nil {
			panic(fmt.Errorf("RegisterEthChain, failed to decode eccd '%s' : %v", config.DefConfig.ETHConfig.Eccd, err))
		}
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
		eccd, err = hex.DecodeString(strings.Replace(config.DefConfig.ETHConfig.Eccd, "0x", "", 1))
		if err != nil {
			panic(fmt.Errorf("RegisterEthChain, failed to decode eccd '%s' : %v", config.DefConfig.ETHConfig.Eccd, err))
		}
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
		eccd, err = hex.DecodeString(strings.Replace(config.DefConfig.ETHConfig.Eccd, "0x", "", 1))
		if err != nil {
			panic(fmt.Errorf("RegisterEthChain, failed to decode eccd '%s' : %v", config.DefConfig.ETHConfig.Eccd, err))
		}
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
		eccd, err = hex.DecodeString(strings.Replace(config.DefConfig.ETHConfig.Eccd, "0x", "", 1))
		if err != nil {
			panic(fmt.Errorf("RegisterEthChain, failed to decode eccd '%s' : %v", config.DefConfig.ETHConfig.Eccd, err))
		}
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
		eccd, err = hex.DecodeString(strings.Replace(config.DefConfig.ETHConfig.Eccd, "0x", "", 1))
		if err != nil {
			panic(fmt.Errorf("RegisterEthChain, failed to decode eccd '%s' : %v", config.DefConfig.ETHConfig.Eccd, err))
		}
	case "neo3":
		blkToWait = 1
		extra = helper3.UInt32ToBytes(config.DefConfig.Neo3Config.Neo3Magic)
		eccd = helper3.HexToBytes(config.DefConfig.Neo3Config.Neo3CCMC)
		if len(eccd) != 4 {
			panic(fmt.Errorf("incorrect Neo3CCMC length"))
		}
	case "zion", "switcheo":
		blkToWait = 1

	default:
		panic(fmt.Errorf("not supported chain name"))
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
		From: signer.Address, To: &utils.SideChainManagerContractAddress, Gas: 0, GasPrice: zeroGasPrice,
		Value: big.NewInt(int64(0)), Data: txData,
	}
	gasLimit, err := z.GetEthClient().EstimateGas(context.Background(), callMsg)
	if err != nil {
		panic(fmt.Errorf("RegisterEthChain, estimate gas limit error: %s", err.Error()))
	}
	nonce := zion.NewNonceManager(z.GetEthClient()).GetAddressNonce(signer.Address)
	tx := types.NewTx(&types.LegacyTx{Nonce: nonce, GasPrice: zeroGasPrice, Gas: gasLimit, To: &utils.SideChainManagerContractAddress, Value: big.NewInt(0), Data: txData})
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
			From: signer.Address, To: &utils.SideChainManagerContractAddress, Gas: 0, GasPrice: zeroGasPrice,
			Value: big.NewInt(int64(0)), Data: txData,
		}
		gasLimit, err := z.GetEthClient().EstimateGas(context.Background(), callMsg)
		if err != nil {
			panic(fmt.Errorf("ApproveRegisterSideChain, estimate gas limit error: %s", err.Error()))
		}
		nonce := zion.NewNonceManager(z.GetEthClient()).GetAddressNonce(signer.Address)
		tx := types.NewTx(&types.LegacyTx{Nonce: nonce, GasPrice: zeroGasPrice, Gas: gasLimit, To: &utils.SideChainManagerContractAddress, Value: big.NewInt(0), Data: txData})
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

	var raw []byte
	switch chainName {
	case "eth":
		curr, err := e.GetNodeHeight()
		if err != nil {
			panic(err)
		}
		log.Infof("current height of eth is %d", curr)
		hdr, err := e.Get1559BlockHeader(curr)
		if err != nil {
			panic(err)
		}
		raw, err = hdr.MarshalJSON()
		if err != nil {
			panic(err)
		}
	case "bsc":
		curr, err := e.GetNodeHeight()
		if err != nil {
			panic(err)
		}
		log.Infof("current height of eth is %d", curr)
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
		curr, err := e.GetNodeHeight()
		if err != nil {
			panic(err)
		}
		log.Infof("current height of eth is %d", curr)
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
		curr, err := e.GetNodeHeight()
		if err != nil {
			panic(err)
		}
		log.Infof("current height of eth is %d", curr)
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
		curr, err := e.GetNodeHeight()
		if err != nil {
			panic(err)
		}
		log.Infof("current height of eth is %d", curr)
		hdr, err := e.GetZionHeader(curr)
		if err != nil {
			panic(err)
		}
		raw, err = hdr.MarshalJSON()
		if err != nil {
			panic(err)
		}

	case "oec":
		curr, err := e.GetNodeHeight()
		if err != nil {
			panic(err)
		}
		log.Infof("current height of eth is %d", curr)
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
		curr, err := e.GetNodeHeight()
		if err != nil {
			panic(err)
		}
		log.Infof("current height of eth is %d", curr)
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
		ontCli := ontology_go_sdk.NewOntologySdk()
		ontCli.NewRpcClient().SetAddress(config.DefConfig.ETHConfig.OntRpcURL)

		genesisBlock, err := ontCli.GetBlockByHeight(config.DefConfig.ETHConfig.OntEpoch)
		if err != nil {
			panic(err)
		}
		raw = genesisBlock.Header.ToArray()
	case "neo3":
		cli := rpc3.NewClient(config.DefConfig.Neo3Config.Neo3Url)
		resp := cli.GetBlockHeader(strconv.Itoa(int(config.DefConfig.Neo3Config.Neo3Epoch)))
		if resp.HasError() {
			panic(fmt.Errorf("failed to get header: %v", resp.Error.Message))
		}
		header, err := block3.NewBlockHeaderFromRPC(&resp.Result)
		if err != nil {
			panic(err)
		}
		buf := io3.NewBufBinaryWriter()
		header.Serialize(buf.BinaryWriter)
		if buf.Err != nil {
			panic(buf.Err)
		}
		raw = buf.Bytes()
	case "switcheo":
		raw, _ = hex.DecodeString("0a94030a02080b120c636172626f6e2d333939313118ee9b0f220c08e8e9a0950610fcd0ced5012a480a206d0563a30e9963061b04d8bcea4a861c09d09f559c5bf9d90e6496ca143eee2f122408011220383c4a9e80bfef4ed9b782bfa1e665213afd23a955c00efcefcb5c057a51220a322080d63c8bfe612e42033c39a9eb30fccaee3d98af95cc021ae1adedf841f35e433a207a022cf773371fee568e9785d3e0b028dc84b2befc2d165c6329eb748a782fee4220b0abd420b473e699d05cfecafe002d84755250e3555c39f11780708e9e511b574a20b0abd420b473e699d05cfecafe002d84755250e3555c39f11780708e9e511b575220048091bc7ddc283f77bfbf91d73c44da58c3df8a9cbc867405d8b7f3daada22f5a200d03f7dd11c484a544c950be60b4a2a356687a1c9f75e0c64cfc00d9bb4b8c7862208541ad546f0b10d6135d517ada33c4a03074ceeec0f4882b930a64ff58e962e26a20e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85572142871b32a1ff12677e1fb7713488aa4d0220288b112f60308ee9b0f1a480a20ab13154744b0203181e101ff4aa3c355f5925d79cb5aa602b9530d610ebe3a52122408011220c2445de6e4b61071c633c65a0567f7d7189902bcd3f7b165ec2d7d731b61c1fe2268080212140563d4e17d981be668c9d2230466f524c9c8a13c1a0c08e9e9a0950610aefee0e90222401fe60289f4aefbf01e0f17286b4339f371df4df566ee5fab45fc9f0651d291180dd4f52c81f31afdd6eb70c11bee859b3f3e90871d97b2edac1c7af3cf9bd40e226808021214224f3dfaff1b2e4483a3ecd607805a57fa1ad4cf1a0c08e9e9a0950610b0ffe0e9022240f4a0a077d91748c17b6466ddea3b5930aea65fd873e3452919a3b033f345cbd966e195b6e248fca515b2c28b0939a7bcd0753b134eca3d9e8d80382aa9b260002268080212142871b32a1ff12677e1fb7713488aa4d0220288b11a0c08e9e9a0950610c296b7ea022240d808a4bf361ab4a4f70911f9c63e6a5584240d221acdabddc4056a490600355309e60cd55a6d3941d192f09fff631dff57f78c8957cd04c47e5101c387def40a226808021214594b590692ee77847194dd33d8355a3299f57de81a0c08e9e9a0950610bcc1e1e90222402262e7830f4c5fa84727b5be7a6274c590a14e4f16af4b9dc3b7761396dbb9acaef68627343d60ccc9fee033cd9c984949fbfb158d5c372fbfbfcdaef7ca9b011a4c0a140563d4e17d981be668c9d2230466f524c9c8a13c12251624de64206d74e00656db8f6c1bbf1ce9c53050666514b9cc57ba55f835d8b3bf80c55fd618a08d0620d8bcfeffffffffffff011a450a14224f3dfaff1b2e4483a3ecd607805a57fa1ad4cf12251624de642099a205552d36e35ea7e7ffdf82401de78bc61fe5995c8fcd949388e250ebf89318a08d0620fca4021a4c0a142871b32a1ff12677e1fb7713488aa4d0220288b112251624de6420b97e34689085fc0b4f317aa865842e634948a3c4c025d9dc7ef783fd9761a94d18a08d0620d8bcfeffffffffffff011a440a14594b590692ee77847194dd33d8355a3299f57de812251624de64202969da5e99366705d6eda69c5365775c98e81dab9f67a66a48fde903c58b33c318a08d0620d461")
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
			From: signer.Address, To: &utils.HeaderSyncContractAddress, Gas: 0, GasPrice: zeroGasPrice,
			Value: big.NewInt(int64(0)), Data: txData,
		}
		gasLimit, err := z.GetEthClient().EstimateGas(context.Background(), callMsg)
		if err != nil {
			panic(fmt.Errorf("SyncETHToZion, estimate gas limit error: %s", err.Error()))
		}
		nonce := zion.NewNonceManager(z.GetEthClient()).GetAddressNonce(signer.Address)
		tx := types.NewTx(&types.LegacyTx{Nonce: nonce, GasPrice: zeroGasPrice, Gas: gasLimit, To: &utils.HeaderSyncContractAddress, Value: big.NewInt(0), Data: txData})
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
	var h uint64
	if epochInfo.StartHeight != 0 {
		h = epochInfo.StartHeight - 1
	}
	rawHeader, _, err := z.GetRawHeaderAndRawSeals(h)
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

func SyncZionToNeo3(z *zion.ZionTools) {
	// get zion genesis validators
	node_manager.InitABI()
	input := new(node_manager.MethodGetEpochByIDInput)
	input.EpochID = 1 // starts from 1
	payload, err := input.Encode()
	if err != nil {
		panic(fmt.Errorf("SyncZionToNeo3, MethodGetEpochByIDInput.Encode error: %s", err.Error()))
	}
	arg := ethereum.CallMsg{
		From: common.Address{},
		To:   &utils.NodeManagerContractAddress,
		Data: payload,
	}
	res, err := z.GetEthClient().CallContract(context.Background(), arg, nil)
	if err != nil {
		panic(fmt.Errorf("SyncZionToNeo3, EthClient.CallContract error: %s", err.Error()))
	}
	output := new(node_manager.MethodEpochOutput)
	if err = output.Decode(res); err != nil {
		panic(fmt.Errorf("SyncZionToNeo3, MethodEpochOutput error: %s", err.Error()))
	}
	epochInfo := output.Epoch
	peers := epochInfo.Peers.List
	// sort public keys
	pubKeyList := []*ecdsa.PublicKey{}
	for _, peer := range peers {
		s := strings.TrimPrefix(peer.PubKey, "0x")
		keyBytes, _ := hex.DecodeString(s)
		pubKey, _ := crypto.DecompressPubkey(keyBytes)
		pubKeyList = append(pubKeyList, pubKey)
	}
	bs := []byte{}
	pubKeyList = neo3.SortPublicKeys(pubKeyList)
	for _, pubKey := range pubKeyList {
		keyBytes := crypto.CompressPubkey(pubKey)
		bs = append(bs, keyBytes...)
	}

	// peer.PubKey example
	//0x02c07fb7d48eac559a2483e249d27841c18c7ce5dbbbf2796a6963cc9cef27cabd
	//0x02f5135ae0853af71f017a8ecb68e720b729ab92c7123c686e75b7487d4a57ae07
	//0x03ecac0ebe7224cfd04056c940605a4a9d4cb0367cf5819bf7e5502bf44f68bdd4
	//0x03d0ecfd09db6b1e4f59da7ebde8f6c3ea3ed09f06f5190477ae4ee528ec692fa8
	//0x0244e509103445d5e8fd290608308d16d08c739655d6994254e413bc1a06783856
	//0x023884de29148505a8d862992e5721767d4b47ff52ffab4c2d2527182d812a6d95
	//0x03b838fa2387beb3a56aed86e447309f8844cb208387c63af64ad740729b5c0a27
	// after sort
	//023884de29148505a8d862992e5721767d4b47ff52ffab4c2d2527182d812a6d95
	//0244e509103445d5e8fd290608308d16d08c739655d6994254e413bc1a06783856
	//03b838fa2387beb3a56aed86e447309f8844cb208387c63af64ad740729b5c0a27
	//02c07fb7d48eac559a2483e249d27841c18c7ce5dbbbf2796a6963cc9cef27cabd
	//03d0ecfd09db6b1e4f59da7ebde8f6c3ea3ed09f06f5190477ae4ee528ec692fa8
	//03ecac0ebe7224cfd04056c940605a4a9d4cb0367cf5819bf7e5502bf44f68bdd4
	//02f5135ae0853af71f017a8ecb68e720b729ab92c7123c686e75b7487d4a57ae07

	// create contract parameter
	cp1 := sc3.ContractParameter{
		Type:  sc3.ByteArray,
		Value: bs,
	}

	// build script
	scriptHash, err := helper3.UInt160FromString(config.DefConfig.Neo3Config.Neo3CCMC) // big endian
	if err != nil {
		panic(fmt.Errorf("SyncZionToNeo3, neo3 ccmc conversion error: %s", err.Error()))
	}

	script, err := sc3.MakeScript(scriptHash, "initGenesisBlock", []interface{}{cp1})
	if err != nil {
		panic(fmt.Errorf("SyncZionToNeo3, neo3 sc.MakeScript error: %s", err.Error()))
	}

	// create wallet helper
	neoRpcClient := rpc3.NewClient(config.DefConfig.Neo3Config.Neo3Url)
	ps := helper3.ProtocolSettings{
		Magic:          config.DefConfig.Neo3Config.Neo3Magic,
		AddressVersion: config.DefConfig.Neo3Config.Neo3AddressVersion,
	}
	w, err := wallet3.NewNEP6Wallet(config.DefConfig.Neo3Config.Neo3Wallet, &ps, nil, nil)
	if err != nil {
		panic(fmt.Errorf("SyncZionToNeo3, neo3 NewNEP6Wallet error: %s", err.Error()))
	}
	err = w.Unlock(config.DefConfig.Neo3Config.Neo3Pwd)
	if err != nil {
		panic(fmt.Errorf("SyncZionToNeo3, neo3 NEP6Wallet.Unlock error: %s", err.Error()))
	}
	wh := wallet3.NewWalletHelperFromWallet(neoRpcClient, w)

	balancesGas, err := wh.GetAccountAndBalance(tx3.GasToken)
	if err != nil {
		panic(fmt.Errorf("SyncZionToNeo3, wh.GetAccountAndBalance error: %s", err.Error()))
	}

	// make transaction
	trx, err := wh.MakeTransaction(script, nil, []tx3.ITransactionAttribute{}, balancesGas)
	if err != nil {
		panic(fmt.Errorf("SyncZionToNeo3, wh.MakeTransaction error: %s", err.Error()))
	}

	// sign transaction
	trx, err = wh.SignTransaction(trx, config.DefConfig.Neo3Config.Neo3Magic)
	if err != nil {
		panic(fmt.Errorf("SyncZionToNeo3, wh.SignTransaction error: %s", err.Error()))
	}
	rawTxString := crypto3.Base64Encode(trx.ToByteArray())

	// send the raw transaction
	response := wh.Client.SendRawTransaction(rawTxString)
	if response.HasError() {
		panic(fmt.Errorf("SyncZionToNeo3, neo3 SendRawTransaction error: %s", response.GetErrorInfo()))
	}
	log.Infof("sync poly header to neo3 as genesis, neo3TxHash: %s", trx.GetHash().String())

	// wait for confirmation on neo3
	count := 0
	for {
		time.Sleep(15 * time.Second) // neo3 block time = 15s
		count++
		response2 := wh.Client.GetRawTransaction(trx.GetHash().String())
		if response2.HasError() {
			if strings.Contains(response2.GetErrorInfo(), "Unknown transaction") {
				if count < 2 {
					continue
				} else {
					panic(fmt.Errorf("SyncZionToNeo3, neo3Tx: %s is not confirmed after 30s", trx.GetHash().String()))
				}
			} else {
				panic(fmt.Errorf("SyncZionToNeo3, neo3 GetRawTransaction error: %s", response2.GetErrorInfo()))
			}
		} else {
			if response2.Result.Hash == "" {
				if count < 2 {
					continue
				} else {
					panic(fmt.Errorf("SyncZionToNeo3, neo3Tx: %s is not confirmed after 30s", trx.GetHash().String()))
				}
			} else {
				log.Infof("sync poly header to neo3 as genesis, neo3TxHash: %s confirmed", response2.Result.Hash)
				break
			}
		}
	}
}

func SyncZionToCM(z *zion.ZionTools) {
	epochInfo, err := z.GetEpochInfo()
	if err != nil {
		panic(fmt.Errorf("SyncZionToCM, GetEpochInfo error: %s", err.Error()))
	}
	var h uint64
	if epochInfo.StartHeight != 0 {
		h = epochInfo.StartHeight - 1
	}
	rawHeader, _, err := z.GetRawHeaderAndRawSeals(h)
	if err != nil {
		panic(fmt.Errorf("SyncZionToCM, GetRawHeaderAndRawSeals error: %s", err.Error()))
	}

	invoker, err := cosmos2.NewCosmosInvoker()
	if err != nil {
		panic(err)
	}

	tx, err := invoker.SyncPolyGenesisHdr(invoker.Acc.Acc, rawHeader)
	if err != nil {
		panic(err)
	}

	log.Infof("successful to sync poly genesis header to cosmos: ( txhash: %s )", tx.Hash.String())
}
