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
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/KSlashh/poly-abi/abi_1.9.25/ccm"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/contracts/native/go_abi/side_chain_manager_abi"
	"github.com/ethereum/go-ethereum/contracts/native/utils"
	"github.com/ethereum/go-ethereum/core/types"
	helper3 "github.com/joeqian10/neo3-gogogo/helper"
	"github.com/polynetwork/zion-setup/config"
	"github.com/polynetwork/zion-setup/log"
	cosmos2 "github.com/polynetwork/zion-setup/tools/cosmos"
	"github.com/polynetwork/zion-setup/tools/eth"
	"github.com/polynetwork/zion-setup/tools/zion"
)

func RegisterSideChain(method string, chainName string, z *zion.ZionTools, signer *zion.ZionSigner) bool {
	var eccd []byte
	var err error
	switch chainName {
	case "quorum", "ont":
		eccd, err = hex.DecodeString(strings.Replace(config.DefConfig.SideConfig.Eccd, "0x", "", 1))
		if err != nil {
			panic(fmt.Errorf("RegisterEthChain, failed to decode eccd '%s' : %v", config.DefConfig.SideConfig.Eccd, err))
		}
	case "eth", "oec", "arbitrum", "optimism", "fantom", "avalanche", "xdai":
		eccd, err = hex.DecodeString(strings.Replace(config.DefConfig.SideConfig.Eccd, "0x", "", 1))
		if err != nil {
			panic(fmt.Errorf("RegisterEthChain, failed to decode eccd '%s' : %v", config.DefConfig.SideConfig.Eccd, err))
		}
	case "bsc":
		eccd, err = hex.DecodeString(strings.Replace(config.DefConfig.SideConfig.Eccd, "0x", "", 1))
		if err != nil {
			panic(fmt.Errorf("RegisterEthChain, failed to decode eccd '%s' : %v", config.DefConfig.SideConfig.Eccd, err))
		}
	case "heco":
		eccd, err = hex.DecodeString(strings.Replace(config.DefConfig.SideConfig.Eccd, "0x", "", 1))
		if err != nil {
			panic(fmt.Errorf("RegisterEthChain, failed to decode eccd '%s' : %v", config.DefConfig.SideConfig.Eccd, err))
		}
	case "polygon":
		eccd, err = hex.DecodeString(strings.Replace(config.DefConfig.SideConfig.Eccd, "0x", "", 1))
		if err != nil {
			panic(fmt.Errorf("RegisterEthChain, failed to decode eccd '%s' : %v", config.DefConfig.SideConfig.Eccd, err))
		}
	case "pixie":
		eccd, err = hex.DecodeString(strings.Replace(config.DefConfig.SideConfig.Eccd, "0x", "", 1))
		if err != nil {
			panic(fmt.Errorf("RegisterEthChain, failed to decode eccd '%s' : %v", config.DefConfig.SideConfig.Eccd, err))
		}
	case "neo3":
		eccd = helper3.HexToBytes(config.DefConfig.SideConfig.Eccd)
		if len(eccd) != 4 {
			panic(fmt.Errorf("incorrect Neo3 eccd length"))
		}

	default:
		panic(fmt.Errorf("not supported chain name"))
	}

	scmAbi, err := abi.JSON(strings.NewReader(side_chain_manager_abi.ISideChainManagerABI))
	if err != nil {
		panic(fmt.Errorf("RegisterEthChain, abi.JSON error:" + err.Error()))
	}
	gasPrice, err := z.GetEthClient().SuggestGasPrice(context.Background())
	if err != nil {
		panic(fmt.Errorf("RegisterEthChain, get suggest gas price failed error: %s", err.Error()))
	}
	gasPrice = gasPrice.Mul(gasPrice, big.NewInt(1))

	txData, err := scmAbi.Pack(method, config.DefConfig.SideConfig.ChainId, config.DefConfig.SideConfig.Router,
		chainName, eccd, []byte{})
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
	scmAbi, err := abi.JSON(strings.NewReader(side_chain_manager_abi.ISideChainManagerABI))
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
		txData, err := scmAbi.Pack(method, config.DefConfig.SideConfig.ChainId)
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

func SyncZionToETH(z *zion.ZionTools, e *eth.ETHTools) {
	signer, err := eth.NewEthSigner(config.DefConfig.SideConfig.PrivateKey)
	if err != nil {
		panic(err)
	}
	epochInfo, err := z.GetEpochInfo()
	if err != nil {
		panic(fmt.Errorf("SyncZionToETH, GetEpochInfo error: %s", err.Error()))
	}
	var h uint64
	if epochInfo.StartHeight.Sign() != 0 {
		h = epochInfo.StartHeight.Uint64() - 1
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
	eccm := common.HexToAddress(config.DefConfig.SideConfig.Eccm)
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

//func SyncZionToNeo3(z *zion.ZionTools) {
//	// get zion genesis validators
//	epochInfo, err := z.GetEpochInfo()
//	if err != nil {
//		panic(fmt.Errorf("SyncZionToETH, GetEpochInfo error: %s", err.Error()))
//	}
//	peers := epochInfo.Validators
//	// sort public keys
//	pubKeyList := []*ecdsa.PublicKey{}
//	for _, peer := range peers {
//		s := strings.TrimPrefix(peer.PubKey, "0x")
//		keyBytes, _ := hex.DecodeString(s)
//		pubKey, _ := crypto.DecompressPubkey(keyBytes)
//		pubKeyList = append(pubKeyList, pubKey)
//	}
//	bs := []byte{}
//	pubKeyList = neo3.SortPublicKeys(pubKeyList)
//	for _, pubKey := range pubKeyList {
//		keyBytes := crypto.CompressPubkey(pubKey)
//		bs = append(bs, keyBytes...)
//	}
//
//	// peer.PubKey example
//	//0x02c07fb7d48eac559a2483e249d27841c18c7ce5dbbbf2796a6963cc9cef27cabd
//	//0x02f5135ae0853af71f017a8ecb68e720b729ab92c7123c686e75b7487d4a57ae07
//	//0x03ecac0ebe7224cfd04056c940605a4a9d4cb0367cf5819bf7e5502bf44f68bdd4
//	//0x03d0ecfd09db6b1e4f59da7ebde8f6c3ea3ed09f06f5190477ae4ee528ec692fa8
//	//0x0244e509103445d5e8fd290608308d16d08c739655d6994254e413bc1a06783856
//	//0x023884de29148505a8d862992e5721767d4b47ff52ffab4c2d2527182d812a6d95
//	//0x03b838fa2387beb3a56aed86e447309f8844cb208387c63af64ad740729b5c0a27
//	// after sort
//	//023884de29148505a8d862992e5721767d4b47ff52ffab4c2d2527182d812a6d95
//	//0244e509103445d5e8fd290608308d16d08c739655d6994254e413bc1a06783856
//	//03b838fa2387beb3a56aed86e447309f8844cb208387c63af64ad740729b5c0a27
//	//02c07fb7d48eac559a2483e249d27841c18c7ce5dbbbf2796a6963cc9cef27cabd
//	//03d0ecfd09db6b1e4f59da7ebde8f6c3ea3ed09f06f5190477ae4ee528ec692fa8
//	//03ecac0ebe7224cfd04056c940605a4a9d4cb0367cf5819bf7e5502bf44f68bdd4
//	//02f5135ae0853af71f017a8ecb68e720b729ab92c7123c686e75b7487d4a57ae07
//
//	// create contract parameter
//	cp1 := sc3.ContractParameter{
//		Type:  sc3.ByteArray,
//		Value: bs,
//	}
//
//	// build script
//	scriptHash, err := helper3.UInt160FromString(config.DefConfig.Neo3Config.Neo3CCMC) // big endian
//	if err != nil {
//		panic(fmt.Errorf("SyncZionToNeo3, neo3 ccmc conversion error: %s", err.Error()))
//	}
//
//	script, err := sc3.MakeScript(scriptHash, "initGenesisBlock", []interface{}{cp1})
//	if err != nil {
//		panic(fmt.Errorf("SyncZionToNeo3, neo3 sc.MakeScript error: %s", err.Error()))
//	}
//
//	// create wallet helper
//	neoRpcClient := rpc3.NewClient(config.DefConfig.Neo3Config.Neo3Url)
//	ps := helper3.ProtocolSettings{
//		Magic:          config.DefConfig.Neo3Config.Neo3Magic,
//		AddressVersion: config.DefConfig.Neo3Config.Neo3AddressVersion,
//	}
//	w, err := wallet3.NewNEP6Wallet(config.DefConfig.Neo3Config.Neo3Wallet, &ps, nil, nil)
//	if err != nil {
//		panic(fmt.Errorf("SyncZionToNeo3, neo3 NewNEP6Wallet error: %s", err.Error()))
//	}
//	err = w.Unlock(config.DefConfig.Neo3Config.Neo3Pwd)
//	if err != nil {
//		panic(fmt.Errorf("SyncZionToNeo3, neo3 NEP6Wallet.Unlock error: %s", err.Error()))
//	}
//	wh := wallet3.NewWalletHelperFromWallet(neoRpcClient, w)
//
//	balancesGas, err := wh.GetAccountAndBalance(tx3.GasToken)
//	if err != nil {
//		panic(fmt.Errorf("SyncZionToNeo3, wh.GetAccountAndBalance error: %s", err.Error()))
//	}
//
//	// make transaction
//	trx, err := wh.MakeTransaction(script, nil, []tx3.ITransactionAttribute{}, balancesGas)
//	if err != nil {
//		panic(fmt.Errorf("SyncZionToNeo3, wh.MakeTransaction error: %s", err.Error()))
//	}
//
//	// sign transaction
//	trx, err = wh.SignTransaction(trx, config.DefConfig.Neo3Config.Neo3Magic)
//	if err != nil {
//		panic(fmt.Errorf("SyncZionToNeo3, wh.SignTransaction error: %s", err.Error()))
//	}
//	rawTxString := crypto3.Base64Encode(trx.ToByteArray())
//
//	// send the raw transaction
//	response := wh.Client.SendRawTransaction(rawTxString)
//	if response.HasError() {
//		panic(fmt.Errorf("SyncZionToNeo3, neo3 SendRawTransaction error: %s", response.GetErrorInfo()))
//	}
//	log.Infof("sync poly header to neo3 as genesis, neo3TxHash: %s", trx.GetHash().String())
//
//	// wait for confirmation on neo3
//	count := 0
//	for {
//		time.Sleep(15 * time.Second) // neo3 block time = 15s
//		count++
//		response2 := wh.Client.GetRawTransaction(trx.GetHash().String())
//		if response2.HasError() {
//			if strings.Contains(response2.GetErrorInfo(), "Unknown transaction") {
//				if count < 2 {
//					continue
//				} else {
//					panic(fmt.Errorf("SyncZionToNeo3, neo3Tx: %s is not confirmed after 30s", trx.GetHash().String()))
//				}
//			} else {
//				panic(fmt.Errorf("SyncZionToNeo3, neo3 GetRawTransaction error: %s", response2.GetErrorInfo()))
//			}
//		} else {
//			if response2.Result.Hash == "" {
//				if count < 2 {
//					continue
//				} else {
//					panic(fmt.Errorf("SyncZionToNeo3, neo3Tx: %s is not confirmed after 30s", trx.GetHash().String()))
//				}
//			} else {
//				log.Infof("sync poly header to neo3 as genesis, neo3TxHash: %s confirmed", response2.Result.Hash)
//				break
//			}
//		}
//	}
//}

func SyncZionToCM(z *zion.ZionTools) {
	epochInfo, err := z.GetEpochInfo()
	if err != nil {
		panic(fmt.Errorf("SyncZionToCM, GetEpochInfo error: %s", err.Error()))
	}
	var h uint64
	if epochInfo.StartHeight.Sign() != 0 {
		h = epochInfo.StartHeight.Uint64() - 1
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
