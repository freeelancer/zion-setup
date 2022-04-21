package method

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/contracts/native/governance/node_manager"
	"github.com/ethereum/go-ethereum/contracts/native/utils"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/joeqian10/neo3-gogogo/helper"
	"github.com/polynetwork/zion-setup/tools/neo3"
	"github.com/polynetwork/zion-setup/tools/zion"
	"strings"
	"testing"
)

func TestSyncZionToNeo3(t *testing.T) {
	z := zion.NewZionTools("http://101.32.99.70:22001")
	epochInfo, err := z.GetEpochInfo()
	if err != nil {
		panic(fmt.Errorf("SyncZionToNeo3, GetEpochInfo error: %s", err.Error()))
	}
	var h uint64
	if epochInfo.StartHeight != 0 {
		h = epochInfo.StartHeight - 1
	}
	rawHeader, _, err := z.GetRawHeaderAndRawSeals(h)
	if err != nil {
		panic(fmt.Errorf("SyncZionToNeo3, GetRawHeaderAndRawSeals error: %s", err.Error()))
	}
	fmt.Println(helper.BytesToHex(rawHeader))
}

func TestSyncZionToNeo3_2(t *testing.T) {
	z := zion.NewZionTools("http://101.32.99.70:22001")
	h := uint64(1)
	rawHeader, _, err := z.GetRawHeaderAndRawSeals(h)
	if err != nil {
		panic(fmt.Errorf("SyncZionToNeo3, GetRawHeaderAndRawSeals error: %s", err.Error()))
	}
	fmt.Println(helper.BytesToHex(rawHeader))
}

func TestSyncZionToNeo3_3(t *testing.T) {
	z := zion.NewZionTools("http://101.32.99.70:22001")
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
	fmt.Println("before sort")
	for _, peer := range peers {
		s := strings.TrimPrefix(peer.PubKey, "0x")
		keyBytes, _ := hex.DecodeString(s)
		fmt.Println(hex.EncodeToString(keyBytes))
		pubKey, _ := crypto.DecompressPubkey(keyBytes)
		pubKeyList = append(pubKeyList, pubKey)
	}
	bs := []byte{}
	pubKeyList = neo3.SortPublicKeys(pubKeyList)
	fmt.Println("after sort")
	for _, pubKey := range pubKeyList {
		keyBytes := crypto.CompressPubkey(pubKey)
		fmt.Println(hex.EncodeToString(keyBytes))
		bs = append(bs, keyBytes...)
	}
}
