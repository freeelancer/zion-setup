package method

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/contracts/native/governance/node_manager"
	"github.com/ethereum/go-ethereum/contracts/native/utils"
	"github.com/joeqian10/neo3-gogogo/helper"
	"github.com/polynetwork/zion-setup/tools/zion"
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
	bs := []byte{}

	peers := epochInfo.Peers.List
	for _, peer := range peers {
		fmt.Println(peer.PubKey)
		keyBytes, _ := hex.DecodeString(peer.PubKey)
		bs = append(bs, keyBytes...)
	}
}