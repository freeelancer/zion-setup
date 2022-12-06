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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/contracts/native/governance/node_manager"
	"github.com/ethereum/go-ethereum/contracts/native/utils"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/polynetwork/zion-setup/log"
)

type ZionTools struct {
	restclient *RestClient
	ethclient  *ethclient.Client
}

type jsonError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type heightReq struct {
	JsonRpc string   `json:"jsonrpc"`
	Method  string   `json:"method"`
	Params  []string `json:"params"`
	Id      uint     `json:"id"`
}

type heightRep struct {
	JsonRpc string     `json:"jsonrpc"`
	Result  string     `json:"result"`
	Error   *jsonError `json:"error,omitempty"`
	Id      uint       `json:"id"`
}

type BlockReq struct {
	JsonRpc string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	Id      uint          `json:"id"`
}

type BlockRep struct {
	JsonRPC string        `json:"jsonrpc"`
	Result  *types.Header `json:"result"`
	Error   *jsonError    `json:"error,omitempty"`
	Id      uint          `json:"id"`
}

type proofReq struct {
	JsonRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	Id      uint          `json:"id"`
}

type proofRsp struct {
	JsonRPC string     `json:"jsonrpc"`
	Result  ETHProof   `json:"result,omitempty"`
	Error   *jsonError `json:"error,omitempty"`
	Id      uint       `json:"id"`
}

type ETHProof struct {
	Address       string         `json:"address"`
	Balance       string         `json:"balance"`
	CodeHash      string         `json:"codeHash"`
	Nonce         string         `json:"nonce"`
	StorageHash   string         `json:"storageHash"`
	AccountProof  []string       `json:"accountProof"`
	StorageProofs []StorageProof `json:"storageProof"`
}

type StorageProof struct {
	Key   string   `json:"key"`
	Value string   `json:"value"`
	Proof []string `json:"proof"`
}

func NewZionTools(url string) *ZionTools {
	ethclient, err := ethclient.Dial(url)
	if err != nil {
		log.Error("NewZionTools: cannot dial sync node, err: %s", err)
		return nil
	}
	restclient := NewRestClient()
	restclient.SetAddr(url)
	tool := &ZionTools{
		restclient: restclient,
		ethclient:  ethclient,
	}
	return tool
}

func (self *ZionTools) GetEthClient() *ethclient.Client {
	return self.ethclient
}

func (self *ZionTools) GetRawHeaderAndRawSeals(height uint64) (rawHeader, rawSeals []byte, err error) {
	header, err := self.GetBlockHeader(height)
	if err != nil {
		return
	}
	headerBs, _ := rlp.EncodeToBytes(header)
	fmt.Println("Height")
	fmt.Println(height)
	fmt.Println("FULL Header")
	fmt.Println(hex.EncodeToString(headerBs))
	rawHeader, err = rlp.EncodeToBytes(types.HotstuffFilteredHeader(header))
	fmt.Println("raw Header")
	fmt.Println(hex.EncodeToString(rawHeader))
	extra, err := types.ExtractHotstuffExtra(header)
	if err != nil {
		return
	}
	rawSeals, err = rlp.EncodeToBytes(extra.CommittedSeal)
	fmt.Println("raw Seals")
	fmt.Println(hex.EncodeToString(rawSeals))
	return
}

func (self *ZionTools) GetEpochInfo() (epochInfo *node_manager.EpochInfo, err error) {
	node_manager.InitABI()
	payload, err := new(node_manager.GetCurrentEpochInfoParam).Encode()
	if err != nil {
		return
	}
	arg := ethereum.CallMsg{
		From: common.Address{},
		To:   &utils.NodeManagerContractAddress,
		Data: payload,
	}
	res, err := self.GetEthClient().CallContract(context.Background(), arg, nil)
	if err != nil {
		return
	}
	output := new(node_manager.EpochInfo)
	if err = output.Decode(res); err != nil {
		return
	}
	epochInfo = output
	return
}

func (self *ZionTools) GetNodeHeight() (uint64, error) {
	req := &heightReq{
		JsonRpc: "2.0",
		Method:  "eth_blockNumber",
		Params:  make([]string, 0),
		Id:      1,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return 0, fmt.Errorf("GetNodeHeight: marshal req err: %s", err)
	}
	resp, err := self.restclient.SendRestRequest(data)
	if err != nil {
		return 0, fmt.Errorf("GetNodeHeight err: %s", err)
	}
	rep := &heightRep{}
	err = json.Unmarshal(resp, rep)
	if err != nil {
		return 0, fmt.Errorf("GetNodeHeight, unmarshal resp err: %s", err)
	}
	if rep.Error != nil {
		return 0, fmt.Errorf("GetNodeHeight, unmarshal resp err: %s", rep.Error.Message)
	}
	height, err := strconv.ParseUint(rep.Result, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("GetNodeHeight, parse resp height %s failed", rep.Result)
	} else {
		return height, nil
	}
}

func (self *ZionTools) GetBlockHeader(height uint64) (*types.Header, error) {
	params := []interface{}{fmt.Sprintf("0x%x", height), true}
	req := &BlockReq{
		JsonRpc: "2.0",
		Method:  "eth_getBlockByNumber",
		Params:  params,
		Id:      1,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("GetBlockHeader: marshal req err: %s", err)
	}
	resp, err := self.restclient.SendRestRequest(data)
	if err != nil {
		return nil, fmt.Errorf("GetBlockHeader err: %s", err)
	}
	rsp := &BlockRep{}
	err = json.Unmarshal(resp, rsp)
	if err != nil {
		return nil, fmt.Errorf("GetBlockHeader, unmarshal resp err: %s", err)
	}
	if rsp.Error != nil {
		return nil, fmt.Errorf("GetBlockHeader, unmarshal resp err: %s", rsp.Error.Message)
	}

	return rsp.Result, nil
}

func (self *ZionTools) GetChainID() (*big.Int, error) {
	return self.ethclient.ChainID(context.Background())
}

func (self *ZionTools) WaitTransactionConfirm(hash common.Hash) bool {
	start := time.Now()
	for {
		if time.Now().After(start.Add(time.Minute * 1)) {
			return false
		}
		time.Sleep(time.Second * 1)
		_, ispending, err := self.GetEthClient().TransactionByHash(context.Background(), hash)
		if err != nil {
			continue
		}
		log.Debugf("eth_transaction %s is pending: %v", hash.String(), ispending)
		if ispending == true {
			continue
		} else {
			receipt, err := self.GetEthClient().TransactionReceipt(context.Background(), hash)
			if err != nil {
				continue
			}
			return receipt.Status == types.ReceiptStatusSuccessful
		}
	}
}

func rlpEncodeStringList(raw []string) ([]byte, error) {
	var rawBytes []byte
	for i := 0; i < len(raw); i++ {
		rawBytes = append(rawBytes, common.Hex2Bytes(raw[i][2:])...)
		// rawBytes = append(rawBytes, common.Hex2Bytes(raw[i][2:]))
	}
	return rlp.EncodeToBytes(rawBytes)
}

type RestClient struct {
	addr       string
	restClient *http.Client
	user       string
	passwd     string
}

func NewRestClient() *RestClient {
	return &RestClient{
		restClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost:   5,
				DisableKeepAlives:     false,
				IdleConnTimeout:       time.Second * 300,
				ResponseHeaderTimeout: time.Second * 300,
				TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: time.Second * 300,
		},
	}
}

func (self *RestClient) SetAddr(addr string) *RestClient {
	self.addr = addr
	return self
}

func (self *RestClient) SetAuth(user string, passwd string) *RestClient {
	self.user = user
	self.passwd = passwd
	return self
}

func (self *RestClient) SetRestClient(restClient *http.Client) *RestClient {
	self.restClient = restClient
	return self
}

func (self *RestClient) SendRestRequest(data []byte) ([]byte, error) {
	resp, err := self.restClient.Post(self.addr, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("http post request:%s error:%s", data, err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read rest response body error:%s", err)
	}
	return body, nil
}

func (self *RestClient) SendRestRequestWithAuth(data []byte) ([]byte, error) {
	url := self.addr
	bodyReader := bytes.NewReader(data)
	httpReq, err := http.NewRequest("POST", url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("SendRestRequestWithAuth - build http request error:%s", err)
	}
	httpReq.Close = true
	httpReq.Header.Set("Content-Type", "application/json")

	httpReq.SetBasicAuth(self.user, self.passwd)

	rsp, err := self.restClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("SendRestRequestWithAuth - http post error:%s", err)
	}
	defer rsp.Body.Close()
	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil || len(body) == 0 {
		return nil, fmt.Errorf("SendRestRequestWithAuth - read rest response body error:%s", err)
	}
	return body, nil
}
