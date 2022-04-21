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
package cosmos

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mintkey"
	"github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/auth"
	"github.com/cosmos/cosmos-sdk/x/auth/exported"
	"github.com/polynetwork/cosmos-poly-module/headersync"
	"github.com/polynetwork/zion-setup/config"
	"github.com/polynetwork/zion-setup/log"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/libs/bytes"
	"github.com/tendermint/tendermint/rpc/client/http"
	coretypes "github.com/tendermint/tendermint/rpc/core/types"
	types2 "github.com/tendermint/tendermint/types"
)

type CosmosInvoker struct {
	RpcCli *http.HTTP
	Acc    *CosmosAcc
	CMGas  uint64
	CMFees types.Coins
	CMCdc  *codec.Codec
}

func GetValidators(rpc *http.HTTP, h int64) ([]*types2.Validator, error) {
	p := 1
	vSet := make([]*types2.Validator, 0)
	for {
		res, err := rpc.Validators(&h, p, 100)
		if err != nil {
			if strings.Contains(err.Error(), "page should be within") {
				return vSet, nil
			}
			return nil, err
		}
		// In case tendermint don't give relayer the right error
		if len(res.Validators) == 0 {
			return vSet, nil
		}
		vSet = append(vSet, res.Validators...)
		p++
	}
}

func NewCosmosInvoker() (*CosmosInvoker, error) {
	var (
		err      error
		gasPrice types.DecCoins
	)
	invoker := &CosmosInvoker{}
	conf := types.GetConfig()
	conf.SetBech32PrefixForAccount("swth", "swthpub")
	conf.SetBech32PrefixForValidator("swthvaloper", "swthvaloperpub")
	conf.SetBech32PrefixForConsensusNode("swthvalcons", "swthvalconspub")
	conf.Seal()

	invoker.RpcCli, err = http.New(config.DefConfig.CMConfig.CMJsonRpcURL, "/websocket")
	if err != nil {
		return nil, err
	}
	invoker.CMCdc = NewCodec()

	invoker.Acc, err = NewCosmosAcc(config.DefConfig.CMConfig.CMWalletPath, config.DefConfig.CMConfig.CMWalletPwd,
		invoker.RpcCli, invoker.CMCdc)
	if err != nil {
		return nil, err
	}
	invoker.CMGas = config.DefConfig.CMConfig.CMGas
	if gasPrice, err = types.ParseDecCoins(config.DefConfig.CMConfig.CMGasPrice); err != nil {
		return nil, err
	}
	if invoker.CMFees, err = CalcCosmosFees(gasPrice, config.DefConfig.CMConfig.CMGas); err != nil {
		return nil, err
	}

	return invoker, nil
}

type CosmosAcc struct {
	Acc        types.AccAddress
	PrivateKey crypto.PrivKey
	Seq        *CosmosSeq
	AccNum     uint64
}

func NewCosmosAcc(wallet, pwd string, cli *http.HTTP, cdc *codec.Codec) (*CosmosAcc, error) {
	acc := &CosmosAcc{}
	bz, err := ioutil.ReadFile(wallet)
	if err != nil {
		return nil, err
	}

	privKey, _, err := mintkey.UnarmorDecryptPrivKey(string(bz), string(pwd))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: v", err)
	}

	acc.PrivateKey = privKey
	acc.Acc = types.AccAddress(privKey.PubKey().Address().Bytes())
	log.Infof("cosmos address: %s", acc.Acc.String())
	var eAcc exported.Account
	rawParam, err := cdc.MarshalJSON(auth.NewQueryAccountParams(acc.Acc))
	if err != nil {
		return nil, err
	}
	res, err := cli.ABCIQuery("/custom/acc/account", rawParam)
	if err != nil {
		return nil, err
	}
	if !res.Response.IsOK() {
		return nil, fmt.Errorf("failed to get response for accout-query: %v", res.Response)
	}
	if err := cdc.UnmarshalJSON(res.Response.Value, &eAcc); err != nil {
		return nil, fmt.Errorf("unmarshal query-account-resp failed, err: %v", err)
	}
	acc.Seq = &CosmosSeq{
		lock: sync.Mutex{},
		val:  eAcc.GetSequence(),
	}
	acc.AccNum = eAcc.GetAccountNumber()

	return acc, nil
}

func (invoker *CosmosInvoker) sendCosmosTx(msgs []types.Msg) (*coretypes.ResultBroadcastTx, error) {
	toSign := auth.StdSignMsg{
		Sequence:      invoker.Acc.Seq.GetAndAdd(),
		AccountNumber: invoker.Acc.AccNum,
		ChainID:       "switcheochain",
		Msgs:          msgs,
		Fee:           auth.NewStdFee(invoker.CMGas, invoker.CMFees),
	}
	sig, err := invoker.Acc.PrivateKey.Sign(toSign.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to sign raw tx: (error: %v, raw tx: %x)", err, toSign.Bytes())
	}

	tx := auth.NewStdTx(msgs, toSign.Fee, []auth.StdSignature{{invoker.Acc.PrivateKey.PubKey(),
		sig}}, toSign.Memo)
	encoder := auth.DefaultTxEncoder(invoker.CMCdc)
	rawTx, err := encoder(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signed tx: %v", err)
	}

	var res *coretypes.ResultBroadcastTx
	for {
		res, err = invoker.RpcCli.BroadcastTxSync(rawTx)
		if err != nil {
			return nil, fmt.Errorf("failed to broadcast tx: (error: %v, raw tx: %x)", err, rawTx)
		}
		if res.Code != 0 {
			if strings.Contains(res.Log, "verify correct account sequence and chain-id") {
				time.Sleep(time.Second)
				continue
			}
			return nil, fmt.Errorf("failed to check tx: (code: %d, log: %s)", res.Code, res.Log)
		} else {
			break
		}
	}

	return res, nil
}

func (invoker *CosmosInvoker) SyncPolyGenesisHdr(syner types.AccAddress, rawHdr []byte) (*coretypes.ResultBroadcastTx, error) {
	param := &headersync.MsgSyncGenesisParam{
		Syncer:        invoker.Acc.Acc,
		GenesisHeader: hex.EncodeToString(rawHdr),
	}
	resTx, err := invoker.sendCosmosTx([]types.Msg{param})
	if err != nil {
		return nil, err
	}

	invoker.WaitTx(resTx.Hash)
	return resTx, nil
}

func (invoker *CosmosInvoker) WaitTx(txhash bytes.HexBytes) {
	tick := time.NewTicker(time.Second)
	for range tick.C {
		res, err := invoker.RpcCli.Tx(txhash, false)
		if err == nil && res.Height > 0 {
			break
		}
	}
}

type CosmosSeq struct {
	lock sync.Mutex
	val  uint64
}

func (seq *CosmosSeq) GetAndAdd() uint64 {
	seq.lock.Lock()
	defer func() {
		seq.val += 1
		seq.lock.Unlock()
	}()
	return seq.val
}
