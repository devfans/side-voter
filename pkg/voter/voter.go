/**
 * Copyright (C) 2021 The poly network Authors
 * This file is part of The poly network library.
 *
 * The poly network is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The poly network is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the poly network.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package voter

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/polynetwork/poly/core/types"
	"math/big"
	"math/rand"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/polynetwork/eth-contracts/go_abi/eccm_abi"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	autils "github.com/polynetwork/poly/native/service/utils"
	"github.com/polynetwork/side-voter/config"
	"github.com/polynetwork/side-voter/pkg/db"
	"github.com/polynetwork/side-voter/pkg/log"
)

type Voter struct {
	polySdk      *sdk.PolySdk
	signer       *sdk.Account
	conf         *config.Config
	clients      []*ethclient.Client
	bdb          *db.BoltDB
	contracts    []*eccm_abi.EthCrossChainManager
	contractAddr ethcommon.Address
	idx          int
}

func New(polySdk *sdk.PolySdk, signer *sdk.Account, conf *config.Config) *Voter {
	return &Voter{polySdk: polySdk, signer: signer, conf: conf}
}

func (v *Voter) Init() (err error) {
	var clients []*ethclient.Client
	for _, node := range v.conf.SideConfig.RestURL {
		client, err := ethclient.Dial(node)
		if err != nil {
			log.Fatalf("ethclient.Dial failed:%v", err)
		}

		clients = append(clients, client)
	}
	v.clients = clients

	bdb, err := db.NewBoltDB(v.conf.BoltDbPath)
	if err != nil {
		return
	}

	v.bdb = bdb

	v.contractAddr = ethcommon.HexToAddress(v.conf.SideConfig.ECCMContractAddress)
	v.contracts = make([]*eccm_abi.EthCrossChainManager, len(clients))
	for i := 0; i < len(v.clients); i++ {
		contract, err := eccm_abi.NewEthCrossChainManager(v.contractAddr, v.clients[i])
		if err != nil {
			return err
		}
		v.contracts[i] = contract
	}

	return
}

func (v *Voter) StartReplenish(ctx context.Context) {
	nextPolyHeight := v.conf.ForceConfig.PolyHeight
	ticker := time.NewTicker(time.Second * 1)
	for {
		select {
		case <-ticker.C:
			h, err := v.polySdk.GetCurrentBlockHeight()
			if err != nil {
				log.Errorf("v.polySdk.GetCurrentBlockHeight failed:%v", err)
				continue
			}
			height := uint64(h)
			log.Infof("current poly height:%d", height)
			if height < nextPolyHeight {
				continue
			}

			for nextPolyHeight <= height {
				select {
				case <-ctx.Done():
					return
				default:
				}
				log.Infof("handling poly height:%d", nextPolyHeight)
				events, err := v.polySdk.GetSmartContractEventByBlock(uint32(nextPolyHeight))
				if err != nil {
					log.Errorf("poly failed to fetch smart contract events for height %d, err %v", height, err)
					continue
				}
				txHashList := make([]interface{}, 0)
				for _, event := range events {
					for _, notify := range event.Notify {
						if notify.ContractAddress != autils.ReplenishContractAddress.ToHexString() {
							continue
						}
						states, ok := notify.States.([]interface{})
						if !ok || states[0].(string) != "ReplenishTx" {
							continue
						}

						chainId := states[2].(float64)
						if uint64(chainId) == v.conf.SideConfig.SideChainId {
							txHashes := states[1].([]interface{})
							txHashList = append(txHashList, txHashes...)
						}
					}
				}

				for _, txHash := range txHashList {
					err = v.fetchLockDepositEventByTxHash(txHash.(string))
					if err != nil {
						log.Errorf("fetchLockDepositEventByTxHash failed:%v", err)
						continue
					}
				}
				nextPolyHeight++
			}
		}
	}
}

func (v *Voter) StartVoter(ctx context.Context) {
	nextSideHeight := v.bdb.GetSideHeight()
	if v.conf.ForceConfig.SideHeight > 0 {
		nextSideHeight = v.conf.ForceConfig.SideHeight
	}
	ticker := time.NewTicker(time.Second * 2)
	for {
		select {
		case <-ticker.C:
			v.idx = randIdx(len(v.clients))
			height, err := ethGetCurrentHeight(v.conf.SideConfig.RestURL[v.idx])
			if err != nil {
				log.Errorf("ethGetCurrentHeight failed:%v", err)
				continue
			}
			log.Infof("current side height:%d", height)
			if height < nextSideHeight+v.conf.SideConfig.BlocksToWait {
				continue
			}

			for nextSideHeight <= height-v.conf.SideConfig.BlocksToWait {
				select {
				case <-ctx.Done():
					return
				default:
				}
				log.Infof("handling side height:%d", nextSideHeight)
				err = v.fetchLockDepositEvents(nextSideHeight)
				if err != nil {
					log.Errorf("fetchLockDepositEvents failed:%v", err)
					sleep()
					continue
				}
				nextSideHeight++
			}

			err = v.bdb.UpdateSideHeight(nextSideHeight)
			if err != nil {
				log.Errorf("UpdateSideHeight failed:%v", err)
			}

		case <-ctx.Done():
			log.Info("quiting from signal...")
			return
		}
	}
}

type CrossTransfer struct {
	txIndex string
	txId    []byte
	value   []byte
	toChain uint32
	height  uint64
}

func (v *Voter) fetchLockDepositEventByTxHash(txHash string) error {
	client := v.clients[v.idx]
	contract := v.contracts[v.idx]
	hash := ethcommon.HexToHash(txHash)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reciept, err := client.TransactionReceipt(ctx, hash)
	if err != nil {
		return err
	}
	height := reciept.BlockNumber.Uint64()

	for _, l := range reciept.Logs {
		evt, err := contract.ParseCrossChainEvent(*l)
		if err != nil {
			continue
		}
		if l.Address != v.contractAddr {
			log.Errorf("event source contract invalid: %s, expect: %s, txHash: %s", evt.Raw.Address.Hex(), v.contractAddr.Hex(), txHash)
			continue
		}
		param := &common2.MakeTxParam{}
		_ = param.Deserialization(common.NewZeroCopySource([]byte(evt.Rawdata)))
		if !v.conf.IsWhitelistMethod(param.Method) {
			log.Errorf("target contract method invalid %s, txHash: %s", param.Method, txHash)
			continue
		}

		raw, _ := v.polySdk.GetStorage(autils.CrossChainManagerContractAddress.ToHexString(),
			append(append([]byte(common2.DONE_TX), autils.GetUint64Bytes(v.conf.SideConfig.SideChainId)...), param.CrossChainID...))
		if len(raw) != 0 {
			log.Infof("fetchLockDepositEvents - ccid %s (tx_hash: %s) already on poly",
				hex.EncodeToString(param.CrossChainID), evt.Raw.TxHash.Hex())
			continue
		}

		index := big.NewInt(0)
		index.SetBytes(evt.TxId)
		crossTx := &CrossTransfer{
			txIndex: encodeBigInt(index),
			txId:    evt.Raw.TxHash.Bytes(),
			toChain: uint32(evt.ToChainId),
			value:   []byte(evt.Rawdata),
			height:  height,
		}

		txHash, err = v.commitVote(uint32(height), crossTx.value, crossTx.txId)
		if err != nil {
			log.Errorf("commitVote failed:%v", err)
			continue
		}
	}
	return nil
}

func (v *Voter) fetchLockDepositEvents(height uint64) error {
	contract := v.contracts[v.idx]

	opt := &bind.FilterOpts{
		Start:   height,
		End:     &height,
		Context: context.Background(),
	}
	events, err := contract.FilterCrossChainEvent(opt, nil)
	if err != nil {
		return err
	}

	empty := true
	for events.Next() {
		evt := events.Event
		if evt.Raw.Address != v.contractAddr {
			log.Errorf("event source contract invalid: %s, expect: %s, height: %d", evt.Raw.Address.Hex(), v.contractAddr.Hex(), height)
			continue
		}
		param := &common2.MakeTxParam{}
		_ = param.Deserialization(common.NewZeroCopySource([]byte(evt.Rawdata)))
		if !v.conf.IsWhitelistMethod(param.Method) {
			log.Errorf("target contract method invalid %s, height: %d", param.Method, height)
			continue
		}

		empty = false
		raw, _ := v.polySdk.GetStorage(autils.CrossChainManagerContractAddress.ToHexString(),
			append(append([]byte(common2.DONE_TX), autils.GetUint64Bytes(v.conf.SideConfig.SideChainId)...), param.CrossChainID...))
		if len(raw) != 0 {
			log.Infof("fetchLockDepositEvents - ccid %s (tx_hash: %s) already on poly",
				hex.EncodeToString(param.CrossChainID), evt.Raw.TxHash.Hex())
			continue
		}

		index := big.NewInt(0)
		index.SetBytes(evt.TxId)
		crossTx := &CrossTransfer{
			txIndex: encodeBigInt(index),
			txId:    evt.Raw.TxHash.Bytes(),
			toChain: uint32(evt.ToChainId),
			value:   []byte(evt.Rawdata),
			height:  height,
		}

		var txHash string
		txHash, err = v.commitVote(uint32(height), crossTx.value, crossTx.txId)
		if err != nil {
			log.Errorf("commitVote failed:%v", err)
			return err
		}
		err = v.waitTx(txHash)
		if err != nil {
			log.Errorf("waitTx failed:%v", err)
			return err
		}
	}

	log.Infof("side height %d empty: %v", height, empty)

	return nil
}

func (v *Voter) commitVote(height uint32, value []byte, txhash []byte) (string, error) {
	log.Infof("commitVote, height: %d, value: %s, txhash: %s", height, hex.EncodeToString(value), hex.EncodeToString(txhash))
	tx, err := v.polySdk.Native.Ccm.ImportOuterTransfer(
		v.conf.SideConfig.SideChainId,
		value,
		height,
		nil,
		v.signer.Address[:],
		[]byte{},
		v.signer)
	if err != nil {
		return "", err
	} else {
		log.Infof("commitVote - send transaction to poly chain: ( poly_txhash: %s, eth_txhash: %s, height: %d )",
			tx.ToHexString(), ethcommon.BytesToHash(txhash).String(), height)
		return tx.ToHexString(), nil
	}
}

func (v *Voter) waitTx(txHash string) (err error) {
	start := time.Now()
	var tx *types.Transaction
	for {
		tx, err = v.polySdk.GetTransaction(txHash)
		if tx == nil || err != nil {
			if time.Since(start) > time.Minute*5 {
				err = fmt.Errorf("waitTx timeout")
				return
			}
			time.Sleep(time.Second)
			continue
		}
		return
	}
}

func sleep() {
	time.Sleep(time.Second)
}
func randIdx(size int) int {
	return int(rand.Uint32()) % size
}
