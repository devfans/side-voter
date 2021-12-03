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
	"math/big"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/KSlashh/poly-abi/abi_1.9.25/ccm"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	common2 "github.com/ethereum/go-ethereum/contracts/native/cross_chain_manager/common"
	"github.com/ethereum/go-ethereum/contracts/native/go_abi/cross_chain_manager_abi"
	"github.com/ethereum/go-ethereum/contracts/native/utils"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/polynetwork/side-voter/config"
	"github.com/polynetwork/side-voter/pkg/db"
	"github.com/polynetwork/side-voter/pkg/log"
)

type Voter struct {
	signers      []*ZionSigner
	conf         *config.Config
	clients      []*ethclient.Client
	zionClients  []*ethclient.Client
	bdb          *db.BoltDB
	contracts    []*ccm.EthCrossChainManagerImplemetation
	contractAddr common.Address
	idx          int
	zidx         int
	chainID      *big.Int
}

func New(conf *config.Config) *Voter {
	return &Voter{conf: conf}
}

func (v *Voter) init() error {
	if v.conf.SideConfig.BlocksToWait > SIDE_USEFUL_BLOCK_NUM {
		SIDE_USEFUL_BLOCK_NUM = v.conf.SideConfig.BlocksToWait
	}

	var clients []*ethclient.Client
	for _, node := range v.conf.SideConfig.RestURL {
		client, err := ethclient.Dial(node)
		if err != nil {
			log.Fatalf("side ethclient.Dial failed:%v", err)
		}

		clients = append(clients, client)
	}
	v.clients = clients

	var zionClients []*ethclient.Client
	for _, node := range v.conf.ZionConfig.RestURL {
		client, err := ethclient.Dial(node)
		if err != nil {
			log.Fatalf("zion ethclient.Dial failed:%v", err)
		}

		zionClients = append(zionClients, client)
	}
	v.zionClients = zionClients

	start := time.Now()
	chainID, err := zionClients[0].ChainID(context.Background())
	if err != nil {
		log.Fatalf("zionClients[0].ChainID failed:%v", err)
	}
	v.chainID = chainID
	log.Infof("ChainID() took %v", time.Now().Sub(start).String())

	signerArr := make([]*ZionSigner, 0)
	for _, nodeKey := range v.conf.ZionConfig.NodeKeyList {
		signer, err := NewZionSigner(nodeKey)
		if err != nil {
			panic(err)
		}
		signerArr = append(signerArr, signer)
	}
	v.signers = signerArr

	// check
	path := v.conf.BoltDbPath
	if _, err := os.Stat(path); err != nil {
		log.Infof("db path not exists: %s, make dir", path)
		err := os.MkdirAll(path, 0711)
		if err != nil {
			return err
		}
	}
	bdb, err := db.NewBoltDB(v.conf.BoltDbPath)
	if err != nil {
		return err
	}

	v.bdb = bdb

	v.contractAddr = common.HexToAddress(v.conf.SideConfig.ECCMContractAddress)
	v.contracts = make([]*ccm.EthCrossChainManagerImplemetation, len(clients))
	for i := 0; i < len(v.clients); i++ {
		contract, err := ccm.NewEthCrossChainManagerImplemetation(v.contractAddr, v.clients[i])
		if err != nil {
			return err
		}
		v.contracts[i] = contract
	}

	return nil
}

var SIDE_USEFUL_BLOCK_NUM = uint64(1)

func (v *Voter) Start(ctx context.Context) {
	err := v.init()
	if err != nil {
		log.Fatalf("Voter.init failed: %v", err)
	}

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
				log.Warnf("ethGetCurrentHeight failed:%v", err)
				continue
			}
			log.Infof("current height:%d", height)
			if height < nextSideHeight+SIDE_USEFUL_BLOCK_NUM {
				continue
			}

			for nextSideHeight < height-SIDE_USEFUL_BLOCK_NUM {
				select {
				case <-ctx.Done():
					return
				default:
				}
				log.Infof("handling side height:%d", nextSideHeight)
				err = v.fetchLockDepositEvents(nextSideHeight)
				if err != nil {
					log.Warnf("fetchLockDepositEvents failed:%v", err)
					sleep()
					continue
				}
				nextSideHeight++
			}

			err = v.bdb.UpdateSideHeight(nextSideHeight)
			if err != nil {
				log.Warnf("UpdateArbHeight failed:%v", err)
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

func (v *Voter) fetchLockDepositEvents(height uint64) error {
	contract := v.contracts[v.idx]
	v.zidx = randIdx(len(v.zionClients))

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
			log.Warnf("event source contract invalid: %s, expect: %s, height: %d", evt.Raw.Address.Hex(), v.contractAddr.Hex(), height)
			continue
		}
		param := &common2.MakeTxParam{}
		param, err = common2.DecodeTxParam(evt.Rawdata)
		if err != nil {
			return fmt.Errorf("MakeTxParam decode error: %s", err)
		}
		if !v.conf.IsWhitelistMethod(param.Method) {
			log.Warnf("target contract method invalid %s, height: %d", param.Method, height)
			continue
		}

		empty = false
		index := big.NewInt(0)
		index.SetBytes(evt.TxId)
		crossTx := &CrossTransfer{
			txIndex: encodeBigInt(index),
			txId:    evt.Raw.TxHash.Bytes(),
			toChain: uint32(evt.ToChainId),
			value:   []byte(evt.Rawdata),
			height:  height,
		}

		txs, err := v.commitVote(uint32(height), crossTx.value, crossTx.txId)
		if err != nil {
			return fmt.Errorf("commitVote failed:%v", err)
		}
		err = v.waitTxs(txs)
		if err != nil {
			return fmt.Errorf("waitTxs failed:%v", err)
		}
	}
	log.Infof("side height %d empty: %v", height, empty)
	return nil
}

func (v *Voter) commitVote(height uint32, value []byte, txhash []byte) ([]string, error) {
	log.Infof("commitVote, height: %d, value: %s, txhash: %s", height, hex.EncodeToString(value), hex.EncodeToString(txhash))

	duration := time.Second * 30
	timerCtx, cancelFunc := context.WithTimeout(context.Background(), duration)
	defer cancelFunc()
	client := v.zionClients[v.zidx]
	gasPrice, err := client.SuggestGasPrice(timerCtx)
	if err != nil {
		return nil, fmt.Errorf("commitVote, SuggestGasPrice failed:%v", err)
	}
	ccmAbi, err := abi.JSON(strings.NewReader(cross_chain_manager_abi.CrossChainManagerABI))
	if err != nil {
		return nil, fmt.Errorf("commitVote, abi.JSON error:" + err.Error())
	}
	txData, err := ccmAbi.Pack("importOuterTransfer", v.conf.SideConfig.SideChainId, height, []byte{}, []byte{}, value, []byte{})
	if err != nil {
		panic(fmt.Errorf("commitVote, scmAbi.Pack error:" + err.Error()))
	}
	var txs []string
	for _, signer := range v.signers {
		callMsg := ethereum.CallMsg{
			From: signer.Address, To: &utils.CrossChainManagerContractAddress, Gas: 0, GasPrice: gasPrice,
			Value: big.NewInt(0), Data: txData,
		}
		gasLimit, err := client.EstimateGas(timerCtx, callMsg)
		if err != nil {
			log.Errorf("commitVote, client.EstimateGas failed:%v", err)
			continue
		}

		nonce := v.getNonce(signer.Address)
		tx := types.NewTx(&types.LegacyTx{Nonce: nonce, GasPrice: gasPrice, Gas: gasLimit, To: &utils.CrossChainManagerContractAddress, Value: big.NewInt(0), Data: txData})
		s := types.LatestSignerForChainID(v.chainID)
		signedtx, err := types.SignTx(tx, s, signer.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("commitVote, SignTransaction failed:%v", err)
		}
		err = client.SendTransaction(timerCtx, signedtx)
		if err != nil {
			return nil, fmt.Errorf("commitVote, SendTransaction failed:%v", err)
		}
		h := signedtx.Hash()
		log.Infof("commitVote - send transaction to zion chain: ( zion_txhash: %s, side_txhash: %s, height: %d )",
			h.Hex(), common.BytesToHash(txhash).String(), height)
		txs = append(txs, h.Hex())
	}
	return txs, nil
}

func (v *Voter) waitTxs(txs []string) error {
	start := time.Now()
	for _, txHash := range txs {
		for {
			duration := time.Second * 30
			timerCtx, cancelFunc := context.WithTimeout(context.Background(), duration)
			receipt, err := v.zionClients[v.zidx].TransactionReceipt(timerCtx, common.HexToHash(txHash))
			cancelFunc()
			if receipt == nil || err != nil {
				if time.Since(start) > time.Minute*5 {
					err = fmt.Errorf("waitTx timeout")
					return err
				}
				time.Sleep(time.Second)
				continue
			}
			break
		}
	}
	return nil
}

func (v *Voter) getNonce(addr common.Address) uint64 {
	for {
		nonce, err := v.zionClients[v.zidx].NonceAt(context.Background(), addr, nil)
		if err != nil {
			log.Errorf("NonceAt failed:%v", err)
			sleep()
			continue
		}
		return nonce
	}
}

func sleep() {
	time.Sleep(time.Second)
}
func randIdx(size int) int {
	return int(rand.Uint32()) % size
}
