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

package main

import (
	"context"
	"flag"
	"os/signal"
	"syscall"

	"github.com/polynetwork/side-voter/config"
	"github.com/polynetwork/side-voter/pkg/log"
	"github.com/polynetwork/side-voter/pkg/voter"
)

var confFile string
var sideHeight uint64

func init() {
	flag.StringVar(&confFile, "conf", "./config.json", "configuration file path")
	flag.Uint64Var(&sideHeight, "side", 0, "specify side start height")
	flag.Parse()
}

func main() {
	log.InitLog(log.InfoLog, "./Log/", log.Stdout)

	conf, err := config.LoadConfig(confFile)
	if err != nil {
		log.Fatalf("LoadConfig fail:%v", err)
	}
	if sideHeight > 0 {
		conf.ForceConfig.SideHeight = sideHeight
	}

	v := voter.New(conf)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	v.Start(ctx)

}
