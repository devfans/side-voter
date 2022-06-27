package voter

import (
	"github.com/polynetwork/side-voter/config"
	"testing"
)

func TestGetCurrentHeight(t *testing.T) {
	conf := &config.Config{SideConfig: config.SideConfig{
		L1URL: "https://ethereum-goerli-rpc.allthatnode.com/",
		L1Contract: "0xa0f968eba6bbd08f28dc061c7856c15725983395",
		ECCMContractAddress: "0xa0f968eba6bbd08f28dc061c7856c15725983395",
		BlocksToWait: 17,
	}, BoltDbPath: "bolt_db"}
	v := New(nil, nil, conf)
	err := v.Init()
	if err != nil { t.Fatal(err) }
	h, err := v.getCurrentHeight()
	if err != nil { t.Fatal(err) }
	t.Log(h)
}

