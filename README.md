# arbitrum-voter

arbitrum voter for polynetwork.

### Build

```shell
git clone https://github.com/polynetwork/arbitrum-voter
cd arbitrum-voter
go build -o arb_voter main.go
```

### Run

Before running, you need feed the configuration file `config.json`.
```
{
    "PolyConfig": {
        "RestURL": "http://seed1.poly.network:20336",
        "WalletFile": "poly.node.dat"
    },
    "BoltDbPath": "db",
    "WhitelistMethods": [
        "add",
        "remove",
        "swap",
        "unlock",
        "addExtension",
        "removeExtension",
        "registerAsset",
        "onCrossTransfer"
    ],
    "ArbConfig": {
        "SideChainId": 19,
        "ECCMContractAddress": "0x7ceA671DABFBa880aF6723bDdd6B9f4caA15C87B",
        "RestURL": [
            "https://rinkeby.arbitrum.io/rpc"
        ]
    }
}
```

Now, you can start voter as follow: 

```shell
./arb_voter -conf config.json 
```

It will generate logs under `./Log` and check relayer status by view log file.