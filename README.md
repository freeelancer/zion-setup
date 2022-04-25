# Description

Register and sync genesis headers for sidechains on Zion

Fork of https://github.com/siovanus/zion-setup on commit d4da4a7dc23997a4fb4bc3cdcb69d9a0d0d43a59

## Setup

Add config.json. Refer to sample below

```json
{
  "ZionJsonRpcURL": "http://101.32.99.70:22001",
  "NodeKeyList": ["", "", "", "", "", "", ""],
  "ChainName": "eth",

  "ETHConfig": {
    "ChainId": 2,
    "Router": 2,
    "Eccd": "0xc88Bea03045806b7A4659A292dadee75313FA518",
    "Eccm": "0x5CDF186BA96b70180999A79D7d2Ede1F9535E805",
    "ETHJsonRpcURL": "https://ropsten.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161",
    "ETHPrivateKey": ""
  }
}
``` 
> **_NOTE:_**  Do not use the same account that you used to deploy the contracts for the EVM sidechain

## Run

### Build
```bash
go build
```
### Register Side Chain
```bash
./zion-setup -cmd=register_side_chain -conf=config.json
```

### Sync Genesis Header
```bash
./zion-setup -cmd=sync_genesis_header -conf=config.json
```

