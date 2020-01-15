#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "chain.h"

int main() {
    ApiContext context=initialize("testnet-thaler-crypto-com-chain-42","ws://localhost:26657/websocket", ".storage");
    ApiResult ret;
    printf("chain id= %s\n", context.chain_id.buf);
    ret=get_network_id();
    printf("network id= %s\n", ret.value.buf);
    HDWallet hd;
    create_hdwallet("a", "1", &hd);
    print_buf("seed", & hd.seed);
    print_buf("viewkey", & hd.viewkey);
    print_buf("enckey", &hd.enckey);
    printf("mnemonic= %s\n", (char*)&hd.mnemonics);
    ret=make_hdwallet_transfer_address(&hd);
    printf("utxo address= %s\n", (char*)&ret.value );
    ret=make_hdwallet_staking_address(&hd);
    printf("staking address= %s\n", (char*)&ret.value );
    return 0;
}
