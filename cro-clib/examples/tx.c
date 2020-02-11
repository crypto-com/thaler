
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <assert.h>
#include "../chain-core.h"
#include "../chain.h"

void print_address(CroAddressPtr a);
void print_hex(char *tmp, int length)
{
    int i;
    for (i = 0; i < length; i++)
    {
        printf("%X", (unsigned char)tmp[i]);
    }
    printf("\n");
}
int test_tx()
{
    const char *mnemonics = "annual dinosaur deliver hour loop food buddy lift alert obvious thank scorpion young amused climb defy erode blur drip gun require clerk beef armed";

    CroHDWalletPtr hdwallet = NULL;
    CroAddressPtr staking = NULL;
    CroAddressPtr staking2 = NULL;
    CroAddressPtr transfer = NULL;
    CroAddressPtr transfer2 = NULL;
    CroAddressPtr viewkey = NULL;
    CroAddressPtr viewkey2 = NULL;
    CroFeePtr fee = NULL;
    cro_create_fee_algorithm(&fee, "5", "1.0");

    cro_restore_hdwallet(mnemonics, &hdwallet);
    cro_create_staking_address(hdwallet, Devnet, &staking, 0);
    cro_create_staking_address(hdwallet, Devnet, &staking2, 1);
    cro_create_transfer_address(hdwallet, Devnet, &transfer, 0);
    cro_create_transfer_address(hdwallet, Devnet, &transfer2, 1);
    cro_create_viewkey(hdwallet, Devnet, &viewkey, 0);
    cro_create_viewkey(hdwallet, Devnet, &viewkey2, 1);
    print_address(staking);
    print_address(staking2);
    print_address(transfer);
    print_address(transfer2);
    print_address(viewkey);
    print_address(viewkey2);

    CroTxPtr tx = NULL;
    cro_create_tx(&tx, 0xab);
    // compose tx
    cro_tx_add_txin(tx, "1483dadcae2e6e44bc3248623c7dce749f08270dc9967c6a3ba57f1ce4416b29", 0, "dcro14yj2fc3u3ssvlsfdrr6fu0qmvjx97d405jw9jnwe50ge4y6v53hqr20xzd",
                    1000);
    cro_tx_add_txout(tx, "dcro194f967ckya03l4pnyrxtushzmlv26lm48c3fjz0tyzf9dwdcfpsqfnpmrt", 600);
    cro_tx_add_txout(tx, "dcro14yj2fc3u3ssvlsfdrr6fu0qmvjx97d405jw9jnwe50ge4y6v53hqr20xzd", 200);
    cro_tx_add_viewkey(tx, "03fe7108a0c6f1dfae943d0193f56d6a5957cd391458d74016b8383c472c6c70d0");
    cro_tx_add_viewkey(tx, "022fd255454c6f30a26cf2fb431fd92a2279f6c0e7ec013a63fc847c98de4382d3");
    cro_tx_sign_txin(staking, tx, 0);
    char tmp[1000];
    unsigned int max_length = 1000;
    cro_tx_complete_signing(tx, tmp, &max_length);
    print_hex(tmp, max_length);

    char fee_output[100];

    uint64_t fee_coin = cro_estimate_fee(fee, max_length);
    printf("bytes=%d fee=%" PRIu64 "\n", max_length, fee_coin);

    // good to encrypt now
    cro_destroy_address(staking);
    cro_destroy_address(staking2);
    cro_destroy_address(transfer);
    cro_destroy_address(transfer2);
    cro_destroy_address(viewkey);
    cro_destroy_address(viewkey2);
    cro_destroy_hdwallet(hdwallet);
    cro_destroy_fee_algorithm(fee);

    return 0;
}