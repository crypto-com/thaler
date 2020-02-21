
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
void transfer(CroAddressPtr staking)
{
    const char* tendermint_url="ws://localhost:26657/websocket";
    CroTxPtr tx = NULL;
    cro_create_tx(&tx,0xab);
    // compose tx
    cro_tx_add_txin(tx, "1483dadcae2e6e44bc3248623c7dce749f08270dc9967c6a3ba57f1ce4416b29", 0, "dcro14yj2fc3u3ssvlsfdrr6fu0qmvjx97d405jw9jnwe50ge4y6v53hqr20xzd",
                    1000);
    cro_tx_add_txout(tx, "dcro194f967ckya03l4pnyrxtushzmlv26lm48c3fjz0tyzf9dwdcfpsqfnpmrt", 600);
    cro_tx_add_txout(tx, "dcro14yj2fc3u3ssvlsfdrr6fu0qmvjx97d405jw9jnwe50ge4y6v53hqr20xzd", 200);
    cro_tx_add_viewkey(tx, "03fe7108a0c6f1dfae943d0193f56d6a5957cd391458d74016b8383c472c6c70d0");
    cro_tx_add_viewkey(tx, "022fd255454c6f30a26cf2fb431fd92a2279f6c0e7ec013a63fc847c98de4382d3");
    // signing    
    cro_tx_sign_txin(staking, tx, 0);
    char signed_tx[1000];
    unsigned int tx_length = 1000;
    cro_tx_complete_signing(tx, signed_tx, &tx_length);
    char enc[1000];
    uint32_t enc_length=sizeof(enc);    
    cro_encrypt(tendermint_url, signed_tx, tx_length, enc, &enc_length);    
    cro_destroy_tx(tx);
}
void unbond(CroAddressPtr staking, uint64_t coin)
{
    const char* tendermint_url="ws://localhost:26657/websocket";
    CroStakedState state;
    cro_get_staked_state(staking, tendermint_url, &state);
    uint64_t nonce= state.nonce;
    char tmp[1000];
    uint32_t tmp_length=sizeof(tmp);
    cro_unbond(0xab, nonce, staking, "0x1ad06eef15492a9a1ed0cfac21a1303198db8840", coin, tmp, &tmp_length);
    cro_broadcast(tendermint_url, tmp, tmp_length);
    
}
void withdraw(CroAddressPtr staking, CroAddressPtr transfer)
{
    const char* tendermint_url="ws://localhost:26657/websocket";
    const char* viewkeys[1]={"03fe7108a0c6f1dfae943d0193f56d6a5957cd391458d74016b8383c472c6c70d0"};
      char tx[1000];
    uint32_t tx_length=sizeof(tx);
    char to_addr[100];
    cro_get_printed_address(transfer, to_addr, 100);
    cro_withdraw(tendermint_url,0xab, staking, to_addr, viewkeys, 1,  tx, &tx_length);
    char enc[1000];
    uint32_t enc_length=sizeof(tx);
    cro_encrypt(tendermint_url, tx, tx_length, enc, &enc_length);
    cro_broadcast(tendermint_url, enc, enc_length);
}
void transfer_amount(CroAddressPtr from, CroAddressPtr to, uint64_t coin, CroAddressPtr viewkey)
{
    const char* tendermint_url="ws://localhost:26657/websocket";
    char from_addr[100];
    char to_addr[100];
    char to_viewkey[100];
    cro_get_printed_address(from, from_addr, 100);
    cro_get_printed_address(to, to_addr, 100);
    cro_get_printed_address(viewkey, to_viewkey, 100);
    const char* txid="22e52c076403b4ed8e7029456c10ac021c70eb9e59435dd590bcc70e63dba96e";
    const char* sender="dcro1xwjryuh85xejtc20qkwtesk0yjhfrwxjmwy6mmxjn0aevjhrw7dszselj5";
    const char* receiver="dcro14yj2fc3u3ssvlsfdrr6fu0qmvjx97d405jw9jnwe50ge4y6v53hqr20xzd";
    const char* receiver_viewkey="022fd255454c6f30a26cf2fb431fd92a2279f6c0e7ec013a63fc847c98de4382d3";
    const char* sender_viewkey="03fe7108a0c6f1dfae943d0193f56d6a5957cd391458d74016b8383c472c6c70d0";  
    uint16_t tx_index=0;
    uint64_t total=100000000;
    uint64_t send=5000;
    uint64_t remain= total -send;
     CroTxPtr tx = NULL;
    cro_create_tx(&tx,0xab);
    // compose tx
    cro_tx_add_txin(tx, txid, tx_index, sender,
                    total);
    cro_tx_add_txout(tx, receiver, send);
    cro_tx_add_txout(tx, sender, remain);    
    cro_tx_add_viewkey(tx, sender_viewkey);
    cro_tx_add_viewkey(tx, receiver_viewkey);
    // signing    
    cro_tx_sign_txin(from, tx, 0);
    
    char signed_tx[1000];
    unsigned int tx_length = 1000;
    cro_tx_complete_signing(tx, signed_tx, &tx_length);
    char enc[1000];
    uint32_t enc_length=sizeof(enc);
    cro_encrypt(tendermint_url, signed_tx, tx_length, enc, &enc_length);
    cro_broadcast(tendermint_url, enc, enc_length);
    cro_destroy_tx(tx);
}

// from: transfer
void deposit(CroAddressPtr from, CroAddressPtr to)
{
    const char* tendermint_url="ws://localhost:26657/websocket";
    char addr_from[100];
    char addr_to[100];
    cro_get_printed_address(from, addr_from, 100);
    cro_get_printed_address(to, addr_to, 100);
    const char* txid="aeec0007c75c9b6648e830d3859ed096d98913b234506e7a60bd14f38b5d3697";
    const char* sender="dcro1xwjryuh85xejtc20qkwtesk0yjhfrwxjmwy6mmxjn0aevjhrw7dszselj5";
    uint16_t tx_index=0;
    uint64_t total=  450000000 ;        
    CroDepositTxPtr tx = NULL;
    cro_create_tx_deposit(&tx,0xab, addr_to);    
    cro_tx_add_txin_deposit(tx, txid, tx_index, sender,total);        
    cro_tx_sign_txin_deposit(from, tx, 0);
    
    char signed_tx[1000];
    unsigned int tx_length = 1000;
    cro_tx_complete_signing_deposit(tx, signed_tx, &tx_length);
    char enc[1000];
    uint32_t enc_length=sizeof(enc);
    cro_encrypt(tendermint_url, signed_tx, tx_length, enc, &enc_length);
    cro_broadcast(tendermint_url, enc, enc_length);
    cro_destroy_tx_deposit(tx);
}

int test_wallet()
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

int test_trasactions()
{
    const char *mnemonics = "annual dinosaur deliver hour loop food buddy lift alert obvious thank scorpion young amused climb defy erode blur drip gun require clerk beef armed";
    const char *mnemonics_b = "input defy basket shift elephant control sting original make like clutch enhance only cross chunk ride flock digital end document stage kite cave use";

    CroHDWalletPtr hdwallet = NULL;
    CroAddressPtr staking = NULL;
    CroAddressPtr staking2 = NULL;
    CroAddressPtr transfer = NULL;
    CroAddressPtr transfer2 = NULL;
    CroAddressPtr viewkey = NULL;
    CroAddressPtr viewkey2 = NULL;

    CroHDWalletPtr hdwallet_b = NULL;
    CroAddressPtr staking_b = NULL;
    CroAddressPtr staking2_b = NULL;
    CroAddressPtr transfer_b = NULL;
    CroAddressPtr transfer2_b = NULL;
    CroAddressPtr viewkey_b = NULL;
    CroAddressPtr viewkey2_b = NULL;

    cro_restore_hdwallet(mnemonics, &hdwallet);
    cro_create_staking_address(hdwallet, Devnet, &staking, 0);
    cro_create_staking_address(hdwallet, Devnet, &staking2, 1);
    cro_create_transfer_address(hdwallet, Devnet, &transfer, 0);
    cro_create_transfer_address(hdwallet, Devnet, &transfer2, 1);
    cro_create_viewkey(hdwallet, Devnet, &viewkey, 0);
    cro_create_viewkey(hdwallet, Devnet, &viewkey2, 1);

    cro_restore_hdwallet(mnemonics_b, &hdwallet_b);
    cro_create_staking_address(hdwallet_b, Devnet, &staking_b, 0);
    cro_create_staking_address(hdwallet_b, Devnet, &staking2_b, 1);
    cro_create_transfer_address(hdwallet_b, Devnet, &transfer_b, 0);
    cro_create_transfer_address(hdwallet_b, Devnet, &transfer2_b, 1);
    cro_create_viewkey(hdwallet_b, Devnet, &viewkey_b, 0);
    cro_create_viewkey(hdwallet_b, Devnet, &viewkey2_b, 1);

    printf("wallet a\n");
    print_address(staking);
    print_address(staking2);
    print_address(transfer);
    print_address(transfer2);
    print_address(viewkey);
    print_address(viewkey2);
    printf("wallet b\n");
    print_address(staking_b);
    print_address(staking2_b);
    print_address(transfer_b);
    print_address(transfer2_b);
    print_address(viewkey_b);
    print_address(viewkey2_b);
    //unbond(staking, 150000000);
    //withdraw(staking,transfer);
    //transfer_amount(transfer, transfer2_b, 1000, viewkey_b);
    //deposit(transfer,staking);

    // good to encrypt now
    cro_destroy_address(staking);
    cro_destroy_address(staking2);
    cro_destroy_address(transfer);
    cro_destroy_address(transfer2);
    cro_destroy_address(viewkey);
    cro_destroy_address(viewkey2);
    cro_destroy_hdwallet(hdwallet);

    cro_destroy_address(staking_b);
    cro_destroy_address(staking2_b);
    cro_destroy_address(transfer_b);
    cro_destroy_address(transfer2_b);
    cro_destroy_address(viewkey_b);
    cro_destroy_address(viewkey2_b);
    cro_destroy_hdwallet(hdwallet_b);
    return 0;
}


int test_tx()
{
    test_trasactions();
    test_wallet();
}