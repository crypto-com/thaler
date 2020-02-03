#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <assert.h>
#include "../chain-core.h"
#include "../chain.h"



void print_address(CroAddressPtr a)
{
    char tmp[300];
    cro_get_printed_address(a, tmp,sizeof(tmp));   
    printf("address= %s\n",tmp);
}

void test_hdwallet_create() {
    CroHDWalletPtr w=NULL;
    char tmp[300];    
    cro_create_hdwallet(&w, tmp, 300);
    printf("mnemonic= %s (%d)\n",tmp,(int) strlen(tmp));
    CroAddressPtr a= NULL;
    cro_create_staking_address(w,Devnet, &a,0);
    print_address(a);   
    cro_destroy_address(a);  
    cro_create_transfer_address(w,Devnet, &a, 0);
    print_address(a);   
    cro_destroy_address(a);
    cro_create_viewkey(w, Devnet,&a,0);  
    print_address(a);   
    cro_destroy_address(a);
    cro_destroy_hdwallet(w);
    w=NULL;
    CroHDWalletPtr q= NULL;
    cro_restore_hdwallet(tmp, &q);
    cro_create_staking_address(q, Devnet,&a,0);
    print_address(a);
    cro_destroy_address(a);
    cro_create_transfer_address(q, Devnet,&a,0);  
    print_address(a);   
    cro_destroy_address(a);
    cro_create_viewkey(q, Devnet,&a,0);  
    print_address(a);   
    cro_destroy_address(a);
    cro_destroy_hdwallet(q);
}
int is_same(const char* src, const char* dst) 
{
    return 0==strncmp(src, dst, strlen(src));
}
int show_hex(const unsigned char* src, int length) {
    int i;
    for (i=0;i<length;i++) {
        unsigned char c= src[i];
        printf("%02X", c);
    }
    printf("\n");
}
void test_hdwallet_mnemonics()
{
    const char* mnemonics= "math original guitar once close news cactus crime cool tank honey file endless neglect catch side cluster clay viable journey october market autumn swing";
    CroHDWalletPtr q= NULL;
    CroAddressPtr a= NULL;
    char tmp[300];
    cro_restore_hdwallet(mnemonics, &q);
    cro_create_staking_address(q, Devnet,&a,0);
    cro_get_printed_address(a, tmp, 300);
    assert(is_same(tmp,"0x2782feb1e457733d83bb738d18b55d91c9b1d7e6"));    
    print_address(a);
    cro_destroy_address(a);
    cro_create_transfer_address(q, Devnet,&a,0);  
    cro_get_printed_address(a, tmp, 300);
    assert(is_same(tmp,"dcro1aj3tv4z40250v9v0aextlsq4pl9qzd7zezd3v6fc392ak00zhtds3d2wyl"));    
    print_address(a);   
    cro_destroy_address(a);
    cro_create_viewkey(q, Devnet,&a,0);  
    cro_get_printed_address(a, tmp, 300);
    assert(is_same(tmp,"02d1a53beae333dfdd18509a1016c6c0047452c1b8018d21e986e23714d15a4fe7"));
    print_address(a);
    print_address(a);   
    cro_destroy_address(a);
    cro_destroy_hdwallet(q);
}


void test_normal_wallet_staking()
{
    CroAddressPtr a= NULL;
    CroAddressPtr b= NULL;
    char addr_a[300];
    char addr_b[300]; 
    cro_basic_create_staking_address(&a);
    print_address(a);
    cro_get_printed_address(a, addr_a, 300);
    char privatekey[32];    
    cro_export_private(a, privatekey);
    cro_basic_restore_staking_address(&b, privatekey);
    print_address(b);
    cro_get_printed_address(a, addr_b, 300);
    assert( is_same(addr_a, addr_b));
    cro_destroy_address(a);   
    cro_destroy_address(b);   
}

void test_normal_wallet_transfer()
{
    CroAddressPtr a= NULL;
    CroAddressPtr b= NULL;
    char addr_a[300];
    char addr_b[300]; 
    cro_basic_create_transfer_address(&a);
    print_address(a);
    cro_get_printed_address(a, addr_a, 300);
    char privatekey[32];
    cro_export_private(a, privatekey);
    cro_basic_restore_transfer_address(&b, privatekey);
    print_address(b);
    cro_get_printed_address(a, addr_b, 300);
    assert( is_same(addr_a, addr_b));
    cro_destroy_address(a);   
    cro_destroy_address(b);   
}
void test_normal_wallet_viewkey()
{
    CroAddressPtr a= NULL;
    CroAddressPtr b= NULL;
    char addr_a[300];
    char addr_b[300]; 
    cro_basic_create_viewkey(&a);
    print_address(a);
    cro_get_printed_address(a, addr_a, 300);
    char privatekey[32];
    cro_export_private(a, privatekey);
    cro_basic_restore_viewkey(&b, privatekey);
    print_address(b);
    cro_get_printed_address(a, addr_b, 300);
    assert( is_same(addr_a, addr_b));
    cro_destroy_address(a);   
    cro_destroy_address(b);   
}

void test_normal_wallet_create() 
{
    test_normal_wallet_staking();
    test_normal_wallet_transfer();
    test_normal_wallet_viewkey();
}

int main() {
    test_hdwallet_create();
    test_hdwallet_mnemonics();  
    test_normal_wallet_create();
    return 0;
}
