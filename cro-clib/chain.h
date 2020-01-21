#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define FAIL -1

#define SUCCESS 0

typedef struct CroAddress CroAddress;

typedef struct CroHDWallet CroHDWallet;

typedef struct CroResult {
  int result;
} CroResult;

typedef CroHDWallet *CroHDWalletPtr;

typedef CroAddress *CroAddressPtr;

/**
 * create hd wallet
 * minimum  300 byte-length is necessary
 * # Safety
 */
CroResult cro_create_hdwallet(CroHDWalletPtr *wallet_out,
                              uint8_t *mnemonics,
                              uint32_t mnemonics_length);

/**
 * create staking address from bip44 hdwallet
 * # Safety
 */
CroResult cro_create_staking_address(CroHDWalletPtr wallet_ptr,
                                     Network network,
                                     CroAddressPtr *address_out,
                                     uint32_t index);

/**
 * create utxo address from bip44 wallet, which is for withdrawal, transfer amount
 * # Safety
 */
CroResult cro_create_transfer_address(CroHDWalletPtr wallet_ptr,
                                      Network network,
                                      CroAddressPtr *address_out,
                                      uint32_t index);

/**
 * create viewkey, which is for encrypted tx
 * # Safety
 */
CroResult cro_create_viewkey(CroHDWalletPtr wallet_ptr,
                             Network network,
                             CroAddressPtr *address_out,
                             uint32_t index);

/**
 * destroy address
 * # Safety
 */
CroResult cro_destroy_address(CroAddressPtr addr);

/**
 * destroy bip44 hdwallet
 * # Safety
 */
CroResult cro_destroy_hdwallet(CroHDWalletPtr hdwallet);

/**
 * print address information
 * minimum byte length 100 is necessary
 * # Safety
 */
CroResult cro_get_printed_address(CroAddressPtr address_ptr,
                                  uint8_t *address_output,
                                  uint32_t address_output_length);

/**
 * print address information
 * minimum 32 length is necessary
 * # Safety
 */
CroResult cro_get_raw_address(CroAddressPtr address_ptr,
                              uint8_t *address_output,
                              uint32_t *address_output_length);

/**
 * print address information
 * # Safety
 */
CroResult cro_print_address(CroAddressPtr address_ptr);

/**
 * # Safety
 */
CroResult cro_restore_hdwallet(const char *mnemonics_string, CroHDWalletPtr *wallet_out);
