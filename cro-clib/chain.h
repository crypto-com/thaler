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

typedef CroAddress *CroAddressPtr;

typedef CroHDWallet *CroHDWalletPtr;

/**
 * create staking address
 * # Safety
 */
CroResult cro_basic_create_staking_address(CroAddressPtr *address_out);

/**
 * create staking address
 * # Safety
 */
CroResult cro_basic_create_transfer_address(CroAddressPtr *address_out);

/**
 * create viewkey, which is for encrypted tx
 * # Safety
 */
CroResult cro_basic_create_viewkey(CroAddressPtr *address_out);

/**
 * restore staking address
 * 32 bytes
 * # Safety
 */
CroResult cro_basic_restore_staking_address(CroAddressPtr *address_out, const uint8_t *input);

/**
 * restore transfer address
 * 32 bytes
 * # Safety
 */
CroResult cro_basic_restore_transfer_address(CroAddressPtr *address_out, const uint8_t *input);

/**
 * restore viewkey
 * 32 bytes
 * # Safety
 */
CroResult cro_basic_restore_viewkey(CroAddressPtr *address_out, const uint8_t *input);

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
 * export privatekey as raw bytes
 * 32 bytes
 * # Safety
 */
CroResult cro_export_private(CroAddressPtr address_ptr, uint8_t *dst);

/**
 * extract address as raw bytes
 * minimum 32 length is necessary
 * # Safety
 */
CroResult cro_extract_raw_address(CroAddressPtr address_ptr,
                                  uint8_t *address_output,
                                  uint32_t *address_output_length);

/**
 * get address as string
 * minimum byte length 100 is necessary
 * # Safety
 */
CroResult cro_get_printed_address(CroAddressPtr address_ptr,
                                  uint8_t *address_output,
                                  uint32_t address_output_length);

/**
 * # Safety
 */
CroResult cro_restore_hdwallet(const char *mnemonics_string, CroHDWalletPtr *wallet_out);
