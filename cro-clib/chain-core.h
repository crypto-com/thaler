#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * The app version returned in Tendermint "Info" response,
 * included in every header + transaction metadata.
 * It denotes both binary schema and semantics (state machine rules)
 * ref: https://github.com/tendermint/tendermint/blob/master/docs/architecture/adr-016-protocol-versions.md#appversion
 * TODO: upgrades/new version signalling
 *
 * version 0 -- 0.4.0 release
 * version 1 -- 0.5.0 release (wire format didn't change, but unbond tx semantics changed: https://github.com/crypto-com/chain/pull/1516)
 */
#define APP_VERSION 1

/**
 * version 2 -- 0.6.0 (not yet released --> transaction data bootstrapping, new TX types, genesis changes, TXID calculation change, app hash calculation change);
 */
#define APP_VERSION 2

/**
 * Size in bytes of a 256-bit hash
 */
#define HASH_SIZE_256 32

/**
 * maximum total supply with a fixed decimal point
 * ref: https://etherscan.io/token/0xa0b73e1ff0b80914ab6fe0444e65848c4c34450b
 * 100 billion + 8 decimals
 */
#define MAX_COIN 10000000000000000000ULL

/**
 * 8 decimals => div/mod 1_0000_0000
 */
#define MAX_COIN_DECIMALS 100000000

/**
 * 100 billion
 */
#define MAX_COIN_UNITS 100000000000

/**
 * Keccak-256 crypto hash length in bytes
 */
#define KECCAK256_BYTES 32

/**
 * Fixed bytes number to represent `RedeemAddress` (Eth-style)
 */
#define REDEEM_ADDRESS_BYTES 20

/**
 * Timeout (in seconds) for MLS handshake commit
 */
#define MLS_COMMIT_TIMEOUT_SECS 60

/**
 * Timeout (in seconds) for MLS handshake message NACK
 */
#define MLS_MESSAGE_NACK_TIMEOUT_SECS MLS_COMMIT_TIMEOUT_SECS

/**
 * Time (in seconds) after which, the keypackage for a node will be considered as expired
 */
#define KEYPACKAGE_EXPIRATION_SECS (uint64_t)DEFAULT_EXPIRATION_SECS

/**
 * Time (in seconds) after which, the keypackage for a node is allowed to update, keypackage_update_secs < keypackage_expiration_secs
 */
#define KEYPACKAGE_UPDATE_SECS (KEYPACKAGE_EXPIRATION_SECS / 3)

/**
 * ed25519 public key size
 */
#define PUBLIC_KEY_SIZE 32

/**
 * Maximum (Tendermint-outer payload) transaction size
 */
#define TX_AUX_SIZE (1024 * 60)

/**
 * network type
 */
typedef enum Network {
  /**
   * main network
   */
  Mainnet,
  /**
   * public testnet
   */
  Testnet,
  /**
   * local testing / regnet
   */
  Devnet,
} Network;

/**
 * Returns the chosen network type
 *
 * # Safety
 * chosen_network is pre-initialized and initialized only once
 */
Network get_network(void);
