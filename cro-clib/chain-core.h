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
 */
#define APP_VERSION 0

/**
 * Size in bytes of a 256-bit hash
 */
#define HASH_SIZE_256 32

/**
 * Keccak-256 crypto hash length in bytes
 */
#define KECCAK256_BYTES 32

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
 * ed25519 public key size
 */
#define PUBLIC_KEY_SIZE 32

/**
 * Fixed bytes number to represent `RedeemAddress` (Eth-style)
 */
#define REDEEM_ADDRESS_BYTES 20

typedef enum Network {
  Mainnet,
  Testnet,
  Devnet,
} Network;

/**
 * Returns the chosen network type
 */
Network get_network(void);
