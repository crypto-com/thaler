#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define APP_VERSION 0

#define HASH_SIZE_256 32

#define KECCAK256_BYTES 32

#define MAX_COIN 10000000000000000000

#define MAX_COIN_DECIMALS 100000000

#define MAX_COIN_UNITS 100000000000

#define PUBLIC_KEY_SIZE 32

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
