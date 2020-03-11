//
//  Use this file to import your target's public headers that you would like to expose to Swift.
//

#include "chain-core.h"
#include "chain.h"
void restore_wallet(const char* tendermint_url, const char* storage,  const char* name, const char* passphrase, const char* enckey, const char* mnemonics);
void sync_wallet(const char* tendermint_url, const char* storage,  const char* name, const char* passphrase, const char* enckey, const char* mnemonics);
float get_rate();
void stop_sync();
