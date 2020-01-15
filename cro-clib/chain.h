/*
chain c bindings
*/

#define MAX_LENGTH 1024
#define MAX_STRING_LENGTH 512
/* general byte buffer */
typedef struct {
    unsigned char buf[MAX_STRING_LENGTH];
    int length;
} Buf;

/* general api result */
typedef struct {
    int error;
    Buf value;
} ApiResult;

/* hdwallet info */
typedef struct {
    int error;
    Buf name;
    Buf value;
    Buf mnemonics;
    Buf viewkey;
    Buf seed;
    Buf enckey;
} HDWallet;

/* initialize state */
typedef struct {
    int error;
    Buf chain_id;
    Buf server_url;
    Buf storage_folder;
} ApiContext;

extern ApiContext initialize(const char* chain_id, const char* server, const char* storage);
extern ApiResult get_network_id();
extern HDWallet create_hdwallet(const char* name, const char* passphrase); /* hd wallet */
extern HDWallet restore_hdwallet(const char* passpharase); 
extern ApiResult make_hdwallet_staking_address(HDWallet* wallet);
extern ApiResult make_hdwallet_transfer_address(HDWallet* wallet);
extern void print_buf(const char* name,Buf* buf); /* for debugging */