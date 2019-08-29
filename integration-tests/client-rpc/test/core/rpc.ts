import { RpcClient } from "./rpc-client";
import { WalletRequest, sleep } from "./utils";

export const syncWallet = async (
	rpcClient: RpcClient,
	walletRequest: WalletRequest,
): Promise<void> => {
	console.log(`[Log] Synchronizaing wallet "${walletRequest.name}"`);
	await rpcClient.request("sync", [walletRequest]);
	await sleep(1000);
};
