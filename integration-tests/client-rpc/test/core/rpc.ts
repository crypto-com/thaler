import { RpcClient } from "./rpc-client";
import { WalletRequest, sleep, asyncMiddleman } from "./utils";
import { TendermintClient } from "./tendermint-client";

export const syncWallet = async (
	rpcClient: RpcClient,
	walletRequest: WalletRequest,
): Promise<void> => {
	console.log(`[Log] Synchronizing wallet "${walletRequest.name}"`);
	await rpcClient.request("sync", [walletRequest]);

	await sleep(1000);
};

// Continuously check for TxId existence until found
export const waitTxIdConfirmed = async (
	tendermintClient: TendermintClient,
	txId: string,
	retryTimeout: number = 1000,
): Promise<boolean> => {
	while (true) {
		console.log("[Log] Checking transaction confirmation on chain");
		const exists = await asyncMiddleman(
			tendermintClient.isTxIdExists(txId),
			"Error when retrieving transaction confirmation",
		);
		if (exists) {
			break;
		}
		await sleep(retryTimeout);
	}

	return true;
};
