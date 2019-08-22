import BigNumber from "bignumber.js";
import { RpcClient } from "./rpc-client";
import * as addressState from "../../../address-state.json";
import { syncWallet } from "./rpc";
import {
	shouldTest,
	FEE_SCHEMA,
	newRpcClient,
	newWalletRequest,
} from "./utils";

export const WALLET_STAKING_ADDRESS = (<any>addressState).staking;
export const WALLET_TRANSFER_ADDRESS_1 = (<any>addressState).transfer[0];
export const WALLET_TRANSFER_ADDRESS_2 = (<any>addressState).transfer[1];

export const unbondAndWithdrawStake = async () => {
	if (shouldTest(FEE_SCHEMA.ZERO_FEE)) {
		const zeroFeeClient: RpcClient = newRpcClient();
		await unbondAndWithdrawStakeFromClient(zeroFeeClient);
	}

	if (shouldTest(FEE_SCHEMA.WITH_FEE)) {
		const withFeeClient: RpcClient = newRpcClient("localhost", 26659);
		await unbondAndWithdrawStakeFromClient(withFeeClient);
	}
};

const unbondAndWithdrawStakeFromClient = async (client: RpcClient) => {
	const walletRequest = newWalletRequest("Default", "123456");

	await syncWallet(client, walletRequest);

	const walletBalance = await client.request("wallet_balance", [walletRequest]);
	console.info(`[Info] Wallet balance: ${walletBalance}`);
	if (new BigNumber(walletBalance).isGreaterThan("0")) {
		console.info("[Init] Bonded funds already withdrew");
		return;
	}
	console.log("[Init] Withdrawing bonded funds");

	console.log(
		`[Init] Withdrawing bonded genesis funds from "${WALLET_STAKING_ADDRESS}" to "${WALLET_TRANSFER_ADDRESS_1}"`,
	);
	await client.request("staking_withdrawAllUnbondedStake", [
		walletRequest,
		WALLET_STAKING_ADDRESS,
		WALLET_TRANSFER_ADDRESS_1,
		[],
	]);

	await syncWallet(client, walletRequest);
};

if (!shouldTest(FEE_SCHEMA.ZERO_FEE)) {
	console.info("[Test] Skipping Zero Fee Tests");
}
if (!shouldTest(FEE_SCHEMA.WITH_FEE)) {
	console.info("[Test] Skipping With Fee Tests");
}
