import BigNumber from "bignumber.js";
import { RpcClient } from "./rpc-client";
import * as addressState from "../../../address-state.json";
import { syncWallet, waitTxIdConfirmed } from "./rpc";
import {
	shouldTest,
	FEE_SCHEMA,
	newWalletRequest,
	newZeroFeeRpcClient,
	newWithFeeRpcClient,
	asyncMiddleman,
	newZeroFeeTendermintClient,
	newWithFeeTendermintClient,
} from "./utils";
import { TendermintClient } from "./tendermint-client";

export const WALLET_STAKING_ADDRESS = (<any>addressState).staking;
export const WALLET_TRANSFER_ADDRESS_1 = (<any>addressState).transfer[0];
export const WALLET_TRANSFER_ADDRESS_2 = (<any>addressState).transfer[1];

export const unbondAndWithdrawStake = async () => {
	if (shouldTest(FEE_SCHEMA.ZERO_FEE)) {
		const zeroFeeRpcClient = newZeroFeeRpcClient();
		const zeroFeeTendermintClient = newZeroFeeTendermintClient();
		await unbondAndWithdrawStakeFromClient(
			zeroFeeRpcClient,
			zeroFeeTendermintClient,
		);
	}

	if (shouldTest(FEE_SCHEMA.WITH_FEE)) {
		const withFeeRpcClient = newWithFeeRpcClient();
		const withFeeTendermintClient = newWithFeeTendermintClient();
		await unbondAndWithdrawStakeFromClient(
			withFeeRpcClient,
			withFeeTendermintClient,
		);
	}
};

const unbondAndWithdrawStakeFromClient = async (
	rpcClient: RpcClient,
	tendermintClient: TendermintClient,
) => {
	const walletRequest = newWalletRequest("Default", "123456");

	await asyncMiddleman(
		syncWallet(rpcClient, walletRequest),
		"Error when synchronizing Default wallet",
	);

	const walletBalance = await asyncMiddleman(
		rpcClient.request("wallet_balance", [walletRequest]),
		"Error when retrieving Default wallet balance",
	);
	console.info(`[Info] Wallet balance: ${walletBalance}`);
	if (new BigNumber(walletBalance.total).isGreaterThan("0")) {
		console.info("[Init] Bonded funds already withdrew");
		return;
	}
	console.log("[Init] Withdrawing bonded funds");

	console.log(
		`[Init] Withdrawing bonded genesis funds from "${WALLET_STAKING_ADDRESS}" to "${WALLET_TRANSFER_ADDRESS_1}"`,
	);
	const withdrawTxId = await asyncMiddleman(
		rpcClient.request("staking_withdrawAllUnbondedStake", [
			walletRequest,
			WALLET_STAKING_ADDRESS,
			WALLET_TRANSFER_ADDRESS_1,
			[],
		]),
		"Error when withdrawing all unbonded stake",
	);
	await asyncMiddleman(
		waitTxIdConfirmed(tendermintClient, withdrawTxId),
		"Error when retrieving transaction confirmation",
	);

	await asyncMiddleman(
		syncWallet(rpcClient, walletRequest),
		"Error when synchronizing Default wallet",
	);
};

if (!shouldTest(FEE_SCHEMA.ZERO_FEE)) {
	console.info("[Test] Skipping Zero Fee Tests");
}
if (!shouldTest(FEE_SCHEMA.WITH_FEE)) {
	console.info("[Test] Skipping With Fee Tests");
}
