import BigNumber from "bignumber.js";
import { RpcClient } from "./rpc-client";
import * as addressState from "../../../address-state.json";

export const WALLET_STAKING_ADDRESS = (<any>addressState).staking;
export const WALLET_TRANSFER_ADDRESS_1 = (<any>addressState).transfer[0];
export const WALLET_TRANSFER_ADDRESS_2 = (<any>addressState).transfer[1];

const clientRpcPort = Number(process.env.CLIENT_RPC_ZERO_FEE_PORT) || 16659;

export const newZeroFeeRpcClient = (): RpcClient => {
	return newRpcClient("localhost", 16659);
}

export const newWithFeeRpcClient = (): RpcClient => {
	return newRpcClient("localhost", 26659);
}

export const newRpcClient = (
	host: string = "localhost",
	port: number = clientRpcPort,
): RpcClient => {
	return new RpcClient(`http://${host}:${port}`);
};

export const sleep = (ms: number = 1000) => {
	return new Promise((resolve) => {
		setTimeout(resolve, ms);
	});
};

interface WalletRequest {
	name: string;
	passphrase: string;
}

export const generateWalletName = (prefix: string = "NewWallet"): string => {
	return `${prefix} ${Date.now()}`;
};

export const newWalletRequest = (
	name: string,
	passphrase: string,
): WalletRequest => {
	return {
		name,
		passphrase,
	};
};

export const shouldTest = (feeSchema: FEE_SCHEMA) => {
	const testOnly = process.env.TEST_ONLY;
	return (!testOnly || testOnly === feeSchema);
}

export enum FEE_SCHEMA {
	ZERO_FEE = "ZERO_FEE",
	WITH_FEE = "WITH_FEE",
}

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

	await client.request("sync", [walletRequest]);
	const walletBalance = await client.request("wallet_balance", [walletRequest]);
	if (new BigNumber(walletBalance).isGreaterThan("0")) {
		console.info("[Init] Bonded funds already withdrew");
		console.info(`[Info] Wallet balance: ${walletBalance}`);
		return;
	}
	console.info("[Init] Withdrawing bonded funds");

	await client.request("staking_withdrawAllUnbondedStake", [
		walletRequest,
		WALLET_STAKING_ADDRESS,
		WALLET_TRANSFER_ADDRESS_1,
		[],
	]);

	await client.request("sync", [walletRequest]);
};

if (!shouldTest(FEE_SCHEMA.ZERO_FEE)) {
	console.info("[Test] Skipping Zero Fee Tests");
}
if (!shouldTest(FEE_SCHEMA.WITH_FEE)) {
	console.info("[Test] Skipping With Fee Tests");
}
