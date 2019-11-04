import { RpcClient } from "./rpc-client";
import * as addressState from "../../../address-state.json";
import { TendermintClient } from "./tendermint-client";

export const WALLET_STAKING_ADDRESS = (<any>addressState).staking;
export const WALLET_TRANSFER_ADDRESS_1 = (<any>addressState).transfer[0];
export const WALLET_TRANSFER_ADDRESS_2 = (<any>addressState).transfer[1];

export const newZeroFeeRpcClient = (): RpcClient => {
	return newRpcClient("localhost", Number(process.env.CLIENT_RPC_ZEROFEE_PORT) || 16659);
};

export const newWithFeeRpcClient = (): RpcClient => {
	return newRpcClient("localhost", Number(process.env.CLIENT_RPC_PORT) || 26659);
};

export const newRpcClient = (
	host: string = "localhost",
	port: number = 26659,
): RpcClient => {
	return new RpcClient(`http://${host}:${port}`);
};

export const newZeroFeeTendermintClient = (): TendermintClient => {
	return newTendermintClient("localhost", Number(process.env.TENDERMINT_ZEROFEE_RPC_PORT) || 16657);
};

export const newWithFeeTendermintClient = (): TendermintClient => {
	return newTendermintClient("localhost", Number(process.env.TENDERMINT_RPC_PORT) || 26657);
};

export const newTendermintClient = (
	host: string = "localhost",
	port: number = 26657,
): TendermintClient => {
	return new TendermintClient(`http://${host}:${port}`);
};

export const sleep = (ms: number = 1000) => {
	return new Promise((resolve) => {
		setTimeout(resolve, ms);
	});
};

export interface WalletRequest {
	name: string;
	passphrase: string;
}

export const generateWalletName = (prefix: string = "NewWallet"): string => {
	return `${prefix}_${Date.now()}`;
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
	return !testOnly || testOnly === feeSchema;
};

export enum FEE_SCHEMA {
	ZERO_FEE = "ZERO_FEE",
	WITH_FEE = "WITH_FEE",
}

export const asyncMiddleman = async (
	promise: Promise<any>,
	errorMessage: String,
): Promise<any> => {
	try {
		return await promise;
	} catch (err) {
		throw Error(`${errorMessage}: ${err.message}`);
	}
};
