import { RpcClient } from "./rpc-client";
import * as addressState from "../../../address-state.json";

export const WALLET_STAKING_ADDRESS = (<any>addressState).staking;
export const WALLET_TRANSFER_ADDRESS_1 = (<any>addressState).transfer[0];
export const WALLET_TRANSFER_ADDRESS_2 = (<any>addressState).transfer[1];

const clientRpcPort = Number(process.env.CLIENT_RPC_ZERO_FEE_PORT) || 16659;

export const newZeroFeeRpcClient = (): RpcClient => {
	return newRpcClient("localhost", 16659);
};

export const newWithFeeRpcClient = (): RpcClient => {
	return newRpcClient("localhost", 26659);
};

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
