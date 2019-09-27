import "mocha";
import chaiAsPromised = require("chai-as-promised");
import { use as chaiUse, expect } from "chai";
import { RpcClient } from "./core/rpc-client";
import { unbondAndWithdrawStake } from "./core/setup";
import {
	generateWalletName,
	newWalletRequest,
	newZeroFeeRpcClient,
	sleep,
	shouldTest,
	FEE_SCHEMA,
	asyncMiddleman,
	newZeroFeeTendermintClient,
} from "./core/utils";
import BigNumber from "bignumber.js";
import { waitTxIdConfirmed, syncWallet } from "./core/rpc";
import { TendermintClient } from "./core/tendermint-client";
chaiUse(chaiAsPromised);

describe("Staking", () => {
	let rpcClient: RpcClient;
	let tendermintClient: TendermintClient;
	if (!shouldTest(FEE_SCHEMA.ZERO_FEE)) {
		return;
	}
	before(async () => {
		await unbondAndWithdrawStake();
		rpcClient = newZeroFeeRpcClient();
		tendermintClient = newZeroFeeTendermintClient();
	});

	it("should support staking, unbonding and withdrawing", async function() {
		this.timeout(90000);

		const defaultWalletRequest = newWalletRequest("Default", "123456");

		const walletName = generateWalletName();
		const walletRequest = newWalletRequest(walletName, "123456");
		await rpcClient.request("wallet_create", [walletRequest]);
		const stakingAddress = await asyncMiddleman(
			rpcClient.request("wallet_createStakingAddress", [walletRequest]),
			"Error when creating staking address",
		);
		const transferAddress = await asyncMiddleman(
			rpcClient.request("wallet_createTransferAddress", [walletRequest]),
			"Error when creating transfer address",
		);
		const viewKey = await asyncMiddleman(
			rpcClient.request("wallet_getViewKey", [walletRequest]),
			"Error when retrieving wallet view key",
		);

		console.info(`[Info] Wallet name: "${walletName}"`);
		console.info(`[Info] Staking Address: "${stakingAddress}"`);
		console.info(`[Info] Transfer Address: "${transferAddress}"`);

		const stakingAmount = "10000";
		console.log(
			`[Log] Transfer ${stakingAmount} base unit from Default wallet to new wallet ${walletName}`,
		);
		let txId = await asyncMiddleman(
			rpcClient.request("wallet_sendToAddress", [
				defaultWalletRequest,
				transferAddress,
				stakingAmount,
				[viewKey],
			]),
			"Error when funding wallet with staking amount",
		);
		console.info(`[Info] Transaction ID: "${txId}"`);

		await asyncMiddleman(
			waitTxIdConfirmed(tendermintClient, txId),
			"Error when retrieving transaction confirmation",
		);

		await asyncMiddleman(
			syncWallet(rpcClient, walletRequest),
			"Error when synchronizing wallet",
		);

		await expect(
			rpcClient.request("wallet_balance", [walletRequest]),
		).to.eventually.deep.eq(
			stakingAmount,
			"Wallet should be funded with staking amount for staking deposit",
		);

		console.log(
			`[Log] Deposit ${stakingAmount} base unit stake to staking address "${stakingAddress}"`,
		);
		const depositStakeTxId = await asyncMiddleman(
			rpcClient.request("staking_depositStake", [
				walletRequest,
				stakingAddress,
				[
					{
						id: txId,
						index: 0,
					},
				],
			]),
			"Deposit stake should work",
		);

		await asyncMiddleman(
			waitTxIdConfirmed(tendermintClient, depositStakeTxId),
			"Error when retrieving deposit stake transaction confirmation",
		);

		const stakingStateAfterDeposit = await asyncMiddleman(
			rpcClient.request("staking_state", [walletRequest, stakingAddress]),
			"Error when query staking state after deposit",
		);
		assertStakingState(
			stakingStateAfterDeposit,
			{
				address: stakingAddress,
				bonded: stakingAmount,
				unbonded: "0",
			},
			"Staking state is incorrect after deposit stake",
		);

		await asyncMiddleman(
			syncWallet(rpcClient, walletRequest),
			"Error when synchronizing wallet",
		);
		await expect(
			rpcClient.request("wallet_balance", [walletRequest]),
		).to.eventually.deep.eq(
			"0",
			"Wallet balance should be deducted after deposit stake",
		);

		const unbondAmount = "5000";
		console.log(
			`[Log] Unbond ${unbondAmount} base unit stake from staking address "${stakingAddress}"`,
		);
		const remainingBondedAmount = new BigNumber(stakingAmount)
			.minus(unbondAmount)
			.toString(10);
		const unbondStakeTxId = await asyncMiddleman(
			rpcClient.request("staking_unbondStake", [
				walletRequest,
				stakingAddress,
				unbondAmount,
			]),
			"Unbond stake should work",
		);
		await asyncMiddleman(
			waitTxIdConfirmed(tendermintClient, unbondStakeTxId),
			"Error when retrieving unbond stake transaction confirmation",
		);

		const stakingStateAfterUnbond = await asyncMiddleman(
			rpcClient.request("staking_state", [walletRequest, stakingAddress]),
			"Error when query staking state after unbond",
		);
		assertStakingState(
			stakingStateAfterUnbond,
			{
				address: stakingAddress,
				bonded: remainingBondedAmount,
				unbonded: unbondAmount,
			},
			"Staking state is incorrect after unbond stake",
		);

		console.log(
			`[Log] Withdraw all unbonded stake from staking address "${stakingAddress}" to address "${transferAddress}"`,
		);
		await expect(
			rpcClient.request("staking_withdrawAllUnbondedStake", [
				walletRequest,
				stakingAddress,
				transferAddress,
				[],
			]),
		).to.eventually.rejectedWith(
			"Tendermint RPC error: verification failed:",
			"Withdraw unbonded stake should fail before unbond from period",
		);

		console.log("[Log] Waiting for unbond period to exceed");
		await sleep(20000);

		const withdrawTxId = await asyncMiddleman(
			rpcClient.request("staking_withdrawAllUnbondedStake", [
				walletRequest,
				stakingAddress,
				transferAddress,
				[],
			]),
			"Withdraw unbonded stake should work"
		);
		await asyncMiddleman(
			waitTxIdConfirmed(tendermintClient, withdrawTxId),
			"Error when retrieving withdraw transaction confirmation",
		);

		await asyncMiddleman(
			syncWallet(rpcClient, walletRequest),
			"Error when synchronizing wallet after withdraw",
		);
		const stakingStateAfterWithdraw = await asyncMiddleman(
			rpcClient.request("staking_state", [walletRequest, stakingAddress]),
			"Error when querying staking state after withdraw",
		);
		assertStakingState(
			stakingStateAfterWithdraw,
			{
				address: stakingAddress,
				bonded: remainingBondedAmount,
				unbonded: "0",
			},
			"Staking state is incorrect after withdraw stake",
		);
		await asyncMiddleman(
			syncWallet(rpcClient, walletRequest),
			"Error when synchronizing wallet",
		);

		return expect(
			rpcClient.request("wallet_balance", [walletRequest]),
		).to.eventually.deep.eq(
			unbondAmount,
			"Wallet balance should be credited after withdraw stake",
		);
	});

	const assertStakingState = (
		actualState: StakingState,
		expectedState: Omit<StakingState, "unbonded_from">,
		errorMessage: string = "Staking state does not match",
	) => {
		Object.keys(expectedState).forEach((prop) => {
			expect(actualState[prop]).to.deep.eq(
				expectedState[prop],
				`${errorMessage}: "${prop}"`,
			);
		});
	};

	type Omit<T, K> = Pick<T, Exclude<keyof T, K>>;

	interface StakingState {
		address?: string;
		bonded?: string;
		nonce?: number;
		unbonded?: string;
		unbonded_from: number;
	}
});
