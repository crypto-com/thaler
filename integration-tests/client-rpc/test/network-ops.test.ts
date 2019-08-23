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
} from "./core/utils";
import BigNumber from "bignumber.js";
chaiUse(chaiAsPromised);

describe("Staking", () => {
	let client: RpcClient;
	if (!shouldTest(FEE_SCHEMA.ZERO_FEE)) {
		return;
	}
	before(async () => {
		await unbondAndWithdrawStake();
		client = newZeroFeeRpcClient();
	});

	it("should support staking, unbonding and withdrawing", async function() {
		this.timeout(30000);
		const defaultWalletRequest = newWalletRequest("Default", "123456");

		const walletName = generateWalletName();
		const walletRequest = newWalletRequest(walletName, "123456");
		await client.request("wallet_create", [walletRequest]);
		const stakingAddress = await client.request("wallet_createStakingAddress", [
			walletRequest,
		]);
		const transferAddress = await client.request("wallet_createTransferAddress", [
			walletRequest,
		]);
		const viewKey = await client.request("wallet_getViewKey", [walletRequest]);

		console.info(`[Info] Wallet name: "${walletName}"`);
		console.info(`[Info] Staking Address: "${stakingAddress}"`);
		console.info(`[Info] Transfer Address: "${transferAddress}"`);

		const stakingAmount = "10000";
		console.log(
			`[Log] Transfer ${stakingAmount} base unit from Default wallet to new wallet ${walletName}`,
		);
		let txId = await client.request("wallet_sendToAddress", [
			defaultWalletRequest,
			transferAddress,
			stakingAmount,
			[viewKey],
		]);
		console.info(`[Info] Transaction ID: "${txId}"`);
		await sleep(1000);

		await client.request("sync", [walletRequest]);

		await expect(
			client.request("wallet_balance", [walletRequest]),
		).to.eventually.deep.eq(stakingAmount);

		console.log(`[Log] Deposit ${stakingAmount} base unit stake to staking address "${stakingAddress}"`);
		await expect(
			client.request("staking_depositStake", [
				walletRequest,
				stakingAddress,
				[
					{
						id: txId,
						index: 0,
					},
				],
			]),
		).to.eventually.eq(null, "Deposit stake should work");
		await sleep(1000);
		const stakingStateAfterDeposit = await client.request("staking_state", [
			walletRequest,
			stakingAddress,
		]);
		assertStakingState(
			stakingStateAfterDeposit,
			{
				address: stakingAddress,
				bonded: stakingAmount,
				unbonded: "0",
			},
			"Staking state is incorrect after deposit stake",
		);
		await client.request("sync", [walletRequest]);
		await expect(
			client.request("wallet_balance", [walletRequest]),
		).to.eventually.deep.eq(
			"0",
			"Wallet balance should be deducted after deposit stake",
		);

		const unbondAmount = "5000";
		console.log(`[Log] Unbond ${unbondAmount} base unit stake from staking address "${stakingAddress}"`);
		const remainingBondedAmount = new BigNumber(stakingAmount)
			.minus(unbondAmount)
			.toString(10);
		await expect(
			client.request("staking_unbondStake", [
				walletRequest,
				stakingAddress,
				unbondAmount,
			]),
		).to.eventually.eq(null, "Unbond stake should work");
		await sleep(1000);
		const stakingStateAfterUnbond = await client.request("staking_state", [
			walletRequest,
			stakingAddress,
		]);
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
			client.request("staking_withdrawAllUnbondedStake", [
				walletRequest,
				stakingAddress,
				transferAddress,
				[],
			]),
		).to.eventually.rejectedWith(
			"Transaction validation failed",
			"Withdraw unbonded stake should fail before unbond from period",
		);

		console.log("[Log] Waiting for unbond period to exceed");
		await sleep(8000);

		await expect(
			client.request("staking_withdrawAllUnbondedStake", [
				walletRequest,
				stakingAddress,
				transferAddress,
				[],
			]),
		).to.eventually.eq(null, "Withdraw unbonded stake should work");
		await sleep(1000);
		await client.request("sync", [walletRequest]);
		const stakingStateAfterWithdraw = await client.request("staking_state", [
			walletRequest,
			stakingAddress,
		]);
		assertStakingState(
			stakingStateAfterWithdraw,
			{
				address: stakingAddress,
				bonded: remainingBondedAmount,
				unbonded: "0",
			},
			"Staking state is incorrect after withdraw stake",
		);
		await client.request("sync", [walletRequest]);
		return expect(
			client.request("wallet_balance", [walletRequest]),
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
