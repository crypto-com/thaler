import "mocha";
import chaiAsPromised = require("chai-as-promised");
import { use as chaiUse, expect } from "chai";
import { RpcClient } from "./core/rpc-client";
import { unbondAndWithdrawStake } from "./core/setup";
import {
	generateWalletName,
	newWalletRequest,
	newCreateWalletRequest,
	rawWalletRequest,
	newZeroFeeRpcClient,
	sleep,
	shouldTest,
	FEE_SCHEMA,
	asyncMiddleman,
	newZeroFeeTendermintClient,
	WalletRequest,
	DEFAULT_PASSPHRASE,
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

	it("unbond of same amount and nonce from different account should have different txid", async function () {
		this.timeout(300000);

		const stakingAmount = "10000";
		const unbondAmount = "5000";

		const firstWalletContext = await prepareWalletContext(
			tendermintClient,
			rpcClient,
		);
		console.info("[Info] First Wallet:");
		console.info(`[Info] Wallet name: "${firstWalletContext.walletName}"`);
		console.info(
			`[Info] Staking Address: "${firstWalletContext.stakingAddress}"`,
		);
		console.info(
			`[Info] Transfer Address: "${firstWalletContext.transferAddress}"`,
		);
		const firstDepositStakeTxId = await testTransferAndStakeAmountBaseUnit(
			firstWalletContext,
			stakingAmount,
		);
		await assertStakeDeposited(
			firstWalletContext,
			stakingAmount,
			firstDepositStakeTxId,
		);
		const firstUnbondTxId = await testUnbondBaseUnit(
			firstWalletContext,
			unbondAmount,
		);

		const secondWalletContext = await prepareWalletContext(
			tendermintClient,
			rpcClient,
		);
		console.info("[Info] Second Wallet:");
		console.info(`[Info] Wallet name: "${secondWalletContext.walletName}"`);
		console.info(
			`[Info] Staking Address: "${secondWalletContext.stakingAddress}"`,
		);
		console.info(
			`[Info] Transfer Address: "${secondWalletContext.transferAddress}"`,
		);
		const secondDepositStakeTxId = await testTransferAndStakeBaseUnit(
			secondWalletContext,
			stakingAmount,
		);
		await assertStakeDeposited(
			secondWalletContext,
			stakingAmount,
			secondDepositStakeTxId,
		);
		const secondUnbondTxId = await testUnbondBaseUnit(
			secondWalletContext,
			unbondAmount,
		);

		expect(firstUnbondTxId).not.to.eq(
			secondUnbondTxId,
			"First unbond txid should be different from second unbond transaction",
		);
	});

	it("should support staking, unbonding and withdrawing", async function () {
		this.timeout(300000);

		const walletContext = await prepareWalletContext(tendermintClient, rpcClient);
		const { walletName, stakingAddress, transferAddress } = walletContext;

		console.info(`[Info] Wallet name: "${walletName}"`);
		console.info(`[Info] Staking Address: "${stakingAddress}"`);
		console.info(`[Info] Transfer Address: "${transferAddress}"`);

		const stakingAmount = "10000";
		const unbondAmount = "5000";
		const depositStakeTxId = await testTransferAndStakeBaseUnit(
			walletContext,
			stakingAmount,
		);
		await assertStakeDeposited(walletContext, stakingAmount, depositStakeTxId);

		const unbondTxId = await testUnbondBaseUnit(walletContext, unbondAmount);
		await assertUnbonded(walletContext, stakingAmount, unbondAmount, unbondTxId);

		const withdrawTxId = await testWithdrawAllUnbondedStake(walletContext);
		await assertWithdrewAllStake(
			walletContext,
			stakingAmount,
			unbondAmount,
			withdrawTxId,
		);
	});

	const prepareWalletContext = async (
		tendermintClient: TendermintClient,
		rpcClient: RpcClient,
	): Promise<WalletContext> => {
		const defaultWalletRequest = await newWalletRequest(rpcClient, "Default", DEFAULT_PASSPHRASE);

		const walletName = generateWalletName();
		const walletCreateRequest = newCreateWalletRequest(walletName, DEFAULT_PASSPHRASE);
		const walletCreateResponse = await rpcClient.request("wallet_create", [walletCreateRequest, "Basic"]);
		const walletRequest = rawWalletRequest(walletName, walletCreateResponse[0])
		const stakingAddress = await asyncMiddleman(
			rpcClient.request("wallet_createStakingAddress", [walletRequest]),
			"Error when creating staking address",
		);
		const transferAddress = await asyncMiddleman(
			rpcClient.request("wallet_createTransferAddress", [walletRequest]),
			"Error when creating transfer address",
		);
		const viewKey = await asyncMiddleman(
			rpcClient.request("wallet_getViewKey", [walletRequest, false]),
			"Error when retrieving wallet view key",
		);

		return {
			walletName,
			stakingAddress,
			transferAddress,
			viewKey,
			defaultWalletRequest,
			walletRequest,
			tendermintClient,
			rpcClient,
		};
	};

	const testTransferAndStakeAmountBaseUnit = async (
		walletContext: WalletContext,
		stakingAmount: string,
	): Promise<string> => {
		const {
			walletName,
			stakingAddress,
			transferAddress,
			viewKey,
			defaultWalletRequest,
			walletRequest,
			tendermintClient,
			rpcClient,
		} = walletContext;

		console.log(
			`[Log] Transfer ${stakingAmount} base unit from Default wallet to new wallet ${walletName}`,
		);
		await asyncMiddleman(
			syncWallet(rpcClient, defaultWalletRequest),
			"Error when synchronizing default wallet",
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
			"Error when waiting transfer transaction confirmation",
		);

		await asyncMiddleman(
			syncWallet(rpcClient, walletRequest),
			"Error when synchronizing wallet",
		);

		// after sync
		const expectedWalletBalanceAfterSync = {
			total: stakingAmount,
			pending: "0",
			available: stakingAmount,
		}
		await expect(
			rpcClient.request("wallet_balance", [walletRequest]),
		).to.eventually.deep.eq(
			expectedWalletBalanceAfterSync,
			"Wallet should be funded with staking amount for staking deposit",
		);

		console.log(
			`[Log] Deposit ${stakingAmount} base unit stake to staking address "${stakingAddress}"`,
		);
		const depositStakeTxId = await asyncMiddleman(
			rpcClient.request("staking_depositAmountStake", [
				walletRequest,
				stakingAddress,
				stakingAmount,
			]),
			"Deposit stake should work",
		);

		return depositStakeTxId;
	};

	const testTransferAndStakeBaseUnit = async (
		walletContext: WalletContext,
		stakingAmount: string,
	): Promise<string> => {
		const {
			walletName,
			stakingAddress,
			transferAddress,
			viewKey,
			defaultWalletRequest,
			walletRequest,
			tendermintClient,
			rpcClient,
		} = walletContext;

		console.log(
			`[Log] Transfer ${stakingAmount} base unit from Default wallet to new wallet ${walletName}`,
		);
		await asyncMiddleman(
			syncWallet(rpcClient, defaultWalletRequest),
			"Error when synchronizing default wallet",
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
			"Error when waiting transfer transaction confirmation",
		);

		await asyncMiddleman(
			syncWallet(rpcClient, walletRequest),
			"Error when synchronizing wallet",
		);

		// after sync
		const expectedWalletBalanceAfterSync = {
			total: stakingAmount,
			pending: "0",
			available: stakingAmount,
		}
		await expect(
			rpcClient.request("wallet_balance", [walletRequest]),
		).to.eventually.deep.eq(
			expectedWalletBalanceAfterSync,
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

		return depositStakeTxId;
	};

	const assertStakeDeposited = async (
		walletContext: WalletContext,
		stakingAmount: string,
		depositStakeTxId: string,
	) => {
		const { stakingAddress, walletRequest } = walletContext;

		await asyncMiddleman(
			waitTxIdConfirmed(tendermintClient, depositStakeTxId),
			"Error when waiting deposit stake transaction confirmation",
		);
		await asyncMiddleman(
			syncWallet(rpcClient, walletRequest),
			"Error when synchronizing wallet",
		);

		const expectedState: ExpectedStakingState = {
			address: stakingAddress,
			bonded: stakingAmount,
			unbonded: "0",
		};

		await waitStakingState(walletRequest, stakingAddress, expectedState);
		const stakingStateAfterDeposit = await asyncMiddleman(
			rpcClient.request("staking_state", [walletRequest.name, stakingAddress]),
			"Error when query staking state after deposit",
		);
		assertStakingState(
			stakingStateAfterDeposit,
			expectedState,
			"Staking state is incorrect after deposit stake",
		);

		const expectedBalance = {
			total: "0",
			pending: "0",
			available: "0",
		};
		await expect(
			rpcClient.request("wallet_balance", [walletRequest]),
		).to.eventually.deep.eq(
			expectedBalance,
			"Wallet balance should be deducted after deposit stake",
		);
	};

	const testUnbondBaseUnit = async (
		walletContext: WalletContext,
		unbondAmount: string,
	): Promise<string> => {
		const { stakingAddress, walletRequest, rpcClient } = walletContext;

		console.log(
			`[Log] Unbond ${unbondAmount} base unit stake from staking address "${stakingAddress}"`,
		);
		const unbondStakeTxId = await asyncMiddleman(
			rpcClient.request("staking_unbondStake", [
				walletRequest,
				stakingAddress,
				unbondAmount,
			]),
			"Unbond stake should work",
		);

		return unbondStakeTxId;
	};

	const assertUnbonded = async (
		walletContext: WalletContext,
		stakingAmount: string,
		unbondAmount: string,
		unbondTxId: string,
	) => {
		const {
			stakingAddress,
			walletRequest,
			tendermintClient,
			rpcClient,
		} = walletContext;

		const remainingBondedAmount = new BigNumber(stakingAmount)
			.minus(unbondAmount)
			.toString(10);

		await asyncMiddleman(
			waitTxIdConfirmed(tendermintClient, unbondTxId),
			"Error when waiting unbond stake transaction confirmation",
		);
		await asyncMiddleman(
			syncWallet(rpcClient, walletRequest),
			"Error when synchronizing default wallet",
		);

		const expectedState: ExpectedStakingState = {
			address: stakingAddress,
			bonded: remainingBondedAmount,
			unbonded: unbondAmount,
		};
		await waitStakingState(walletRequest, stakingAddress, expectedState);
		const stakingStateAfterUnbond = await asyncMiddleman(
			rpcClient.request("staking_state", [walletRequest.name, stakingAddress]),
			"Error when query staking state after unbond",
		);
		assertStakingState(
			stakingStateAfterUnbond,
			expectedState,
			"Staking state is incorrect after unbond stake",
		);
	};

	const testWithdrawAllUnbondedStake = async (
		walletContext: WalletContext,
	): Promise<string> => {
		const {
			stakingAddress,
			transferAddress,
			walletRequest,
			rpcClient,
		} = walletContext;

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
			"Validation error: Staking state is not yet unbonded",
			"Withdraw unbonded stake should fail before unbond from period",
		);

		console.log("[Log] Waiting for unbond period to exceed");
		await sleep(20000);

		await asyncMiddleman(
			syncWallet(rpcClient, walletRequest),
			"Error when synchronizing wallet after withdraw",
		);

		const withdrawTxId = await asyncMiddleman(
			rpcClient.request("staking_withdrawAllUnbondedStake", [
				walletRequest,
				stakingAddress,
				transferAddress,
				[],
			]),
			"Withdraw unbonded stake should work",
		);

		return withdrawTxId;
	};

	const assertWithdrewAllStake = async (
		walletContext: WalletContext,
		stakingAmount: string,
		unbondAmount: string,
		withdrawTxId: string,
	) => {
		const {
			stakingAddress,
			walletRequest,
			tendermintClient,
			rpcClient,
		} = walletContext;

		const remainingBondedAmount = new BigNumber(stakingAmount)
			.minus(unbondAmount)
			.toString(10);

		await asyncMiddleman(
			waitTxIdConfirmed(tendermintClient, withdrawTxId),
			"Error when waiting withdraw transaction confirmation",
		);
		await asyncMiddleman(
			syncWallet(rpcClient, walletRequest),
			"Error when synchronizing wallet after withdraw",
		);

		const expectedState: ExpectedStakingState = {
			address: stakingAddress,
			bonded: remainingBondedAmount,
			unbonded: "0",
		};
		await waitStakingState(walletRequest, stakingAddress, expectedState);
		const stakingStateAfterWithdraw = await asyncMiddleman(
			rpcClient.request("staking_state", [walletRequest.name, stakingAddress]),
			"Error when querying staking state after withdraw",
		);
		assertStakingState(
			stakingStateAfterWithdraw,
			expectedState,
			"Staking state is incorrect after withdraw stake",
		);
		await asyncMiddleman(
			syncWallet(rpcClient, walletRequest),
			"Error when synchronizing wallet",
		);

		const expectedBalance = {
			total: unbondAmount,
			pending: "0",
			available: unbondAmount,
		};
		return expect(
			rpcClient.request("wallet_balance", [walletRequest]),
		).to.eventually.deep.eq(
			expectedBalance,
			"Wallet balance should be credited after withdraw stake",
		);
	};

	interface WalletContext {
		walletName: string;
		stakingAddress: string;
		transferAddress: string;
		viewKey: string;
		defaultWalletRequest: WalletRequest;
		walletRequest: WalletRequest;
		tendermintClient: TendermintClient;
		rpcClient: RpcClient;
	}

	const waitStakingState = async (
		walletRequest: WalletRequest,
		stakingAddress: string,
		expectedState: ExpectedStakingState,
	) => {
		while (true) {
			await sleep(2000);
			console.log(`[Log] Checking latest staking state`);
			await asyncMiddleman(
				syncWallet(rpcClient, walletRequest),
				"Error when synchronizing default wallet",
			);
			const stakingState = await asyncMiddleman(
				rpcClient.request("staking_state", [walletRequest.name, stakingAddress]),
				"Error when query staking state",
			);

			if (isStakingStateMatch(stakingState, expectedState)) {
				break;
			}
		}
	};

	const isStakingStateMatch = (
		actualState: StakingState,
		expectedState: ExpectedStakingState,
	) => {
		for (let prop of Object.keys(expectedState)) {
			if (actualState[prop] !== expectedState[prop]) {
				return false;
			}
		}
		return true;
	};

	const assertStakingState = (
		actualState: StakingState,
		expectedState: ExpectedStakingState,
		errorMessage: string = "Staking state does not match",
	) => {
		Object.keys(expectedState).forEach((prop) => {
			expect(actualState[prop]).to.deep.eq(
				expectedState[prop],
				`${errorMessage}: "${prop}"`,
			);
		});
	};

	type ExpectedStakingState = Omit<StakingState, "unbonded_from">;
	type Omit<T, K> = Pick<T, Exclude<keyof T, K>>;

	interface StakingState {
		address?: string;
		bonded?: string;
		nonce?: number;
		unbonded?: string;
		unbonded_from: number;
	}
});
