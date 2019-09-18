import "mocha";
import chaiAsPromised = require("chai-as-promised");
import { use as chaiUse, expect } from "chai";
import BigNumber from "bignumber.js";

import { RpcClient } from "./core/rpc-client";
import {
	WALLET_TRANSFER_ADDRESS_2,
	unbondAndWithdrawStake,
} from "./core/setup";
import {
	newWalletRequest,
	generateWalletName,
	newZeroFeeRpcClient,
	newWithFeeRpcClient,
	sleep,
	shouldTest,
	FEE_SCHEMA,
} from "./core/utils";
chaiUse(chaiAsPromised);

describe("Wallet transaction", () => {
	let zeroFeeClient: RpcClient;
	let withFeeClient: RpcClient;
	before(async () => {
		await unbondAndWithdrawStake();
		zeroFeeClient = newZeroFeeRpcClient();
		withFeeClient = newWithFeeRpcClient();
	});

	describe("Zero Fee", () => {
		if (!shouldTest(FEE_SCHEMA.ZERO_FEE)) {
			return;
		}
		it("cannot send funds larger than wallet balance", async () => {
			const walletRequest = newWalletRequest("Default", "123456");

			const totalCROSupply = "10000000000000000000";
			return expect(
				zeroFeeClient.request("wallet_sendToAddress", [
					walletRequest,
					WALLET_TRANSFER_ADDRESS_2,
					totalCROSupply,
					[],
				]),
			).to.eventually.rejectedWith("Insufficient balance");
		});

		it("can transfer funds between two wallets", async () => {
			const receiverWalletName = generateWalletName("Receive");
			const senderWalletRequest = newWalletRequest("Default", "123456");
			const receiverWalletRequest = newWalletRequest(receiverWalletName, "123456");
			const transferAmount = "1000";

			await zeroFeeClient.request("wallet_create", [receiverWalletRequest]);

			const senderWalletTransactionListBeforeSend = await zeroFeeClient.request(
				"wallet_transactions",
				[senderWalletRequest],
			);
			const senderWalletBalanceBeforeSend = await zeroFeeClient.request(
				"wallet_balance",
				[senderWalletRequest],
			);

			const receiverWalletTransferAddress = await zeroFeeClient.request(
				"wallet_createTransferAddress",
				[receiverWalletRequest],
			);
			const receiverWalletTransactionListBeforeReceive = await zeroFeeClient.request(
				"wallet_transactions",
				[receiverWalletRequest],
			);
			const receiverWalletBalanceBeforeReceive = await zeroFeeClient.request(
				"wallet_balance",
				[receiverWalletRequest],
			);
			const receiverViewKey = await zeroFeeClient.request(
				"wallet_getViewKey",
				[receiverWalletRequest]
			);

			const txId = await zeroFeeClient.request("wallet_sendToAddress", [
				senderWalletRequest,
				receiverWalletTransferAddress,
				transferAmount,
				[receiverViewKey],
			]);
			expect(txId.length).to.eq(
				64,
				"wallet_sendToAddress should return transaction id",
			);

			await sleep(2000);

			await zeroFeeClient.request("sync", [senderWalletRequest]);
			await zeroFeeClient.request("sync", [receiverWalletRequest]);

			const senderWalletTransactionListAfterSend = await zeroFeeClient.request(
				"wallet_transactions",
				[senderWalletRequest],
			);

			expect(senderWalletTransactionListAfterSend.length).to.eq(
				senderWalletTransactionListBeforeSend.length + 1,
				"Sender should have one extra transaction record",
			);
			const senderWalletLastTransaction = getFirstElementOfArray(
				senderWalletTransactionListAfterSend,
			);

			expectTransactionShouldBe(
				senderWalletLastTransaction,
				{
					direction: TransactionDirection.OUTGOING,
					amount: new BigNumber(transferAmount),
				},
				"Sender should have one Outgoing transaction",
			);

			const senderWalletBalanceAfterSend = await zeroFeeClient.request(
				"wallet_balance",
				[senderWalletRequest],
			);
			expect(senderWalletBalanceAfterSend).to.eq(
				new BigNumber(senderWalletBalanceBeforeSend)
					.minus(transferAmount)
					.toString(10),
				"Sender balance should be deducted by transfer amount",
			);

			const receiverWalletTransactionListAfterReceive = await zeroFeeClient.request(
				"wallet_transactions",
				[receiverWalletRequest],
			);
			expect(receiverWalletTransactionListAfterReceive.length).to.eq(
				receiverWalletTransactionListBeforeReceive.length + 1,
				"Receiver should have one extra transaction record",
			);

			const receiverWalletLastTransaction = getFirstElementOfArray(
				receiverWalletTransactionListAfterReceive,
			);
			expectTransactionShouldBe(
				receiverWalletLastTransaction,
				{
					direction: TransactionDirection.INCOMING,
					amount: new BigNumber(transferAmount),
				},
				"Receiver should have one Incoming transaction of the received amount",
			);

			const receiverWalletBalanceAfterReceive = await zeroFeeClient.request(
				"wallet_balance",
				[receiverWalletRequest],
			);
			expect(receiverWalletBalanceAfterReceive).to.eq(
				new BigNumber(receiverWalletBalanceBeforeReceive)
					.plus(transferAmount)
					.toString(10),
				"Receiver balance should be increased by transfer amount",
			);
		});
	});

	describe("With Fee", () => {
		if (!shouldTest(FEE_SCHEMA.WITH_FEE)) {
			return;
		}
		it("can transfer funds between two wallets with fee included", async function () {
			const receiverWalletName = generateWalletName("Receive");
			const senderWalletRequest = newWalletRequest("Default", "123456");
			const receiverWalletRequest = newWalletRequest(receiverWalletName, "123456");
			const transferAmount = "1000";

			await withFeeClient.request("wallet_create", [receiverWalletRequest]);

			const senderWalletTransactionListBeforeSend = await withFeeClient.request(
				"wallet_transactions",
				[senderWalletRequest],
			);
			const senderWalletBalanceBeforeSend = await withFeeClient.request(
				"wallet_balance",
				[senderWalletRequest],
			);

			const receiverWalletTransferAddress = await withFeeClient.request(
				"wallet_createTransferAddress",
				[receiverWalletRequest],
			);
			const receiverWalletTransactionListBeforeReceive = await withFeeClient.request(
				"wallet_transactions",
				[receiverWalletRequest],
			);
			const receiverWalletBalanceBeforeReceive = await withFeeClient.request(
				"wallet_balance",
				[receiverWalletRequest],
			);
			const receiverViewKey = await withFeeClient.request(
				"wallet_getViewKey",
				[receiverWalletRequest]
			);

			const txId = await withFeeClient.request("wallet_sendToAddress", [
				senderWalletRequest,
				receiverWalletTransferAddress,
				transferAmount,
				[receiverViewKey],
			]);
			expect(txId.length).to.eq(
				64,
				"wallet_sendToAddress should return transaction id",
			);

			await sleep(2000);

			await withFeeClient.request("sync", [senderWalletRequest]);
			await withFeeClient.request("sync", [receiverWalletRequest]);

			const senderWalletTransactionListAfterSend = await withFeeClient.request(
				"wallet_transactions",
				[senderWalletRequest],
			);
			expect(senderWalletTransactionListAfterSend.length).to.eq(
				senderWalletTransactionListBeforeSend.length + 1,
				"Sender should have one extra transaction record1",
			);
			const senderWalletLastTransaction = getFirstElementOfArray(
				senderWalletTransactionListAfterSend,
			);
			expectTransactionShouldBe(
				senderWalletLastTransaction,
				{
					direction: TransactionDirection.OUTGOING,
					amount: new BigNumber(transferAmount),
				},
				"Sender should have one Outgoing transaction",
			);
			expect(senderWalletLastTransaction.kind).to.eq(
				TransactionDirection.OUTGOING,
			);
			expect(
				new BigNumber(0).isLessThan(
					new BigNumber(senderWalletLastTransaction.fee),
				),
			).to.eq(true, "Sender should pay for transfer fee");

			const senderWalletBalanceAfterSend = await withFeeClient.request(
				"wallet_balance",
				[senderWalletRequest],
			);
			expect(
				new BigNumber(senderWalletBalanceAfterSend).isLessThan(
					new BigNumber(senderWalletBalanceBeforeSend).minus(transferAmount),
				),
			).to.eq(
				true,
				"Sender balance should be deducted by transfer amount and fee",
			);

			const receiverWalletTransactionListAfterReceive = await withFeeClient.request(
				"wallet_transactions",
				[receiverWalletRequest],
			);
			expect(receiverWalletTransactionListAfterReceive.length).to.eq(
				receiverWalletTransactionListBeforeReceive.length + 1,
				"Receiver should have one extra transaction record",
			);

			const receiverWalletLastTransaction = getFirstElementOfArray(
				receiverWalletTransactionListAfterReceive,
			);
			expectTransactionShouldBe(
				receiverWalletLastTransaction,
				{
					direction: TransactionDirection.INCOMING,
					amount: new BigNumber(transferAmount),
				},
				"Receiver should have one Incoming transaction of the exact received amount",
			);

			const receiverWalletBalanceAfterReceive = await withFeeClient.request(
				"wallet_balance",
				[receiverWalletRequest],
			);
			expect(receiverWalletBalanceAfterReceive).to.eq(
				new BigNumber(receiverWalletBalanceBeforeReceive)
					.plus(transferAmount)
					.toString(10),
				"Receiver balance should be increased by the exact transfer amount",
			);
		});
	});
});

enum TransactionDirection {
	INCOMING = "Incoming",
	OUTGOING = "Outgoing",
}
interface TransactionAssertion {
	address?: string;
	direction: TransactionDirection;
	amount?: BigNumber;
	height?: number;
}

const expectTransactionShouldBe = (
	actual: any,
	expected: TransactionAssertion,
	message?: string,
): boolean => {
	expect(actual).to.contain.keys(["kind"]);

	expect(actual.kind).to.eq(expected.direction);

	if (expected.direction === TransactionDirection.INCOMING) {
		expect(actual).to.contain.keys([
			"value",
			"inputs",
			"outputs",
			"block_height",
			"kind",
			"transaction_id",
			"transaction_type",
			"block_time",
		]);
	} else {
		expect(actual).to.contain.keys([
			"value",
			"fee",
			"inputs",
			"outputs",
			"block_height",
			"kind",
			"transaction_id",
			"transaction_type",
			"block_time",
		]);
	}

	expect(actual.kind).to.eq(expected.direction);
	if (typeof expected.amount !== "undefined") {
		expect(actual.value).to.eq(expected.amount.toString(10), message);
	}

	if (typeof expected.height !== "undefined") {
		expect(actual.block_height).to.eq(expected.height.toString(), message);
	} else {
		expect(new BigNumber(actual.block_height).isGreaterThan(0)).to.eq(
			true,
			message,
		);
	}
	return true;
};

const getFirstElementOfArray = (arr: any[]) => {
	return arr[0];
};
