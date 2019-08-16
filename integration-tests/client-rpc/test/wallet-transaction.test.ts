import "mocha";
import chaiAsPromised = require("chai-as-promised");
import { use as chaiUse, expect } from "chai";
import BigNumber from "bignumber.js";

import { RpcClient } from "./core/rpc-client";
import {
	newWalletRequest,
	generateWalletName,
	WALLET_TRANSFER_ADDRESS_2,
	newZeroFeeRpcClient,
	newWithFeeRpcClient,
	sleep,
	unbondAndWithdrawStake,
} from "./core/setup";
chaiUse(chaiAsPromised);

describe("Wallet transaction", () => {
	let zeroFeeClient: RpcClient;
	let withFeeClient: RpcClient;
	before(async () => {
		await unbondAndWithdrawStake();
		zeroFeeClient = newZeroFeeRpcClient();
		withFeeClient = newWithFeeRpcClient();
	});

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

		const txId = await zeroFeeClient.request("wallet_sendToAddress", [
			senderWalletRequest,
			receiverWalletTransferAddress,
			transferAmount,
			[],
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
			senderWalletTransactionListBeforeSend.length + 2,
			"Sender should have two extra transaction records",
		);
		const senderWalletSecondLastTransaction = getSecondLastElementOfArray(
			senderWalletTransactionListAfterSend,
		);
		const senderWalletLastTransaction = getLastElementOfArray(
			senderWalletTransactionListAfterSend,
		);
		expectTransactionShouldBe(
			senderWalletSecondLastTransaction,
			{
				direction: TransactionDirection.OUTGOING,
				amount: senderWalletBalanceBeforeSend,
			},
			"Sender should have one Outgoing transaction",
		);
		expectTransactionShouldBe(
			senderWalletLastTransaction,
			{
				direction: TransactionDirection.INCOMING,
				amount: new BigNumber(senderWalletBalanceBeforeSend).minus(transferAmount),
			},
			"Sender should have one Incoming transaction",
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

		const receiverWalletLastTransaction = getLastElementOfArray(
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

	it("can transfer funds between two wallets with fee included", async function() {
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

		const txId = await withFeeClient.request("wallet_sendToAddress", [
			senderWalletRequest,
			receiverWalletTransferAddress,
			transferAmount,
			[],
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
			senderWalletTransactionListBeforeSend.length + 2,
			"Sender should have two extra transaction records",
		);
		const senderWalletSecondLastTransaction = getSecondLastElementOfArray(
			senderWalletTransactionListAfterSend,
		);
		const senderWalletLastTransaction = getLastElementOfArray(
			senderWalletTransactionListAfterSend,
		);
		expectTransactionShouldBe(
			senderWalletSecondLastTransaction,
			{
				direction: TransactionDirection.OUTGOING,
				amount: senderWalletBalanceBeforeSend,
			},
			"Sender should have one Outgoing transaction",
		);
		expectTransactionShouldBe(
			senderWalletLastTransaction,
			{
				direction: TransactionDirection.INCOMING,
			},
			"Sender should have one Incoming transaction",
		);
		expect(senderWalletLastTransaction.kind).to.eq("incoming");
		const senderWalletIncomingAmount = senderWalletLastTransaction.amount;
		expect(
			new BigNumber(senderWalletIncomingAmount).isLessThan(
				new BigNumber(senderWalletBalanceBeforeSend).minus(transferAmount),
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
		).to.eq(true, "Sender balance should be deducted by transfer amount and fee");

		const receiverWalletTransactionListAfterReceive = await withFeeClient.request(
			"wallet_transactions",
			[receiverWalletRequest],
		);
		expect(receiverWalletTransactionListAfterReceive.length).to.eq(
			receiverWalletTransactionListBeforeReceive.length + 1,
			"Receiver should have one extra transaction record",
		);

		const receiverWalletLastTransaction = getLastElementOfArray(
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

enum TransactionDirection {
	INCOMING = "incoming",
	OUTGOING = "outgoing",
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
	expect(actual).to.contain.keys([
		"address",
		"amount",
		"height",
		"kind",
		"transaction_id",
		"time",
	]);

	if (typeof expected.address !== "undefined") {
		expect(actual.address).to.deep.eq(
			{
				BasicRedeem: expected.address,
			},
			message,
		);
	}

	expect(actual.kind).to.eq(expected.direction);
	if (typeof expected.amount !== "undefined") {
		expect(actual.amount).to.eq(expected.amount.toString(10), message);
	}

	if (typeof expected.height !== "undefined") {
		expect(actual.height).to.eq(expected.height.toString(), message);
	} else {
		expect(new BigNumber(actual.height).isGreaterThan(0)).to.eq(true, message);
	}
	return true;
};

const getSecondLastElementOfArray = (arr: any[]) => {
	return arr[arr.length - 2];
};

const getLastElementOfArray = (arr: any[]) => {
	return arr[arr.length - 1];
};
