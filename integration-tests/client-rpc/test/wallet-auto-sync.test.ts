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

describe("Wallet: Auto-sync", () => {
	let zeroFeeClient: RpcClient;
	before(async () => {
		await unbondAndWithdrawStake();
		zeroFeeClient = newZeroFeeRpcClient();
	});

	if (!shouldTest(FEE_SCHEMA.ZERO_FEE)) {
		return;
	}

	it("Able to auto-sync", async function() {
		this.timeout(1000000);

		const receiverWalletName = generateWalletName("Receive");
		const senderWalletRequest = newWalletRequest("Default", "123456");
		const receiverWalletRequest = newWalletRequest(receiverWalletName, "123456");
		const transferAmount = "1000";

		await zeroFeeClient.request("wallet_create", [receiverWalletRequest]);

		//		await zeroFeeClient.request("sync", [senderWalletRequest]);
		//		await zeroFeeClient.request("sync", [receiverWalletRequest]);

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
		const receiverViewKey = await zeroFeeClient.request("wallet_getViewKey", [
			receiverWalletRequest,
		]);

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

		await sleep(5000);

		await zeroFeeClient.request("sync_unlockWallet", [senderWalletRequest]);
		await zeroFeeClient.request("sync_unlockWallet", [receiverWalletRequest]);
		console.info(
			`[Log] Enabled auto-sync for wallets and "${senderWalletRequest.name}" "${receiverWalletName}"`,
		);

		await sleep(1000);

		while (true) {
			const senderWalletTransactionListAfterSend = await zeroFeeClient.request(
				"wallet_transactions",
				[senderWalletRequest],
			);

			const receiverWalletTransactionListAfterReceive = await zeroFeeClient.request(
				"wallet_transactions",
				[receiverWalletRequest],
			);
			if (
				senderWalletTransactionListAfterSend.length ===
					senderWalletTransactionListBeforeSend.length + 1 &&
				receiverWalletTransactionListAfterReceive.length ===
					receiverWalletTransactionListBeforeReceive.length + 1
			) {
				console.log("Sync comepleted");
				break;
			}
			await sleep(500);
		}

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
