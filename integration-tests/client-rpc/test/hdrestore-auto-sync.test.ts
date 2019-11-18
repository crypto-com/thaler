import "mocha";
import chaiAsPromised = require("chai-as-promised");
import { use as chaiUse, expect } from "chai";
import BigNumber from "bignumber.js";

import { RpcClient } from "./core/rpc-client";
import { unbondAndWithdrawStake } from "./core/setup";
import {
	newWalletRequest,
	generateWalletName,
	newZeroFeeRpcClient,
	sleep,
	shouldTest,
	FEE_SCHEMA,
	asyncMiddleman,
	newZeroFeeTendermintClient,
} from "./core/utils";
import { syncWallet, waitTxIdConfirmed } from "./core/rpc";
import { TendermintClient } from "./core/tendermint-client";
import {
	getFirstElementOfArray,
	expectTransactionShouldBe,
	TransactionDirection,
} from "./core/transaction-utils";
chaiUse(chaiAsPromised);

describe("Wallet Auto-sync", () => {
	let zeroFeeRpcClient: RpcClient;
	let zeroFeeTendermintClient: TendermintClient;
	before(async () => {
		await unbondAndWithdrawStake();
		zeroFeeRpcClient = newZeroFeeRpcClient();
		zeroFeeTendermintClient = newZeroFeeTendermintClient();
	});

	if (!shouldTest(FEE_SCHEMA.ZERO_FEE)) {
		return;
	}

	it("can auto-sync unlocked wallets", async function() {
		this.timeout(300000);

		const receiverWalletName = generateWalletName("Receive");
		const senderWalletRequest = newWalletRequest("Default", "123456");
		const receiverWalletRequest = newWalletRequest(receiverWalletName, "123456");
		const transferAmount = "1000";

		await asyncMiddleman(
			zeroFeeRpcClient.request("wallet_restore", [receiverWalletRequest, "blind heavy warrior off power high lab trend diagram happy bargain level demise safe image pride napkin example wolf adjust pistol spatial eight audit"]),
			"Error when recovering receiver hdwallet",
		);


		await asyncMiddleman(
			syncWallet(zeroFeeRpcClient, senderWalletRequest),
			"Error when synchronizing sender wallet",
		);
		await asyncMiddleman(
			syncWallet(zeroFeeRpcClient, receiverWalletRequest),
			"Error when synchronizing receiver wallet",
		);

		const senderWalletTransactionListBeforeSend = await asyncMiddleman(
			zeroFeeRpcClient.request("wallet_transactions", [senderWalletRequest]),
			"Error when retrieving sender wallet transactions before send",
		);
		const senderWalletBalanceBeforeSend = await asyncMiddleman(
			zeroFeeRpcClient.request("wallet_balance", [senderWalletRequest]),
			"Error when retrieving sender wallet balance before send",
		);

		const receiverWalletTransferAddress = await asyncMiddleman(
			zeroFeeRpcClient.request("wallet_createTransferAddress", [
				receiverWalletRequest,
			]),
			"Error when creating receiver wallet transfer address",
		);
		const receiverWalletTransactionListBeforeReceive = await asyncMiddleman(
			zeroFeeRpcClient.request("wallet_transactions", [receiverWalletRequest]),
			"Error when retrieving receiver wallet transactions before receive",
		);
		const receiverWalletBalanceBeforeReceive = await asyncMiddleman(
			zeroFeeRpcClient.request("wallet_balance", [receiverWalletRequest]),
			"Error when retrieving receiver wallet balance before receive",
		);
		const receiverViewKey = await asyncMiddleman(
			zeroFeeRpcClient.request("wallet_getViewKey", [receiverWalletRequest]),
			"Error when retrieving receiver view key",
		);

		const txId = await asyncMiddleman(
			zeroFeeRpcClient.request("wallet_sendToAddress", [
				senderWalletRequest,
				receiverWalletTransferAddress,
				transferAmount,
				[receiverViewKey],
			]),
			"Error when sending funds from sender to receiver",
		);
		expect(txId.length).to.eq(
			64,
			"wallet_sendToAddress should return transaction id",
		);

		await asyncMiddleman(
			waitTxIdConfirmed(zeroFeeTendermintClient, txId),
			"Error when waiting transfer transaction confirmation",
		);

		await zeroFeeRpcClient.request("sync_unlockWallet", [senderWalletRequest]);
		await zeroFeeRpcClient.request("sync_unlockWallet", [receiverWalletRequest]);
		console.info(
			`[Log] Enabled auto-sync for wallets "${senderWalletRequest.name}" and "${receiverWalletName}"`,
		);

		await sleep(1000);
		while (true) {
			console.log(`[Log] Checking for wallet sync status`);
			const senderWalletTransactionListAfterSend = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_transactions", [senderWalletRequest]),
				"Error when retrieving sender wallet transactions after send",
			);

			const receiverWalletTransactionListAfterReceive = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_transactions", [receiverWalletRequest]),
				"Error when retrieving receiver wallet transactions after send",
			);

			if (
				senderWalletTransactionListAfterSend.length ===
					senderWalletTransactionListBeforeSend.length + 1 &&
				receiverWalletTransactionListAfterReceive.length ===
					receiverWalletTransactionListBeforeReceive.length + 1
			) {
				console.log(`[Log] Auto-sync caught up with latest transactions`);
				break;
			}
			await sleep(1000);
		}

		const senderWalletTransactionListAfterSend = await asyncMiddleman(
			zeroFeeRpcClient.request("wallet_transactions", [senderWalletRequest]),
			"Error when retrieving sender wallet transactions after send",
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

		const senderWalletBalanceAfterSend = await asyncMiddleman(
			zeroFeeRpcClient.request("wallet_balance", [senderWalletRequest]),
			"Error when retrieving sender wallet balance after send",
		);
		expect(senderWalletBalanceAfterSend).to.eq(
			new BigNumber(senderWalletBalanceBeforeSend)
				.minus(transferAmount)
				.toString(10),
			"Sender balance should be deducted by transfer amount",
		);

		const receiverWalletTransactionListAfterReceive = await asyncMiddleman(
			zeroFeeRpcClient.request("wallet_transactions", [receiverWalletRequest]),
			"Error when retrieving receiver wallet transactions after receive",
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

		const receiverWalletBalanceAfterReceive = await asyncMiddleman(
			zeroFeeRpcClient.request("wallet_balance", [receiverWalletRequest]),
			"Error when retrieving receiver wallet balance after receive",
		);
		expect(receiverWalletBalanceAfterReceive).to.eq(
			new BigNumber(receiverWalletBalanceBeforeReceive)
				.plus(transferAmount)
				.toString(10),
			"Receiver balance should be increased by transfer amount",
		);
	});
});
