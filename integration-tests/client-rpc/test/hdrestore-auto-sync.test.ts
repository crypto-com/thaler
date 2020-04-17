import "mocha";
import chaiAsPromised = require("chai-as-promised");
import { use as chaiUse, expect } from "chai";
import BigNumber from "bignumber.js";

import { RpcClient } from "./core/rpc-client";
import { unbondAndWithdrawStake } from "./core/setup";
import {
	newWalletRequest,
	newCreateWalletRequest,
	generateWalletName,
	newZeroFeeRpcClient,
	sleep,
	shouldTest,
	FEE_SCHEMA,
	asyncMiddleman,
	newZeroFeeTendermintClient,
	TRANSACTION_HISTORY_LIMIT,
	DEFAULT_PASSPHRASE,
} from "./core/utils";
import { syncWallet, waitTxIdConfirmed } from "./core/rpc";
import { TendermintClient } from "./core/tendermint-client";
import {
	getFirstElementOfArray,
	expectTransactionShouldBe,
	TransactionDirection,
} from "./core/transaction-utils";
chaiUse(chaiAsPromised);

describe("HDWallet Restore Auto-sync", () => {
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

	it("can auto-sync unlocked wallets", async function () {
		this.timeout(300000);

		const receiverWalletName = generateWalletName("Receive");
		const senderWalletRequest = await newWalletRequest(zeroFeeRpcClient, "Default", DEFAULT_PASSPHRASE);
		const createReceiverWalletRequest = newCreateWalletRequest(receiverWalletName, DEFAULT_PASSPHRASE);
		const transferAmount = "1000";

		const enckey = await asyncMiddleman(
			zeroFeeRpcClient.request("wallet_restore", [createReceiverWalletRequest, "blind heavy warrior off power high lab trend diagram happy bargain level demise safe image pride napkin example wolf adjust pistol spatial eight audit"]),
			"Error when recovering receiver hdwallet",
		);
		const receiverWalletRequest = {
			name: receiverWalletName,
			enckey,
		};
		console.log('receiverWalletRequest', receiverWalletRequest);

		await asyncMiddleman(
			syncWallet(zeroFeeRpcClient, senderWalletRequest),
			"Error when synchronizing sender wallet",
		);
		await asyncMiddleman(
			syncWallet(zeroFeeRpcClient, receiverWalletRequest),
			"Error when synchronizing receiver wallet",
		);

		const senderWalletTransactionListBeforeSend = await asyncMiddleman(
			zeroFeeRpcClient.request("wallet_transactions", [senderWalletRequest, 0, TRANSACTION_HISTORY_LIMIT, true]),
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
			zeroFeeRpcClient.request("wallet_transactions", [receiverWalletRequest, 0, TRANSACTION_HISTORY_LIMIT, true]),
			"Error when retrieving receiver wallet transactions before receive",
		);
		const receiverWalletBalanceBeforeReceive = await asyncMiddleman(
			zeroFeeRpcClient.request("wallet_balance", [receiverWalletRequest]),
			"Error when retrieving receiver wallet balance before receive",
		);
		const receiverViewKey = await asyncMiddleman(
			zeroFeeRpcClient.request("wallet_getViewKey", [receiverWalletRequest, false]),
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

		await zeroFeeRpcClient.request("sync", [senderWalletRequest, {
			blocking: false,
			reset: false,
			do_loop: false,
		}]);
		await zeroFeeRpcClient.request("sync", [receiverWalletRequest, {
			blocking: false,
			reset: false,
			do_loop: false,
		}]);
		console.info(
			`[Log] Enabled auto-sync for wallets "${senderWalletRequest.name}" and "${receiverWalletName}"`,
		);

		await sleep(1000);
		while (true) {
			console.log(`[Log] Checking for wallet sync status`);
			const senderWalletTransactionListAfterSend = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_transactions", [senderWalletRequest, 0, TRANSACTION_HISTORY_LIMIT, true]),
				"Error when retrieving sender wallet transactions after send",
			);

			const receiverWalletTransactionListAfterReceive = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_transactions", [receiverWalletRequest, 0, TRANSACTION_HISTORY_LIMIT, true]),
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
			zeroFeeRpcClient.request("wallet_transactions", [senderWalletRequest, 0, TRANSACTION_HISTORY_LIMIT, true]),
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
		// after sync, the pending balance will become available
		const senderWalletBalanceAfterSync = await asyncMiddleman(
			zeroFeeRpcClient.request("wallet_balance", [senderWalletRequest]),
			"Error when retrieving sender wallet balance after send",
		);
		const returnAmount = new BigNumber(senderWalletBalanceBeforeSend.total)
			.minus(transferAmount)
			.toString(10);
		const expectBalanceAfterSync = {
			total: returnAmount,
			available: returnAmount,
			pending: "0",
		}
		expect(senderWalletBalanceAfterSync).to.deep.eq(
			expectBalanceAfterSync,
			"Sender balance total should be deducted by transfer amount",
		);

		const receiverWalletTransactionListAfterReceive = await asyncMiddleman(
			zeroFeeRpcClient.request("wallet_transactions", [receiverWalletRequest, 0, TRANSACTION_HISTORY_LIMIT, true]),
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
		const expectBalanceAfterReciev = {
			total: transferAmount,
			available: transferAmount,
			pending: "0",
		}
		expect(receiverWalletBalanceAfterReceive).to.deep.eq(
			expectBalanceAfterReciev,
			"Receiver balance should be increased by transfer amount",
		);
	});
});
