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
	newCreateWalletRequest,
	generateWalletName,
	newZeroFeeRpcClient,
	newWithFeeRpcClient,
	shouldTest,
	FEE_SCHEMA,
	newZeroFeeTendermintClient,
	newWithFeeTendermintClient,
	asyncMiddleman,
	TRANSACTION_HISTORY_LIMIT,
	DEFAULT_PASSPHRASE,
} from "./core/utils";
import { TendermintClient } from "./core/tendermint-client";
import { waitTxIdConfirmed, syncWallet } from "./core/rpc";
import {
	expectTransactionShouldBe,
	expectUTXOShouldEq,
	TransactionDirection,
	getFirstElementOfArray,
} from "./core/transaction-utils";
chaiUse(chaiAsPromised);

describe("Wallet transaction", () => {
	let zeroFeeRpcClient: RpcClient;
	let zeroFeeTendermintClient: TendermintClient;
	let withFeeRpcClient: RpcClient;
	let withFeeTendermintClient: TendermintClient;
	before(async () => {
		await unbondAndWithdrawStake();
		zeroFeeRpcClient = newZeroFeeRpcClient();
		zeroFeeTendermintClient = newZeroFeeTendermintClient();
		withFeeRpcClient = newWithFeeRpcClient();
		withFeeTendermintClient = newWithFeeTendermintClient();
	});

	describe("Zero Fee", () => {
		if (!shouldTest(FEE_SCHEMA.ZERO_FEE)) {
			return;
		}
		it("cannot send funds larger than wallet balance", async () => {
			const walletRequest = await newWalletRequest(
				zeroFeeRpcClient,
				"Default",
				DEFAULT_PASSPHRASE,
			);

			const totalCROSupply = "10000000000000000000";
			return expect(
				zeroFeeRpcClient.request("wallet_sendToAddress", [
					walletRequest,
					WALLET_TRANSFER_ADDRESS_2,
					totalCROSupply,
					[],
				]),
			).to.eventually.rejectedWith("Insufficient balance");
		});

		it("can transfer funds between two wallets", async function () {
			this.timeout(300000);

			const receiverWalletName = generateWalletName("Receive");
			const senderWalletRequest = await newWalletRequest(
				zeroFeeRpcClient,
				"Default",
				DEFAULT_PASSPHRASE,
			);
			const receiverCreateWalletRequest = newCreateWalletRequest(
				receiverWalletName,
				DEFAULT_PASSPHRASE,
			);
			const transferAmount = "1000";

			const enckey = (
				await asyncMiddleman(
					zeroFeeRpcClient.request("wallet_create", [
						receiverCreateWalletRequest,
						"Basic",
					]),
					"Error when creating receiver wallet",
				)
			)[0];
			const receiverWalletRequest = {
				name: receiverWalletName,
				enckey,
			};

			const senderWalletTransactionListBeforeSend = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_transactions", [
					senderWalletRequest,
					0,
					TRANSACTION_HISTORY_LIMIT,
					true,
				]),
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
				"Error when creating receiver transfer address",
			);
			const receiverWalletTransactionListBeforeReceive = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_transactions", [
					receiverWalletRequest,
					0,
					TRANSACTION_HISTORY_LIMIT,
					true,
				]),
				"Error when retrieving receiver wallet transactions before receive",
			);
			const receiverWalletBalanceBeforeReceive = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_balance", [receiverWalletRequest]),
				"Error when retrieving reciever wallet balance before receive",
			);
			const receiverViewKey = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_getViewKey", [
					receiverWalletRequest,
					false,
				]),
				"Error when retrieving receiver view key",
			);

			const txId = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_sendToAddress", [
					senderWalletRequest,
					receiverWalletTransferAddress,
					transferAmount,
					[receiverViewKey],
				]),
				"Error when trying to send funds from sender to receiver",
			);
			expect(txId.length).to.eq(
				64,
				"wallet_sendToAddress should return transaction id",
			);

			//before sync, check wallet
			const senderWalletBalanceBeforeSync = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_balance", [senderWalletRequest]),
				"Error when retrieving sender wallet balance after send",
			);
			const senderWalletAvailableAmountAfterSend = new BigNumber(
				senderWalletBalanceBeforeSend.total,
			)
				.minus(transferAmount)
				.toString(10);
			const expectedSenderWalletBalanceBeforeSync = {
				total: senderWalletAvailableAmountAfterSend,
				pending: senderWalletAvailableAmountAfterSend,
				available: "0",
			};
			expect(senderWalletBalanceBeforeSync).to.deep.eq(
				expectedSenderWalletBalanceBeforeSync,
				"Sender balance should be deducted by transfer amount",
			);

			await asyncMiddleman(
				waitTxIdConfirmed(zeroFeeTendermintClient, txId),
				"Error when waiting for transaction confirmation",
			);
			await asyncMiddleman(
				syncWallet(zeroFeeRpcClient, senderWalletRequest),
				"Error when synchronizing sender wallet",
			);
			await asyncMiddleman(
				syncWallet(zeroFeeRpcClient, receiverWalletRequest),
				"Error when synchronizing receiver wallet",
			);

			const senderWalletTransactionListAfterSend = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_transactions", [
					senderWalletRequest,
					0,
					TRANSACTION_HISTORY_LIMIT,
					true,
				]),
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

			// after sync, the pending amount will become available
			const senderWalletBalanceAfterSync = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_balance", [senderWalletRequest]),
				"Error when retrieving sender wallet balance after send",
			);
			const expectedSenderWalletBalanceAfterSync = {
				total: senderWalletAvailableAmountAfterSend,
				pending: "0",
				available: senderWalletAvailableAmountAfterSend,
			};
			expect(senderWalletBalanceAfterSync).to.deep.eq(
				expectedSenderWalletBalanceAfterSync,
				"Sender balance should be deducted by transfer amount",
			);

			const receiverWalletTransactionListAfterReceive = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_transactions", [
					receiverWalletRequest,
					0,
					TRANSACTION_HISTORY_LIMIT,
					true,
				]),
				"Error when retrieving receiver wallet transaction after receive",
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
			const receiverTotalAmount = new BigNumber(
				receiverWalletBalanceBeforeReceive.total,
			)
				.plus(transferAmount)
				.toString(10);
			const expectedReceiverBalanceBalanceAfterReceive = {
				total: receiverTotalAmount,
				available: receiverTotalAmount,
				pending: "0",
			};
			expect(receiverWalletBalanceAfterReceive).to.deep.eq(
				expectedReceiverBalanceBalanceAfterReceive,
				"Receiver balance should be increased by transfer amount",
			);

			// Transfer funds to address the second time
			const senderUTXOsAfterSend = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_listUTxO", [senderWalletRequest]),
				"Error when retrieving sender wallet UTXO after send",
			);
			expect(senderUTXOsAfterSend.length).to.eq(1);
			expectUTXOShouldEq(
				senderUTXOsAfterSend[0],
				{
					txId,
					index: 1,
					amount: senderWalletAvailableAmountAfterSend,
				},
				"Mismatch UTXO after send",
			);

			const secondTxId = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_sendToAddress", [
					senderWalletRequest,
					receiverWalletTransferAddress,
					transferAmount,
					[receiverViewKey],
				]),
				"Error when trying to send funds from sender to receiver in second transfer",
			);
			expect(txId.length).to.eq(
				64,
				"wallet_sendToAddress should return transaction id in second transfer",
			);

			const senderSecondTransferWalletBalanceBeforeSync = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_balance", [senderWalletRequest]),
				"Error when retrieving sender wallet balance after send in second transfer",
			);
			const senderSecondTransferWalletAvailableAmountAfterSend = new BigNumber(
				senderWalletAvailableAmountAfterSend,
			)
				.minus(transferAmount)
				.toString(10);
			const expectedSenderSecondTransferWalletBalanceBeforeSync = {
				total: senderSecondTransferWalletAvailableAmountAfterSend,
				pending: senderSecondTransferWalletAvailableAmountAfterSend,
				available: "0",
			};
			expect(senderSecondTransferWalletBalanceBeforeSync).to.deep.eq(
				expectedSenderSecondTransferWalletBalanceBeforeSync,
				"Sender balance should be deducted by transfer amount in second transfer",
			);

			await asyncMiddleman(
				waitTxIdConfirmed(zeroFeeTendermintClient, txId),
				"Error when waiting for transaction confirmation in second transfer",
			);
			await asyncMiddleman(
				syncWallet(zeroFeeRpcClient, senderWalletRequest),
				"Error when synchronizing sender wallet in second transfer",
			);

			const senderSecondTransferWalletBalanceAfterSync = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_balance", [senderWalletRequest]),
				"Error when retrieving sender wallet balance after send in second transfer",
			);
			const expectedSenderSecondTransferWalletBalanceAfterSync = {
				total: senderSecondTransferWalletAvailableAmountAfterSend,
				pending: "0",
				available: senderSecondTransferWalletAvailableAmountAfterSend,
			};
			expect(senderSecondTransferWalletBalanceAfterSync).to.deep.eq(
				expectedSenderSecondTransferWalletBalanceAfterSync,
				"Sender balance should be available after sync in second transfer",
			);

			const senderSecondTransferUTXOsAfterSend = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_listUTxO", [senderWalletRequest]),
				"Error when retrieving sender wallet UTXO after send in second transfer",
			);
			expect(senderSecondTransferUTXOsAfterSend.length).to.eq(1);
			expectUTXOShouldEq(
				senderSecondTransferUTXOsAfterSend[0],
				{
					txId: secondTxId,
					index: 1,
					amount: senderSecondTransferWalletAvailableAmountAfterSend,
				},
				"Mismatch UTXO after send in second transfer",
			);

			const senderSecondTransferWalletTransactionListAfterSend = await asyncMiddleman(
				zeroFeeRpcClient.request("wallet_transactions", [
					senderWalletRequest,
					0,
					TRANSACTION_HISTORY_LIMIT,
					true,
				]),
				"Error when retrieving sender wallet transactions after send in second transfer",
			);

			expect(senderSecondTransferWalletTransactionListAfterSend.length).to.eq(
				senderWalletTransactionListAfterSend.length + 1,
				"Sender should have one extra transaction record after second send",
			);
		});
	});

	describe("With Fee", () => {
		if (!shouldTest(FEE_SCHEMA.WITH_FEE)) {
			return;
		}
		it("can transfer funds between two wallets with fee included", async function () {
			this.timeout(300000);

			const receiverWalletName = generateWalletName("Receive");
			const senderWalletRequest = await newWalletRequest(
				withFeeRpcClient,
				"Default",
				DEFAULT_PASSPHRASE,
			);
			const receiverCreateWalletRequest = newCreateWalletRequest(
				receiverWalletName,
				DEFAULT_PASSPHRASE,
			);
			const transferAmount = "1000";

			const enckey = (
				await asyncMiddleman(
					withFeeRpcClient.request("wallet_create", [
						receiverCreateWalletRequest,
						"Basic",
					]),
					"Error when creating receiver wallet",
				)
			)[0];
			const receiverWalletRequest = {
				name: receiverWalletName,
				enckey,
			};

			const senderWalletTransactionListBeforeSend = await asyncMiddleman(
				withFeeRpcClient.request("wallet_transactions", [
					senderWalletRequest,
					0,
					TRANSACTION_HISTORY_LIMIT,
					true,
				]),
				"Error when retrieving sender wallet transaction before send",
			);
			const senderWalletBalanceBeforeSend = await asyncMiddleman(
				withFeeRpcClient.request("wallet_balance", [senderWalletRequest]),
				"Error when retrieving sender wallet balance before send",
			);

			const receiverWalletTransferAddress = await asyncMiddleman(
				withFeeRpcClient.request("wallet_createTransferAddress", [
					receiverWalletRequest,
				]),
				"Error when creating receiver transfer address",
			);
			const receiverWalletTransactionListBeforeReceive = await asyncMiddleman(
				withFeeRpcClient.request("wallet_transactions", [
					receiverWalletRequest,
					0,
					TRANSACTION_HISTORY_LIMIT,
					true,
				]),
				"Error when retrieving receiver wallet transaction before receive",
			);
			const receiverWalletBalanceBeforeReceive = await asyncMiddleman(
				withFeeRpcClient.request("wallet_balance", [receiverWalletRequest]),
				"Error when retrieving receiver wallet balance before receive",
			);
			const receiverViewKey = await asyncMiddleman(
				withFeeRpcClient.request("wallet_getViewKey", [
					receiverWalletRequest,
					false,
				]),
				"Error when retrieving receiver view key",
			);

			const txId = await asyncMiddleman(
				withFeeRpcClient.request("wallet_sendToAddress", [
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
				waitTxIdConfirmed(withFeeTendermintClient, txId),
				"Error when waiting for transaction confirmation",
			);

			await asyncMiddleman(
				syncWallet(withFeeRpcClient, senderWalletRequest),
				"Error when synchronizing sender wallet",
			);
			await asyncMiddleman(
				syncWallet(withFeeRpcClient, receiverWalletRequest),
				"Error when synchronizing receiver wallet",
			);

			const senderWalletTransactionListAfterSend = await asyncMiddleman(
				withFeeRpcClient.request("wallet_transactions", [
					senderWalletRequest,
					0,
					TRANSACTION_HISTORY_LIMIT,
					true,
				]),
				"Error when retrieving sender wallet transactions after send",
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
				new BigNumber(0).isLessThan(new BigNumber(senderWalletLastTransaction.fee)),
			).to.eq(true, "Sender should pay for transfer fee");

			const senderWalletBalanceAfterSend = await asyncMiddleman(
				withFeeRpcClient.request("wallet_balance", [senderWalletRequest]),
				"Error when retrieving sender wallet balance after send",
			);
			expect(
				new BigNumber(senderWalletBalanceAfterSend.total).isLessThan(
					new BigNumber(senderWalletBalanceBeforeSend.available).minus(
						transferAmount,
					),
				),
			).to.eq(
				true,
				"Sender balance should be deducted by transfer amount and fee",
			);

			const receiverWalletTransactionListAfterReceive = await asyncMiddleman(
				withFeeRpcClient.request("wallet_transactions", [
					receiverWalletRequest,
					0,
					TRANSACTION_HISTORY_LIMIT,
					true,
				]),
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
				"Receiver should have one Incoming transaction of the exact received amount",
			);

			const receiverWalletBalanceAfterReceive = await asyncMiddleman(
				withFeeRpcClient.request("wallet_balance", [receiverWalletRequest]),
				"Error when retrieving receiver wallet balance after receive",
			);
			const receiverTotalAmount = new BigNumber(
				receiverWalletBalanceBeforeReceive.total,
			)
				.plus(transferAmount)
				.toString(10);
			const expectedBalanceAfterReceive = {
				total: receiverTotalAmount,
				available: receiverTotalAmount,
				pending: "0",
			};
			expect(receiverWalletBalanceAfterReceive).to.deep.eq(
				expectedBalanceAfterReceive,
				"Receiver balance should be increased by the exact transfer amount",
			);
		});
	});
});
