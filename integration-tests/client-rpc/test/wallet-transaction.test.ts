import "mocha";
import chaiAsPromised = require("chai-as-promised");
import { use as chaiUse, expect } from "chai";
import { RpcClient } from "./core/rpc-client";
import {
  sleep,
  newRpcClient,
  newWalletRequest,
  generateWalletName,
  RECEIVE_WALLET_ADDRESS,
  SPEND_WALLET_ADDRESS
} from "./core/setup";
import BigNumber from "bignumber.js";
chaiUse(chaiAsPromised);

describe("Wallet transaction", () => {
  let client: RpcClient;
  before(() => {
    client = newRpcClient();
  });

  it("User can view genesis distribution in transaction", async () => {
    const walletRequest = newWalletRequest("Spend");

    const transactionList = await client.request("wallet_transactions", [
      walletRequest
    ]);

    expect(transactionList.length).to.be.greaterThan(0);
    const firstTransaction = transactionList[0];
    expectTransactionShouldBe(firstTransaction, {
      address: SPEND_WALLET_ADDRESS,
      direction: TransactionDirection.INCOMING,
      amount: "3000000000000000000",
      height: 0
    });
  });

  it("User cannot send funds larger than wallet balance", async () => {
    const walletRequest = newWalletRequest("Spend");

    const totalCROSupply = "10000000000000000000";
    return expect(
      client.request("wallet_sendtoaddress", [
        walletRequest,
        RECEIVE_WALLET_ADDRESS,
        totalCROSupply
      ])
    ).to.eventually.rejectedWith("Insufficient balance");
  });

  it("User can send funds", async () => {
    const spendWalletRequest = newWalletRequest("Spend");

    const spendWalletTransactionListBeforeSend = await client.request(
      "wallet_transactions",
      [spendWalletRequest]
    );
    const spendWalletBalanceBeforeSend = await client.request(
      "wallet_balance",
      [spendWalletRequest]
    );

    const amountToSpend = "500000000000000000";
    await expect(
      client.request("wallet_sendtoaddress", [
        spendWalletRequest,
        RECEIVE_WALLET_ADDRESS,
        amountToSpend
      ])
    ).to.eventually.deep.eq(null);

    await sleep(2000);

    const spendWalletTransactionList = await client.request(
      "wallet_transactions",
      [spendWalletRequest]
    );
    expect(spendWalletTransactionList.length).to.be.greaterThan(
      spendWalletTransactionListBeforeSend.length + 1
    );

    const spendWalletSecondLastTransaction =
      spendWalletTransactionList[spendWalletTransactionList.length - 2];
    expectTransactionShouldBe(spendWalletSecondLastTransaction, {
      direction: TransactionDirection.OUTGOING,
      amount: spendWalletBalanceBeforeSend
    });

    const spendWalletLastTransaction =
      spendWalletTransactionList[spendWalletTransactionList.length - 1];
    const expectedSpendWalletBalanceAfterSend = spendWalletBalanceBeforeSend.minus(
      amountToSpend
    );
    expectTransactionShouldBe(spendWalletLastTransaction, {
      direction: TransactionDirection.INCOMING,
      amount: expectedSpendWalletBalanceAfterSend
    });

    return expect(
      client.request("wallet_balance", [spendWalletRequest])
    ).to.eventually.deep.eq(expectedSpendWalletBalanceAfterSend);
  });

  it("User can get receive address in newly created wallet", async () => {
    const walletName = generateWalletName("New Receive");
    const walletRequest = newWalletRequest(walletName);

    await expect(
      client.request("wallet_create", [walletRequest])
    ).to.eventually.eq(walletName);

    const walletAddresses = await client.request("wallet_addresses", [
      walletRequest
    ]);
    expect(walletAddresses).to.be.an("array");
    expect(walletAddresses.length).to.eq(1);
    expect(walletAddresses[0]).to.match(/0x[0-9a-z]+/);
  });

  it("User can receive funds in newly created wallet", async () => {
    const spendWalletRequest = newWalletRequest("Spend");
    const receiveWalletName = generateWalletName("New Receive");
    const receiveWalletRequest = newWalletRequest(receiveWalletName);

    await expect(
      client.request("wallet_create", [receiveWalletRequest])
    ).to.eventually.eq(receiveWalletName);
    const receiveWalletAddresses = await client.request("wallet_addresses", [
      receiveWalletRequest
    ]);
    const receiveWalletAddress = receiveWalletAddresses[0];

    await expect(
      client.request("wallet_balance", [receiveWalletRequest])
    ).to.eventually.deep.eq(0);

    await expect(
      client.request("wallet_sendtoaddress", [
        spendWalletRequest,
        receiveWalletAddress,
        "500000000000000000"
      ])
    ).to.eventually.deep.eq(null);

    await sleep(2000);

    const transactionList = await client.request("wallet_transactions", [
      receiveWalletRequest
    ]);
    expect(transactionList.length).to.eq(1);

    const lastTransaction = transactionList[transactionList.length - 1];
    expectTransactionShouldBe(lastTransaction, {
      address: receiveWalletAddress,
      direction: TransactionDirection.INCOMING,
      amount: "500000000000000000"
    });

    return expect(
      client.request("wallet_balance", [receiveWalletRequest])
    ).to.eventually.deep.eq("500000000000000000");
  });

  it("User can receive funds", async () => {
    const spendWalletRequest = newWalletRequest("Spend");
    const receiveWalletRequest = newWalletRequest("Receive");

    const receiveWalletTransactionListBeforeSend = await client.request(
      "wallet_transactions",
      [receiveWalletRequest]
    );
    const receiveWalletBalanceBeforeSend = await client.request(
      "wallet_balance",
      [receiveWalletRequest]
    );

    await expect(
      client.request("wallet_sendtoaddress", [
        spendWalletRequest,
        RECEIVE_WALLET_ADDRESS,
        "500000000000000000"
      ])
    ).to.eventually.deep.eq(null);

    await sleep(2000);

    const receiveWalletTransactionList = await client.request(
      "wallet_transactions",
      [receiveWalletRequest]
    );
    expect(receiveWalletTransactionList.length).to.eq(
      receiveWalletTransactionListBeforeSend.length + 1
    );

    const lastTransaction =
      receiveWalletTransactionListBeforeSend[
        receiveWalletTransactionListBeforeSend.length - 1
      ];
    expectTransactionShouldBe(lastTransaction, {
      address: RECEIVE_WALLET_ADDRESS,
      direction: TransactionDirection.INCOMING,
      amount: "500000000000000000"
    });

    const expectedReceiveWalletBalanceAfterSend = receiveWalletBalanceBeforeSend.plus(
      "500000000000000000"
    );
    return expect(
      client.request("wallet_balance", [receiveWalletRequest])
    ).to.eventually.deep.eq(expectedReceiveWalletBalanceAfterSend);
  });

  it("User can send funds with fee included", async () => {
    const clientRpcWithFeePort =
      Number(process.env.CLIENT_RPC_WITH_FEE_PORT) || 26659;
    const client = newRpcClient("localhost", clientRpcWithFeePort);

    const walletRequest = newWalletRequest("Spend");

    const transactionListBeforeSend = await client.request(
      "wallet_transactions",
      [walletRequest]
    );
    const balanceBeforeSend = await client.request("wallet_balance", [
      walletRequest
    ]);

    await expect(
      client.request("wallet_sendtoaddress", [
        walletRequest,
        RECEIVE_WALLET_ADDRESS,
        "500000000000000000"
      ])
    ).to.eventually.deep.eq(null);

    await sleep(2000);

    const transactionList = await client.request("wallet_transactions", [
      walletRequest
    ]);
    expect(transactionList.length).to.be.greaterThan(
      transactionListBeforeSend.length
    );

    const expectedMaxBalanceAfterSend = balanceBeforeSend.minus(
      "500000000000000000"
    );
    const expectedMaxFee = "10000000";
    const expectedMinBalanceAfterSend = balanceBeforeSend
      .minus("500000000000000000")
      .minus(expectedMaxFee);
    const balanceAfterSend: BigNumber = await client.request("wallet_balance", [
      walletRequest
    ]);
    expect(balanceAfterSend.isLessThan(expectedMaxBalanceAfterSend)).to.eq(
      true
    );
    expect(balanceAfterSend.isGreaterThan(expectedMinBalanceAfterSend)).to.eq(
      true
    );
  });
});

enum TransactionDirection {
  INCOMING = "Incoming",
  OUTGOING = "Outgoing"
}
interface TransactionAssertion {
  address?: string;
  direction: TransactionDirection;
  amount: BigNumber;
  height?: number;
}

const expectTransactionShouldBe = (
  actual: any,
  expected: TransactionAssertion
): boolean => {
  expect(actual).to.contain.keys([
    "address",
    "balance_change",
    "height",
    "time",
    "transaction_id"
  ]);

  if (typeof expected.address !== "undefined") {
    expect(actual.address).to.deep.eq({
      BasicRedeem: expected.address
    });
  }

  expect(actual.balance_change).to.deep.eq({
    [expected.direction]: expected.amount
  });

  if (typeof expected.height !== "undefined") {
    expect(actual.height).to.deep.eq(expected.height);
  } else {
    expect(actual.height.isGreaterThan(0)).to.eq(true);
  }
  return true;
};
