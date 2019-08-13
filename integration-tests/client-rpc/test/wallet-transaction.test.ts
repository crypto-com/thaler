import "mocha";
import chaiAsPromised = require("chai-as-promised");
import { use as chaiUse, expect } from "chai";
import { RpcClient } from "./core/rpc-client";
import {
  sleep,
  newRpcClient,
  newWalletRequest,
  generateWalletName,
  WALLET_STAKING_ADDRESS,
  WALLET_TRANSFER_ADDRESS_1,
  WALLET_TRANSFER_ADDRESS_2,
  newZeroFeeRpcClient,
} from "./core/setup";
import BigNumber from "bignumber.js";
chaiUse(chaiAsPromised);

describe("Wallet transaction", () => {
  let zeroFeeClient: RpcClient;
  before(() => {
    zeroFeeClient = newZeroFeeRpcClient();
  });

  it("cannot send funds larger than wallet balance", async () => {
    const walletRequest = newWalletRequest("Spend");

    const totalCROSupply = "10000000000000000000";
    return expect(
      zeroFeeClient.request("wallet_sendToAddress", [
        walletRequest,
        WALLET_TRANSFER_ADDRESS_2,
        totalCROSupply
      ])
    ).to.eventually.rejectedWith("Insufficient balance");
  });

  it("can transfer funds between two wallets", async () => {
    const receiveWalletName = generateWalletName("Receive");
    const receiveWalletRequest = newWalletRequest("Receive");
    const receiveWalletTransactionListBeforeSend = await zeroFeeClient.request(
      "wallet_transactions",
      [receiveWalletRequest]
    );
    const spendWalletBalanceBeforeSend = await zeroFeeClient.request(
      "wallet_balance",
      [spendWalletRequest]
    );

    const receiveWalletTransferAddress = await zeroFeeClient.request(
      "wallet_newTransferAddress",
      [receiveWalletRequest],
    );










    const spendWalletRequest = newWalletRequest("Spend");

    const spendWalletTransactionListBeforeSend = await zeroFeeClient.request(
      "wallet_transactions",
      [spendWalletRequest]
    );
    const spendWalletBalanceBeforeSend = await zeroFeeClient.request(
      "wallet_balance",
      [spendWalletRequest]
    );

    const amountToSpend = 1000;
    await expect(
      zeroFeeClient.request("wallet_sendToAddress", [
        spendWalletRequest,
        WALLET_TRANSFER_ADDRESS_2,
        amountToSpend
      ])
    ).to.eventually.deep.eq(null);

    await sleep(2000);

    const spendWalletTransactionList = await zeroFeeClient.request(
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
      zeroFeeClient.request("wallet_balance", [spendWalletRequest])
    ).to.eventually.deep.eq(expectedSpendWalletBalanceAfterSend);
  });

  it("User can get receive address in newly created wallet", async () => {
    const walletName = generateWalletName("New Receive");
    const walletRequest = newWalletRequest(walletName);

    await expect(
      zeroFeeClient.request("wallet_create", [walletRequest])
    ).to.eventually.eq(walletName);

    const walletAddresses = await zeroFeeClient.request("wallet_addresses", [
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
      zeroFeeClient.request("wallet_create", [receiveWalletRequest])
    ).to.eventually.eq(receiveWalletName);
    const receiveWalletAddresses = await zeroFeeClient.request("wallet_addresses", [
      receiveWalletRequest
    ]);
    const receiveWalletAddress = receiveWalletAddresses[0];

    await expect(
      zeroFeeClient.request("wallet_balance", [receiveWalletRequest])
    ).to.eventually.deep.eq(new BigNumber(0));

    await expect(
      zeroFeeClient.request("wallet_sendtoaddress", [
        spendWalletRequest,
        receiveWalletAddress,
        500000000000000000
      ])
    ).to.eventually.deep.eq(null);

    await sleep(2000);

    const transactionList = await zeroFeeClient.request("wallet_transactions", [
      receiveWalletRequest
    ]);
    expect(transactionList.length).to.eq(1);

    const lastTransaction = transactionList[transactionList.length - 1];
    expectTransactionShouldBe(lastTransaction, {
      address: receiveWalletAddress,
      direction: TransactionDirection.INCOMING,
      amount: new BigNumber("500000000000000000")
    });

    return expect(
      zeroFeeClient.request("wallet_balance", [receiveWalletRequest])
    ).to.eventually.deep.eq(new BigNumber("500000000000000000"));
  });

  it("User can receive funds", async () => {
    const spendWalletRequest = newWalletRequest("Spend");
    const receiveWalletRequest = newWalletRequest("Receive");

    const receiveWalletTransactionListBeforeSend = await zeroFeeClient.request(
      "wallet_transactions",
      [receiveWalletRequest]
    );
    const receiveWalletBalanceBeforeSend = await zeroFeeClient.request(
      "wallet_balance",
      [receiveWalletRequest]
    );

    await expect(
      zeroFeeClient.request("wallet_sendtoaddress", [
        spendWalletRequest,
        RECEIVE_WALLET_ADDRESS,
        500000000000000000
      ])
    ).to.eventually.deep.eq(null);

    await sleep(2000);

    const receiveWalletTransactionList = await zeroFeeClient.request(
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
      amount: new BigNumber("500000000000000000")
    });

    const expectedReceiveWalletBalanceAfterSend = receiveWalletBalanceBeforeSend.plus(
      "500000000000000000"
    );
    return expect(
      zeroFeeClient.request("wallet_balance", [receiveWalletRequest])
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
        500000000000000000
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
    expect(actual.height).to.deep.eq(new BigNumber(expected.height));
  } else {
    expect(actual.height.isGreaterThan(0)).to.eq(true);
  }
  return true;
};
