import "mocha";
import chaiAsPromised = require("chai-as-promised");
import { use as chaiUse, expect } from "chai";
import { RpcClient } from "./core/rpc-client";
import {
  generateWalletName,
  newWalletRequest,
  newRpcClient
} from "./core/setup";
chaiUse(chaiAsPromised);

describe("Wallet management", () => {
  let client: RpcClient;
  before(() => {
    client = newRpcClient();
  });

  it("User cannot access un-existing wallet", async () => {
    const nonExistingWalletName = generateWalletName();
    const nonExistingWalletRequest = newWalletRequest(nonExistingWalletName);

    await expect(
      client.request("wallet_addresses", [nonExistingWalletRequest])
    ).to.eventually.rejectedWith("Wallet not found");
    await expect(
      client.request("wallet_balance", [nonExistingWalletRequest])
    ).to.eventually.rejectedWith("Wallet not found");
    await expect(
      client.request("wallet_transactions", [nonExistingWalletRequest])
    ).to.eventually.rejectedWith("Wallet not found");
  });

  it("User can create wallet with specified name", async () => {
    const walletName = generateWalletName();
    const walletRequest = newWalletRequest(walletName);

    const walletCreateResult = await client.request("wallet_create", [
      walletRequest
    ]);
    expect(walletCreateResult).to.deep.eq(walletName);

    const walletList = await client.request("wallet_list");
    expect(walletList).to.include(walletName);
  });

  it("Newly created wallet has a new address associated", async () => {
    const walletName = generateWalletName();
    const walletRequest = newWalletRequest(walletName);

    const walletCreateResponse = await client.request("wallet_create", [
      walletRequest
    ]);
    expect(walletCreateResponse).to.deep.eq(walletName);

    const walletAddresses = await client.request("wallet_addresses", [
      walletRequest
    ]);
    expect(walletAddresses).to.be.an("array");
    expect(walletAddresses.length).to.eq(1);
  });

  it("User cannot create duplicated wallet", async () => {
    const walletName = generateWalletName();
    const walletRequest = newWalletRequest(walletName);

    const walletCreateResponse = await client.request("wallet_create", [
      walletRequest
    ]);
    expect(walletCreateResponse).to.deep.eq(walletName);

    const walletAddresses = await client.request("wallet_addresses", [
      walletRequest
    ]);

    await expect(
      client.request("wallet_create", [walletRequest])
    ).to.eventually.rejectedWith("Already exists in storage");

    return expect(
      client.request("wallet_addresses", [walletRequest])
    ).to.eventually.deep.eq(walletAddresses);
  });

  it("User cannot access wallet with incorrect passphrase", async () => {
    const walletName = generateWalletName();
    const walletPassphrase = "passphrase";
    const walletRequest = newWalletRequest(walletName, walletPassphrase);

    await expect(
      client.request("wallet_create", [walletRequest])
    ).to.eventually.deep.eq(walletName);

    const incorrectWalletPassphrase = "different_passphrase";
    const incorrectWalletRequest = newWalletRequest(
      walletName,
      incorrectWalletPassphrase
    );

    await expect(
      client.request("wallet_addresses", [incorrectWalletRequest])
    ).to.eventually.rejectedWith("Decryption error");
    await expect(
      client.request("wallet_balance", [incorrectWalletRequest])
    ).to.eventually.rejectedWith("Decryption error");
    await expect(
      client.request("wallet_transactions", [incorrectWalletRequest])
    ).to.eventually.rejectedWith("Decryption error");
  });
});
