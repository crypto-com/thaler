import { RpcClient } from "./rpc-client";

export const DEFAULT_WALLET_ADDRESS = "0xfb135596b941711a1611e59284424d412ee8fd9d";
export const SPEND_WALLET_ADDRESS = "0x4234ddd8fca1f213180526413042fe2ee6bceac8";
export const VIEW_WALLET_ADDRESS = "0x9c58f8fca74d7a555c2c52f3aa49f898dd1fc37b";
export const RECEIVE_WALLET_ADDRESS = "0x9af90833742a9c5552a0c3336540c8d083c9a79a";

const clientRpcPort = Number(process.env.CLIENT_RPC_ZERO_FEE_PORT) || 16659;

export const newRpcClient = (host: string = "localhost", port: number = clientRpcPort) => {
    return new RpcClient(`http://${host}:${port}`);
};

export const sleep = (ms: number = 1000) => {
  return new Promise(resolve => {
    setTimeout(resolve, ms);
  });
};

interface WalletRequest {
  name: string;
  passphrase: string;
}

export const generateWalletName = (prefix: string = "New Wallet"): string => {
  return `${prefix} ${Date.now()}`;
};

export const newWalletRequest = (
  name: string,
  passphrase: string = "uV97tEs5!*lLRQKj"
): WalletRequest => {
  return {
    name,
    passphrase
  };
};
