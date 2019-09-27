import axios from "axios";
import BigNumber from "bignumber.js";

export class TendermintClient {
	constructor(private url: string) {}

	public isTxIdExists(txId: string): Promise<boolean> {
		console.log(txId);
		return axios
			.get(`${this.url}/tx_search?query="valid_txs.txid='${txId}'"`)
			.then((res) => {
				console.dir(res.data, { depth: null });
				return new BigNumber(res.data["result"].total_count).isGreaterThanOrEqualTo(
					1,
				);
			});
	}
}
