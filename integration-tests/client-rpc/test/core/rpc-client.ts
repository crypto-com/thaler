import axios from "axios";
import LosslessJSON = require("lossless-json");
import BigNumber from "bignumber.js";

export class RpcClient {
  private requestId = 1;
  constructor(private url: string) {}

  public async request(
    method: string,
    params: string | any[] = null
  ): Promise<any> {
    const id = (this.requestId += 1);
    const { data } = await axios.post(this.url, {
      jsonrpc: "2.0",
      id,
      method,
      params: typeof params === "string" ? [params] : params
    }, {
      transformResponse: (data) => {
        return LosslessJSON.parse(data, this.losslessJSONReviver);
      },
    });
    if (data["error"]) {
      return Promise.reject(data["error"]);
    }
    return data["result"];
  }

  private losslessJSONReviver(key, value) {
    if (value && value.isLosslessNumber) {
      return new BigNumber(value.toString());
    } else {
      return value;
    }
  }
}
