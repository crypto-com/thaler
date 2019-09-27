import "mocha";
import { expect } from "chai";
import BigNumber from "bignumber.js";

export enum TransactionDirection {
	INCOMING = "Incoming",
	OUTGOING = "Outgoing",
}
export interface TransactionAssertion {
	address?: string;
	direction: TransactionDirection;
	amount?: BigNumber;
	height?: number;
}

export const expectTransactionShouldBe = (
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

export const getFirstElementOfArray = (arr: any[]) => {
	return arr[0];
};