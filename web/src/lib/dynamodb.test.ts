import { beforeEach, describe, expect, it, vi } from "vitest";
import { load, query } from "./dynamodb";

// Fake DynamoDB client - no AWS or Cognito calls
const send = vi.hoisted(() => vi.fn());
vi.mock("@aws-sdk/client-dynamodb", () => ({ DynamoDBClient: class {} }));
vi.mock("@aws-sdk/credential-providers", () => ({
  fromCognitoIdentityPool: () => undefined,
}));
vi.mock("@aws-sdk/lib-dynamodb", () => ({
  DynamoDBDocumentClient: { from: () => ({ send }) },
  QueryCommand: class {
    input: unknown;
    constructor(input: unknown) {
      this.input = input;
    }
  },
}));

describe("query", () => {
  beforeEach(() => {
    send.mockReset();
  });

  it("reads all pages of a partition", async () => {
    send
      .mockResolvedValueOnce({
        Items: [{ sk: "1" }, { sk: "2" }],
        LastEvaluatedKey: { pk: "LATEST", sk: "2" },
      })
      .mockResolvedValueOnce({ Items: [{ sk: "3" }] });

    expect(await query("LATEST")).toEqual([
      { sk: "1" },
      { sk: "2" },
      { sk: "3" },
    ]);
    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[0][0].input).toEqual({
      TableName: "container-image-scans",
      KeyConditionExpression: "pk = :pk",
      ExpressionAttributeValues: { ":pk": "LATEST" },
      ExclusiveStartKey: undefined,
    });
    expect(send.mock.calls[1][0].input.ExclusiveStartKey).toEqual({
      pk: "LATEST",
      sk: "2",
    });
  });

  it("returns an empty list for an empty partition", async () => {
    send.mockResolvedValueOnce({});

    expect(await query("CVES#none")).toEqual([]);
  });

  it("reads only the sort keys of a range", async () => {
    send.mockResolvedValueOnce({ Items: [] });

    await query("HISTORY#python", ["2026-11-01", "~"]);

    expect(send.mock.calls[0][0].input).toMatchObject({
      KeyConditionExpression: "pk = :pk AND sk BETWEEN :from AND :to",
      ExpressionAttributeValues: {
        ":pk": "HISTORY#python",
        ":from": "2026-11-01",
        ":to": "~",
      },
    });
  });
});

describe("load", () => {
  beforeEach(() => {
    send.mockReset();
  });

  it("queries a partition once, but again after an error", async () => {
    send
      .mockRejectedValueOnce(new Error("ThrottlingException"))
      .mockResolvedValueOnce({ Items: [{ sk: "1" }] });

    await expect(load("CVES#cached")).rejects.toThrow("ThrottlingException");
    expect(await load("CVES#cached")).toEqual([{ sk: "1" }]);
    expect(await load("CVES#cached")).toEqual([{ sk: "1" }]);
    expect(send).toHaveBeenCalledTimes(2);
  });
});
