// DynamoDB access with Cognito guest credentials - guests can only GetItem / BatchGetItem / Query the table
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { fromCognitoIdentityPool } from "@aws-sdk/credential-providers";
import { DynamoDBDocumentClient, QueryCommand } from "@aws-sdk/lib-dynamodb";

// Public values (outputs of opentofu/aws in ruzickap/my-git-projects)
const REGION = "eu-central-1";
const TABLE = "container-image-scans";
const IDENTITY_POOL_ID = "eu-central-1:52860e4f-1539-4b91-a8aa-a3862fa7cf65";

// "LATEST" item - latest scan of one image (group + vendor) by one scanner
export interface Scan {
  sk: string;
  group: string;
  group_description: string;
  vendor: string;
  image: string;
  image_description: string;
  scanner: string;
  scanner_version: string;
  scanner_db: string;
  image_digest: string;
  scanned_at: string;
  cves_pk: string;
  cve_total: number;
  cve_critical: number;
  cve_high: number;
  cve_medium: number;
  cve_low: number;
}

// One CVE of one package found by one scan
export interface Cve {
  sk: string;
  cve_id: string;
  severity: string;
  description: string;
  url: string;
  package_name: string;
  installed_version: string;
  fixed_version: string;
}

const db = DynamoDBDocumentClient.from(
  new DynamoDBClient({
    region: REGION,
    // Local development only: e.g. VITE_DYNAMODB_ENDPOINT=http://localhost:8000 for DynamoDB Local
    endpoint: import.meta.env.VITE_DYNAMODB_ENDPOINT || undefined,
    credentials: fromCognitoIdentityPool({
      identityPoolId: IDENTITY_POOL_ID,
      clientConfig: { region: REGION },
    }),
  }),
);

// All items of one partition - Query returns max. 1 MB per page
export async function query<T>(pk: string): Promise<T[]> {
  const items: T[] = [];
  let startKey: Record<string, unknown> | undefined;
  do {
    const page = await db.send(
      new QueryCommand({
        TableName: TABLE,
        KeyConditionExpression: "pk = :pk",
        ExpressionAttributeValues: { ":pk": pk },
        ExclusiveStartKey: startKey,
      }),
    );
    items.push(...((page.Items ?? []) as T[]));
    startKey = page.LastEvaluatedKey;
  } while (startKey);
  return items;
}
