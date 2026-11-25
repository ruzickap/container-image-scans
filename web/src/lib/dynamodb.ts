// DynamoDB access with Cognito guest credentials - guests can only GetItem / BatchGetItem / Query the table
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { fromCognitoIdentityPool } from "@aws-sdk/credential-providers";
import { DynamoDBDocumentClient, QueryCommand } from "@aws-sdk/lib-dynamodb";

// Public values (outputs of opentofu/aws in ruzickap/my-git-projects)
const REGION = "eu-central-1";
const TABLE = "container-image-scans";
const IDENTITY_POOL_ID = "eu-central-1:52860e4f-1539-4b91-a8aa-a3862fa7cf65";

// "HISTORY#<group>" item - summary of one scan (sk: <scanned_at>#<vendor>#<scanner>)
export interface History {
  sk: string;
  group: string;
  vendor: string;
  image: string;
  scanner: string;
  scanner_version: string;
  scanner_db: string;
  image_digest: string;
  // Missing in scans before the dashboard redesign
  image_size?: number;
  image_created?: string;
  scanned_at: string;
  cves_pk: string;
  cve_total: number;
  cve_critical: number;
  cve_high: number;
  cve_medium: number;
  cve_low: number;
  cve_fixable?: number;
}

// "LATEST" item - latest scan of one image (group + vendor) by one scanner
export interface Scan extends History {
  group_description: string;
  image_description: string;
  // Worst CVEs with a fixed version (missing in scans before the redesign)
  top_fixable?: Omit<Cve, "sk" | "description" | "url">[];
}

// "LIFECYCLE#<group>#<vendor>#<scanner>" item - one CVE + package of an image over time
export interface Lifecycle {
  sk: string;
  cve_id: string;
  package_name: string;
  severity: string;
  installed_version: string;
  fixed_version: string;
  first_seen: string;
  // First scan with a fixed version / first scan without the CVE
  fix_seen?: string;
  removed_at?: string;
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

// All items of one partition (optionally only sk between skRange) - Query returns max. 1 MB per page
export async function query<T>(
  pk: string,
  skRange?: [string, string],
): Promise<T[]> {
  const items: T[] = [];
  let startKey: Record<string, unknown> | undefined;
  do {
    const page = await db.send(
      new QueryCommand({
        TableName: TABLE,
        KeyConditionExpression: skRange
          ? "pk = :pk AND sk BETWEEN :from AND :to"
          : "pk = :pk",
        ExpressionAttributeValues: skRange
          ? { ":pk": pk, ":from": skRange[0], ":to": skRange[1] }
          : { ":pk": pk },
        ExclusiveStartKey: startKey,
      }),
    );
    items.push(...((page.Items ?? []) as T[]));
    startKey = page.LastEvaluatedKey;
  } while (startKey);
  return items;
}

// query() with a cache - the data changes once a day and the table has only 2 RCU
const cache = new Map<string, Promise<unknown[]>>();

export function load<T>(pk: string, skRange?: [string, string]): Promise<T[]> {
  const key = JSON.stringify([pk, skRange]);
  if (!cache.has(key)) {
    // A failed query is tried again next time
    cache.set(
      key,
      query<T>(pk, skRange).catch((error: unknown) => {
        cache.delete(key);
        throw error;
      }),
    );
  }
  return cache.get(key) as Promise<T[]>;
}
