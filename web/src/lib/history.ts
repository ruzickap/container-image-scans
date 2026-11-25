import { withLatest } from "./data";
import { load, type History } from "./dynamodb";

// Scans of a group since "from" (YYYY-MM-DD): HISTORY#<group> items plus the
// LATEST items not in HISTORY (scans before HISTORY existed)
export async function loadHistory(
  group: string,
  from: string,
  latest: History[],
): Promise<History[]> {
  const items = await load<History>(`HISTORY#${group}`, [from, "~"]);
  return withLatest(items, latest, from);
}
