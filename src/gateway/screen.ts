/**
 * Heuristic prompt-injection screening for tool output.
 *
 * Scans text the server returns to the client for classic injection
 * tells. This is a flag — not a block: detection is heuristic and
 * blocking would break legitimate tools that echo user text. Matches
 * are recorded on the audit record as `injectionFlags`.
 */

export interface InjectionPattern {
  name: string;
  pattern: RegExp;
}

const PATTERNS: InjectionPattern[] = [
  {
    name: "ignore-instructions",
    pattern: /\bignore\s+(all\s+|any\s+)?(previous|prior)\s+instructions?\b/i,
  },
  {
    name: "disregard-instructions",
    pattern: /\bdisregard\s+(all\s+|your\s+|these\s+)?instructions?\b/i,
  },
  {
    name: "system-prompt-request",
    pattern: /\b(system\s+prompt|reveal\s+your\s+instructions?)\b/i,
  },
  { name: "role-override", pattern: /\byou\s+are\s+now\b/i },
  { name: "new-instructions", pattern: /\bnew\s+instructions?:/i },
  {
    name: "do-not-disclose",
    pattern: /\bdo\s+not\s+(reveal|mention|disclose)\b/i,
  },
  { name: "jailbreak", pattern: /\bjailbreak\b/i },
];

/** Names of the injection patterns that match `text` (deduped). */
export function screenText(text: string): string[] {
  const hits = new Set<string>();
  for (const p of PATTERNS) {
    if (p.pattern.test(text)) hits.add(p.name);
  }
  return [...hits];
}

/** Pull every text block out of a tools/call result payload. */
export function extractResultTexts(result: unknown): string[] {
  if (typeof result !== "object" || result === null) return [];
  const content = (result as Record<string, unknown>)["content"];
  const texts: string[] = [];
  if (Array.isArray(content)) {
    for (const block of content) {
      if (
        typeof block === "object" &&
        block !== null &&
        (block as Record<string, unknown>)["type"] === "text" &&
        typeof (block as Record<string, unknown>)["text"] === "string"
      ) {
        texts.push((block as Record<string, unknown>)["text"] as string);
      }
    }
  }
  // structuredContent carries the same tool output as JSON: a server can
  // hide injection tells there instead of in a text block, so walk it
  // and collect every string value for screening too.
  collectStrings((result as Record<string, unknown>)["structuredContent"], texts);
  return texts;
}

/** Append every string value found anywhere inside `value` to `out`. */
function collectStrings(value: unknown, out: string[]): void {
  if (typeof value === "string") {
    out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, out);
    return;
  }
  if (typeof value === "object" && value !== null) {
    for (const item of Object.values(value as Record<string, unknown>)) {
      collectStrings(item, out);
    }
  }
}
