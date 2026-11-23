import type { Profile, Settings } from "../types";

export const PROFILES: { id: Profile; label: string; summary: string; calls: string; defaultBudget: number }[] = [
  { id: "quick", label: "快速", summary: "一轮狩猎，适合小仓库或复查", calls: "约 15–25 次调用", defaultBudget: 30 },
  { id: "standard", label: "标准", summary: "多轮狩猎直到覆盖评审通过", calls: "约 50–80 次调用", defaultBudget: 60 },
  { id: "deep", label: "深入", summary: "按子系统细分，已覆盖单元再审一遍", calls: "约 150 次以上", defaultBudget: 160 },
];

export const DEFAULT_SETTINGS: Settings = {
  profile: "standard",
  budget: 60,
  concurrency: 4,
  excludes: ["node_modules/", "vendor/", "dist/", "**/testdata/"],
  readSecurityMd: true,
};

function int(value: unknown, fallback: number, min: number, max: number): number {
  const n = typeof value === "number" ? value : typeof value === "string" && value.trim() ? Number(value) : NaN;
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.round(n)));
}

/** Parse the stored settings object; anything missing or malformed falls back to the default. */
export function parseSettings(value: unknown): Settings {
  const o = typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
  const profile = o.profile === "quick" || o.profile === "deep" || o.profile === "standard" ? o.profile : DEFAULT_SETTINGS.profile;
  const excludes = Array.isArray(o.excludes)
    ? o.excludes.filter((x): x is string => typeof x === "string").map((x) => x.trim()).filter(Boolean).slice(0, 50)
    : DEFAULT_SETTINGS.excludes;
  return {
    profile,
    budget: int(o.budget, DEFAULT_SETTINGS.budget, 1, 1000),
    concurrency: int(o.concurrency, DEFAULT_SETTINGS.concurrency, 1, 8),
    excludes,
    readSecurityMd: typeof o.readSecurityMd === "boolean" ? o.readSecurityMd : DEFAULT_SETTINGS.readSecurityMd,
  };
}

/** One path per line or comma separated; blank lines dropped, duplicates removed. */
export function parsePathList(text: string): string[] {
  const seen = new Set<string>();
  for (const part of text.split(/[\n,]/)) {
    const trimmed = part.trim();
    if (trimmed) seen.add(trimmed);
  }
  return [...seen];
}
