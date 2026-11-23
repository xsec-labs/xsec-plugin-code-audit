import type { PluginHost } from "../types";

/** The host pushes color-mode and on-primary; when an older host does not, the page derives them from the surface and accent colours. */
export function luminance(color: string): number | undefined {
  const hex = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(color.trim());
  let r: number, g: number, b: number;
  if (hex) {
    const h = hex[1]!.length === 3 ? hex[1]!.split("").map((c) => c + c).join("") : hex[1]!;
    [r, g, b] = [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
  } else {
    const rgb = /^rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)/i.exec(color.trim());
    if (!rgb) return undefined;
    [r, g, b] = [Number(rgb[1]), Number(rgb[2]), Number(rgb[3])];
  }
  const lin = (v: number) => { const s = v / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4; };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

export type ThemeFacts = { dark: boolean; onPrimary: string };

export function themeFacts(theme: Record<string, string>): ThemeFacts {
  const mode = theme["color-mode"];
  const pushedOn = theme["on-primary"];
  if ((mode === "dark" || mode === "light") && pushedOn) return { dark: mode === "dark", onPrimary: pushedOn };
  const surface = luminance(theme["content-surface"] ?? theme["window-background"] ?? "");
  const accent = luminance(theme["text-accent"] ?? "");
  return {
    dark: surface !== undefined ? surface < 0.25 : false,
    // Black or white, whichever reads better on the host's accent fill.
    onPrimary: accent !== undefined && accent > 0.4 ? "#000" : "#fff",
  };
}

/** "sent": the text is in the composer. "manual": it is not, and the panel shows it for the user to copy. */
export type SendResult = { kind: "sent" } | { kind: "manual"; reason: string };

/** Copy from inside a click handler: `execCommand` needs the user gesture, so nothing may be awaited before it. */
export function copySync(text: string): boolean {
  try {
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.cssText = "position:fixed;left:-9999px;top:0;opacity:0";
    document.body.append(area);
    area.select();
    const ok = document.execCommand("copy");
    area.remove();
    return ok;
  } catch { return false; }
}

export const COMPOSER_TEXT_METHOD = "xsec.workspace.composer.text.add";

const METHOD_MISSING = /unsupported|not (mounted|implemented|declared|found|allowed)|unknown|undeclared|no such/i;

/**
 * Put a request into the conversation's input box. Desktop has no text method for plugins yet, so when the host
 * does not offer COMPOSER_TEXT_METHOD (or refuses it) the caller shows the text for the user to copy by hand.
 */
export async function toConversation(host: PluginHost, text: string): Promise<SendResult> {
  try {
    await host.request(COMPOSER_TEXT_METHOD, { text });
    return { kind: "sent" };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error ?? "");
    return { kind: "manual", reason: METHOD_MISSING.test(message) ? "" : message };
  }
}
