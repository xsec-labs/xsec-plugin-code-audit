import type { PluginHost } from "../types";

/** The theme the host pushes has no colour mode, so the page derives it from the surface colour. */
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
  const surface = luminance(theme["content-surface"] ?? theme["window-background"] ?? "");
  const accent = luminance(theme["text-accent"] ?? "");
  return {
    dark: surface !== undefined ? surface < 0.25 : false,
    // Black or white, whichever reads better on the host's accent fill.
    onPrimary: accent !== undefined && accent > 0.4 ? "#000" : "#fff",
  };
}

export type SendResult = "sent" | "copied" | "failed";

async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) { await navigator.clipboard.writeText(text); return true; }
  } catch { /* fall through to the selection route */ }
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

/**
 * Put a request into the conversation's input box. Desktop has no text method for plugins yet, so when the host
 * does not offer COMPOSER_TEXT_METHOD (or the session cannot be edited) the text goes to the clipboard instead.
 */
export async function toConversation(host: PluginHost, text: string): Promise<SendResult> {
  try {
    await host.request(COMPOSER_TEXT_METHOD, { text });
    return "sent";
  } catch { /* the host has no such method for this plugin yet */ }
  return (await copyText(text)) ? "copied" : "failed";
}

export async function copy(text: string): Promise<boolean> {
  return copyText(text);
}
