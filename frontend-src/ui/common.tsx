import type { ComponentChildren } from "preact";
import { useEffect, useState } from "preact/hooks";
import type { Severity, Verdict } from "../types";
import { SEVERITY_GLYPH, SEVERITY_LABEL, VERDICT_LABEL } from "../lib/derive";
import { Icon } from "./icons";

/** Severity square; a candidate without a rating shows 待, a rejected one 排 (verdict decides when there is no severity). */
export function SevBadge({ severity, verdict }: { severity?: Severity; verdict: Verdict }) {
  if (severity && verdict === "confirmed") {
    const cls = severity === "critical" ? "c" : severity === "high" ? "h" : severity === "medium" ? "m" : severity === "low" ? "l" : "x";
    return <span class={`sev ${cls}`} title={SEVERITY_LABEL[severity]}>{SEVERITY_GLYPH[severity]}</span>;
  }
  return verdict === "needs_validation"
    ? <span class="sev q" title="待验证，不评级">待</span>
    : <span class="sev x" title="已排除">排</span>;
}

export function VerdictPill({ verdict, extra }: { verdict: Verdict; extra?: string }) {
  const tone = verdict === "confirmed" ? "ok" : verdict === "needs_validation" ? "warn" : "";
  return <span class={`pill ${tone}`}>{VERDICT_LABEL[verdict]}{extra ? ` · ${extra}` : ""}</span>;
}

export function Segmented<T extends string>({ value, options, onChange, label }: {
  value: T;
  options: { id: T; label: ComponentChildren }[];
  onChange(value: T): void;
  label: string;
}) {
  return (
    <div class="seg" role="group" aria-label={label}>
      {options.map((o) => (
        <button type="button" key={o.id} aria-pressed={o.id === value} onClick={() => onChange(o.id)}>{o.label}</button>
      ))}
    </div>
  );
}

export function Switch({ on, onChange, disabled, label }: { on: boolean; onChange(next: boolean): void; disabled?: boolean; label: string }) {
  return (
    <button type="button" role="switch" aria-checked={on} aria-label={label} disabled={disabled} class={`sw${on ? " on" : ""}`} onClick={() => onChange(!on)} />
  );
}

export function Empty({ title, children }: { title: string; children?: ComponentChildren }) {
  return (
    <div class="empty">
      <b>{title}</b>
      {children ? <span class="muted">{children}</span> : null}
    </div>
  );
}

export function ErrorNote({ message, lines, onRetry }: { message: string; lines?: string[]; onRetry?(): void }) {
  return (
    <div class="err" role="alert">
      <Icon name="alert" />
      <div class="grow">
        <div>{message}</div>
        {lines?.length ? <ul>{lines.map((l, i) => <li key={i} class="mono">{l}</li>)}</ul> : null}
      </div>
      {onRetry ? <button type="button" class="btn sm" onClick={onRetry}>重试</button> : null}
    </div>
  );
}

export type ToastState = { id: number; text: string; tone: "ok" | "err" } | null;

export function Toast({ toast }: { toast: ToastState }) {
  if (!toast) return null;
  return <div class={`toast ${toast.tone}`} role="status" aria-live="polite" key={toast.id}>{toast.text}</div>;
}

/** Auto-hiding notice, per Desktop's composer-notice convention. */
export function useToast(): [ToastState, (text: string, tone?: "ok" | "err") => void] {
  const [toast, setToast] = useState<ToastState>(null);
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(null), 4000);
    return () => clearTimeout(timer);
  }, [toast]);
  return [toast, (text, tone = "ok") => setToast({ id: Date.now(), text, tone })];
}

/** A button that asks once more before a destructive action. */
export function ConfirmButton({ label, confirmLabel, onConfirm, disabled }: { label: ComponentChildren; confirmLabel: string; onConfirm(): void; disabled?: boolean }) {
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (!armed) return;
    const timer = setTimeout(() => setArmed(false), 4000);
    return () => clearTimeout(timer);
  }, [armed]);
  return armed
    ? <button type="button" class="btn sm danger" onClick={() => { setArmed(false); onConfirm(); }}>{confirmLabel}</button>
    : <button type="button" class="btn sm ghost" disabled={disabled} onClick={() => setArmed(true)}>{label}</button>;
}

export function Meter({ value, max }: { value: number; max: number }) {
  const pct = max > 0 ? Math.min(100, Math.round((value / max) * 100)) : 0;
  return <div class="meter" role="progressbar" aria-valuemin={0} aria-valuemax={max} aria-valuenow={value}><i style={{ width: `${pct}%` }} /></div>;
}
