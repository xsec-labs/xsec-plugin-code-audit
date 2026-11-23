import type { JSX } from "preact";

const PATHS: Record<string, JSX.Element> = {
  shield: <path d="M8 1.8 2.9 3.6v4.1c0 3 2.1 5.3 5.1 6.5 3-1.2 5.1-3.5 5.1-6.5V3.6L8 1.8Z" />,
  search: <><circle cx="7" cy="7" r="4.2" /><path d="m10.2 10.2 3 3" /></>,
  chevronDown: <path d="m4 6 4 4 4-4" />,
  chevronRight: <path d="m6 4 4 4-4 4" />,
  chevronLeft: <path d="m10 4-4 4 4 4" />,
  chevronUp: <path d="m4 10 4-4 4 4" />,
  download: <><path d="M8 2.5v8" /><path d="m4.8 7.6 3.2 3.2 3.2-3.2" /><path d="M3 13h10" /></>,
  play: <path d="M5 3.2v9.6l7.6-4.8L5 3.2Z" />,
  plus: <path d="M8 3v10M3 8h10" />,
  at: <><circle cx="8" cy="8" r="2.4" /><path d="M10.4 8v1a1.8 1.8 0 0 0 3.6 0V8a6 6 0 1 0-2.4 4.8" /></>,
  folder: <path d="M2 4.6c0-.6.4-1 1-1h3l1.4 1.6H13c.6 0 1 .4 1 1v5.2c0 .6-.4 1-1 1H3c-.6 0-1-.4-1-1V4.6Z" />,
  x: <path d="m4 4 8 8M12 4l-8 8" />,
  copy: <><rect x="5.4" y="5.4" width="7.6" height="7.6" rx="1.6" /><path d="M10.6 5.4V4a1.4 1.4 0 0 0-1.4-1.4H4A1.4 1.4 0 0 0 2.6 4v5.2A1.4 1.4 0 0 0 4 10.6h1.4" /></>,
  check: <path d="m3.4 8.4 3 3 6.2-6.8" />,
  trash: <><path d="M3 4.6h10M6.4 4.6V3.2h3.2v1.4" /><path d="m4.2 4.6.6 8.2h6.4l.6-8.2" /></>,
  file: <><path d="M4 2.5h5l3 3v8H4v-11Z" /><path d="M9 2.5v3h3" /></>,
  refresh: <><path d="M13 8a5 5 0 1 1-1.6-3.7" /><path d="M13 2.8v2.6h-2.6" /></>,
  maximize: <><path d="M10 2.6h3.4V6" /><path d="M6 13.4H2.6V10" /><path d="m13.2 2.8-4 4" /><path d="m2.8 13.2 4-4" /></>,
  minimize: <><path d="M13.4 6H10V2.6" /><path d="M2.6 10H6v3.4" /><path d="m13.2 2.8-4 4" /><path d="m2.8 13.2 4-4" /></>,
  alert: <><path d="M8 2.4 14 13H2L8 2.4Z" /><path d="M8 6.6v3" /><path d="M8 11.4v.1" /></>,
};

export function Icon({ name }: { name: keyof typeof PATHS | string }) {
  return <svg class="i" viewBox="0 0 16 16" aria-hidden="true">{PATHS[name]}</svg>;
}
