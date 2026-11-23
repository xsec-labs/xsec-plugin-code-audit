import { render } from "preact";
import { parseContext } from "./context";
import { themeFacts } from "./lib/host";
import { SettingsApp, WorkspaceApp } from "./ui/app";
import { styles } from "./styles";
import type { Disposable, PluginContext, PluginHost } from "./types";

const THEME_TOKEN_NAME = /^[a-z0-9-]+$/iu;

/** Apply the host theme, plus the two facts it does not send: dark or light, and a readable colour on the accent. */
function applyTheme(theme: Record<string, string>): void {
  const html = document.documentElement;
  for (const [name, value] of Object.entries(theme)) {
    if (THEME_TOKEN_NAME.test(name)) html.style.setProperty(`--xsec-${name}`, value);
  }
  const facts = themeFacts(theme);
  html.dataset.mode = facts.dark ? "dark" : "light";
  html.style.colorScheme = facts.dark ? "dark" : "light";
  html.style.setProperty("--ca-on-primary", facts.onPrimary);
}

/** The bootstrap script writes the host theme to <html> before the module loads; read it back for the first paint. */
function themeFromDocument(): Record<string, string> {
  const style = document.documentElement.style;
  const theme: Record<string, string> = {};
  for (let i = 0; i < style.length; i++) {
    const name = style.item(i);
    if (name.startsWith("--xsec-")) theme[name.slice(7)] = style.getPropertyValue(name).trim();
  }
  return theme;
}

type Controller = {
  mount(root: HTMLElement, context: unknown): void;
  update(context: unknown): void;
  dispose(): void;
};

/** Activate the Code Audit frontend controller against the Desktop host bridge. */
export function activate(host: PluginHost): Controller {
  if (host.apiVersion !== 2) throw new Error(`不支持的 Frontend API：${host.apiVersion}`);
  let root: HTMLElement | undefined;
  let current: PluginContext | undefined;
  let theme: Disposable | undefined;
  let style: HTMLStyleElement | undefined;
  const draw = () => {
    if (!root || !current) return;
    render(
      current.kind === "settings-page"
        ? <SettingsApp host={host} />
        : <WorkspaceApp host={host} context={current} visible={current.visible} />,
      root,
    );
  };
  return {
    mount(nextRoot, context) {
      root = nextRoot;
      current = parseContext(context);
      style = document.createElement("style");
      style.dataset.xsecCodeAuditStyles = "";
      style.textContent = styles;
      root.before(style);
      applyTheme(themeFromDocument());
      theme = host.onTheme(applyTheme);
      draw();
    },
    update(context) {
      current = parseContext(context);
      draw();
    },
    dispose() {
      theme?.dispose();
      if (root) render(null, root);
      style?.remove();
      root = undefined;
      current = undefined;
    },
  };
}
