import type { PluginContext } from "./types";

function object(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name}无效`);
  return value as Record<string, unknown>;
}

/** Parse the host context into the surface this frontend renders: the workspace panel or the settings page. */
export function parseContext(value: unknown): PluginContext {
  const root = object(value, "插件上下文");
  if (root.kind === "settings-page") return { kind: "settings-page" };
  if (root.kind === "workspace-tool") {
    const workspace = object(root.workspace, "工作区绑定");
    return {
      kind: "workspace-tool",
      visible: root.visible !== false,
      workspace: {
        mode: workspace.mode === "observe" ? "observe" : "interactive",
        dock: workspace.dock === "bottom" ? "bottom" : "side",
        canAddComposerReference: workspace.canAddComposerReference === true,
      },
    };
  }
  throw new Error("插件上下文类型无效");
}
