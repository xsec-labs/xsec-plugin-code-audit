import { build } from "esbuild";
import { mkdir, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const output = resolve("com.xsec.desktop/frontend/index.js");
// The audit method version shown on the settings page comes from the vendored skill's pin.
const upstream = JSON.parse(await readFile(resolve("skills/security-audit/UPSTREAM.json"), "utf8"));
const activateDocumentation = `/**
 * Activate the Code Audit frontend and expose its host lifecycle.
 * @param {object} host Desktop host bridge for the active plugin surface.
 * @returns {object} Explicit mount, update, and dispose lifecycle delegates.
 */`;

// Factory reads this boundary statically, so preserve the named lifecycle source.
const frontendFooter = `${activateDocumentation}
export function activate(host){
  const controller=__xsecCodeAuditFrontend.activate(host);
  return{
    /**
     * Mount the active Code Audit surface into the supplied root and context.
     * @param {Element} root Host-owned element for the active surface.
     * @param {object} context Initial workspace-tool or settings-page context.
     * @returns {void} The delegated mount completes synchronously.
     */
    mount(root,context){return controller.mount(root,context)},
    /**
     * Update the active Code Audit surface with the next host context.
     * @param {object} context Current workspace-tool or settings-page context.
     * @returns {void} The delegated update completes synchronously.
     */
    update(context){return controller.update(context)},
    /**
     * Dispose subscriptions, timers, rendered content, and retained surface state.
     * @returns {void} The delegated cleanup completes synchronously.
     */
    dispose(){return controller.dispose()}
  };
}`;
await mkdir(dirname(output), { recursive: true });
await build({
  entryPoints: [resolve("frontend-src/entrypoint.tsx")],
  outfile: output,
  bundle: true,
  format: "iife",
  globalName: "__xsecCodeAuditFrontend",
  platform: "browser",
  target: ["es2022"],
  charset: "utf8",
  jsx: "automatic",
  jsxImportSource: "preact",
  loader: { ".css": "text" },
  define: {
    __SKILL_REF__: JSON.stringify(String(upstream.ref)),
    __SKILL_REPO__: JSON.stringify(String(upstream.repo)),
    __SKILL_LICENSE__: JSON.stringify(String(upstream.license)),
  },
  footer: { js: frontendFooter },
  legalComments: "none",
  minifyIdentifiers: false,
  minifySyntax: true,
  minifyWhitespace: true,
  sourcemap: false,
});
