export class SafeHtml {
  public constructor(public readonly value: string) {}

  public toString(): string {
    return this.value;
  }
}

export const escapeHtml = (value: string): string =>
  value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const render = (value: unknown): string => {
  if (value === null || value === undefined || value === false) return "";
  if (value instanceof SafeHtml) return value.value;
  if (Array.isArray(value)) return value.map(render).join("");
  if (value instanceof Date) return escapeHtml(value.toISOString());
  return escapeHtml(String(value));
};

// Tagged template: every interpolated value is escaped unless it is already SafeHtml.
export const html = (
  strings: TemplateStringsArray,
  ...values: unknown[]
): SafeHtml => {
  let out = strings[0];
  values.forEach((value, i) => {
    out += render(value) + strings[i + 1];
  });
  return new SafeHtml(out);
};

export const raw = (value: string): SafeHtml => new SafeHtml(value);

export const ADMIN_UI_PATH = "/_admin";

export const adminUrl = (...segments: string[]): string =>
  [ADMIN_UI_PATH, ...segments.map(encodeURIComponent)].join("/");

export const withQuery = (
  url: string,
  params: Record<string, string | undefined>,
): string => {
  const query = new URLSearchParams(
    Object.entries(params).filter(
      (entry): entry is [string, string] => !!entry[1],
    ),
  ).toString();
  return query ? `${url}?${query}` : url;
};

const STYLES = `
:root{--bg:#f6f7f9;--panel:#fff;--text:#1d2330;--muted:#5d6678;--border:#dfe3ea;--accent:#2557d6;--accent-soft:#e8eefc;--ok:#1f7a45;--ok-soft:#e3f4ea;--warn:#8a5a00;--warn-soft:#fdf1d8;--err:#b42318;--err-soft:#fde8e6;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--panel:#1a1f27;--text:#e6e9ef;--muted:#9aa3b5;--border:#2c333f;--accent:#7aa2ff;--accent-soft:#1f2b47;--ok:#5fd394;--ok-soft:#173326;--warn:#f0bf5a;--warn-soft:#3a2e12;--err:#ff8a80;--err-soft:#3d1c1a}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
header{background:var(--panel);border-bottom:1px solid var(--border)}
.bar{max-width:1200px;margin:0 auto;padding:10px 16px;display:flex;gap:20px;align-items:center;flex-wrap:wrap}
.brand{font-weight:700;color:var(--text)}
nav{display:flex;gap:4px;flex-wrap:wrap}
nav a{padding:6px 10px;border-radius:6px;color:var(--muted)}
nav a.active{background:var(--accent-soft);color:var(--accent);font-weight:600}
.notice{margin-left:auto;font-size:12px;color:var(--warn);background:var(--warn-soft);padding:3px 8px;border-radius:999px}
main{min-width:0;max-width:1200px;margin:0 auto;padding:20px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0 0 12px}
.sub{color:var(--muted);margin:0 0 20px}
.crumbs{font-size:13px;color:var(--muted);margin-bottom:8px}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:16px}
.grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);font-weight:600;white-space:nowrap}
tr:last-child td{border-bottom:0}
dl{display:grid;grid-template-columns:minmax(120px,max-content) 1fr;gap:6px 16px;margin:0}
dt{color:var(--muted)}dd{margin:0;word-break:break-word}
code,.mono{font-family:var(--mono);font-size:13px}
.code{font-family:var(--mono);font-size:18px;font-weight:700;letter-spacing:.08em}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;background:var(--accent-soft);color:var(--accent);white-space:nowrap}
.badge.ok{background:var(--ok-soft);color:var(--ok)}.badge.warn{background:var(--warn-soft);color:var(--warn)}.badge.err{background:var(--err-soft);color:var(--err)}.badge.muted{background:var(--bg);color:var(--muted)}
.chips{display:flex;gap:4px;flex-wrap:wrap}
.flash{padding:10px 14px;border-radius:8px;margin-bottom:16px}
.flash.ok{background:var(--ok-soft);color:var(--ok)}.flash.error{background:var(--err-soft);color:var(--err)}
form.inline{display:inline}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:end}
label{display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--muted)}
label.check{flex-direction:row;align-items:center;gap:6px;font-size:13px;color:var(--text)}
.row>label:not(.check){flex:1 1 180px;min-width:0}
.row>label:not(.check) input,.row>label:not(.check) select{width:100%}
input,select,textarea{max-width:100%;font:inherit;color:var(--text);background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:6px 8px;min-width:0}
textarea{width:100%;font-family:var(--mono);font-size:12px;min-height:120px}
button{font:inherit;cursor:pointer;border:1px solid var(--border);background:var(--panel);color:var(--text);border-radius:6px;padding:6px 12px}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.danger{color:var(--err);border-color:var(--err)}
button.link{border:0;background:none;color:var(--accent);padding:0 4px}
.muted{color:var(--muted)}.empty{color:var(--muted);padding:12px 0}
pre{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px;overflow:auto;font-family:var(--mono);font-size:12px;margin:0}
.check-ok{color:var(--ok)}.check-fail{color:var(--err)}
@media (max-width:640px){.notice{margin-left:0}th,td{padding:6px}}
`;

const SCRIPT = `
document.addEventListener('click',function(e){var b=e.target.closest('[data-copy]');if(!b)return;navigator.clipboard&&navigator.clipboard.writeText(b.getAttribute('data-copy'));var t=b.textContent;b.textContent='Copied';setTimeout(function(){b.textContent=t},900)});
document.addEventListener('submit',function(e){var m=e.target.getAttribute('data-confirm');if(m&&!confirm(m))e.preventDefault()});
function tick(){document.querySelectorAll('[data-expires]').forEach(function(el){var s=Math.round((Date.parse(el.getAttribute('data-expires'))-Date.now())/1000);el.textContent=s>0?Math.floor(s/60)+'m '+(s%60)+'s':'expired'})}
tick();setInterval(tick,1000);
var ar=document.getElementById('autorefresh');if(ar){var k='cognito-local-admin-autorefresh';try{ar.checked=localStorage.getItem(k)==='1'}catch(_){}ar.addEventListener('change',function(){try{localStorage.setItem(k,ar.checked?'1':'0')}catch(_){}});setInterval(function(){if(ar.checked)location.reload()},3000)}
`;

export type NavSection = "pools" | "codes" | "tokens" | "callback";

export interface Flash {
  ok?: string;
  error?: string;
}

export const layout = (opts: {
  title: string;
  active: NavSection;
  flash?: Flash;
  body: SafeHtml;
}): string =>
  html`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="robots" content="noindex" />
<title>${opts.title} · Cognito Local admin</title>
<style>${raw(STYLES)}</style>
</head>
<body>
<header><div class="bar">
  <a class="brand" href="${ADMIN_UI_PATH}">Cognito Local admin</a>
  <nav>
    <a href="${ADMIN_UI_PATH}" class="${opts.active === "pools" ? "active" : ""}">User pools</a>
    <a href="${adminUrl("codes")}" class="${opts.active === "codes" ? "active" : ""}">Codes</a>
    <a href="${adminUrl("tokens")}" class="${opts.active === "tokens" ? "active" : ""}">Tokens</a>
    <a href="${adminUrl("callback")}" class="${opts.active === "callback" ? "active" : ""}">OAuth callback</a>
  </nav>
  <span class="notice" title="Disable with AdminUIConfig.Enabled=false or COGNITO_LOCAL_ADMIN_UI=false">No authentication: local development only</span>
</div></header>
<main>
${opts.flash?.ok ? html`<div class="flash ok" role="status">${opts.flash.ok}</div>` : ""}
${opts.flash?.error ? html`<div class="flash error" role="alert">${opts.flash.error}</div>` : ""}
${opts.body}
</main>
<script>${raw(SCRIPT)}</script>
</body>
</html>`.value;

export const copyButton = (value: string | undefined) =>
  value
    ? html`<button type="button" class="link" data-copy="${value}" aria-label="Copy">Copy</button>`
    : "";

export const statusBadge = (status: string | undefined) => {
  const kind =
    status === "CONFIRMED"
      ? "ok"
      : status === "UNCONFIRMED" || status === "FORCE_CHANGE_PASSWORD"
        ? "warn"
        : status === "RESET_REQUIRED" || status === "COMPROMISED"
          ? "err"
          : "muted";
  return html`<span class="badge ${kind}">${status ?? "UNKNOWN"}</span>`;
};

export const chips = (values: readonly string[] | undefined) =>
  values?.length
    ? html`<span class="chips">${values.map((v) => html`<span class="badge muted">${v}</span>`)}</span>`
    : html`<span class="muted">none</span>`;

export const formatDate = (value: Date | string | number | undefined) => {
  if (value === undefined || value === null) return "";
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime())
    ? String(value)
    : date
        .toISOString()
        .replace("T", " ")
        .replace(/\.\d+Z$/, "Z");
};
