import { escapeHtml } from "../oauth2/html";

export const PRODUCT_NAME = "cognito-emulator";
export const PRODUCT_TAGLINE = "Local Amazon Cognito emulator, not AWS";
export const ADMIN_UI_PATH = "/_admin";
export const ADMIN_CODES_PATH = `${ADMIN_UI_PATH}/codes`;

/** Marks every page the emulator serves to a browser; tests look for it. */
export const EMULATOR_BANNER_MARKER = 'data-emulator-banner=""';

// Logical properties and flex gaps only, so the strip reads correctly in a right-to-left page.
const BANNER_CSS = `
.ce-banner{background:#1e2533;color:#f3f5f9;font:13px/1.4 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;border-block-end:3px solid #f2b631}
.ce-banner-inner{max-width:1200px;margin:0 auto;padding-block:7px;padding-inline:16px;display:flex;flex-wrap:wrap;align-items:center;gap:4px 12px}
.ce-banner .ce-banner-name{color:#fff;font-weight:700;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.ce-banner-tag{color:#d3d9e4}
.ce-banner-links{display:flex;gap:12px;margin-inline-start:auto}
.ce-banner a{color:#a9c4ff;padding:0;border-radius:0;background:none;text-decoration:none}
.ce-banner a:hover{text-decoration:underline}
.ce-banner a:focus-visible{outline:2px solid #f2b631;outline-offset:2px}
`;

/** The banner's stylesheet, for the page's head. */
export const emulatorBannerStyle = (): string => `<style>${BANNER_CSS}</style>`;

/** The strip every browser page opens with: names the emulator and links its admin UI. */
export const emulatorBanner = (): string =>
  `<header class="ce-banner" ${EMULATOR_BANNER_MARKER}>
<div class="ce-banner-inner">
  <a class="ce-banner-name" href="${ADMIN_UI_PATH}">${PRODUCT_NAME}</a>
  <span class="ce-banner-tag">${PRODUCT_TAGLINE}</span>
  <nav class="ce-banner-links" aria-label="${PRODUCT_NAME}">
    <a href="${ADMIN_UI_PATH}">Admin UI</a>
    <a href="${ADMIN_CODES_PATH}">Codes</a>
  </nav>
</div>
</header>`;

/** A complete branded page, for the emulator's own notices such as a disabled admin UI. */
export const emulatorNoticePage = (title: string, message: string): string =>
  `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><meta name="robots" content="noindex" /><title>${escapeHtml(title)} · ${PRODUCT_NAME}</title>${emulatorBannerStyle()}</head>
<body style="margin:0;font:14px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif">
${emulatorBanner()}
<main style="max-width:640px;margin:24px auto;padding-inline:16px">
<h1 style="font-size:20px">${escapeHtml(title)}</h1>
<p>${escapeHtml(message)}</p>
</main>
</body>
</html>`;
