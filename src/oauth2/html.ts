// Escape untrusted values before interpolating them into HTML text or attributes.
export function escapeHtml(value: string | undefined | null): string {
  if (!value) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export const hiddenInput = (name: string, value: string | undefined) =>
  value === undefined
    ? ""
    : `  <input type="hidden" name="${name}" value="${escapeHtml(value)}" />\n`;
