export const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;
export const MAX_SIGMA_BYTES = 64 * 1024;

export function number(value: number): string {
  return new Intl.NumberFormat('en-US', { maximumFractionDigits: 20 }).format(value);
}

export function utc(value: string | null | undefined, timeOnly = false): string {
  if (!value) return '—';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return value;
  const precise = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}(?:\.\d+)?)(?:Z|\+00:00)$/i.exec(value);
  if (precise) return timeOnly ? precise[2] : `${precise[1]} ${precise[2]}`;
  const iso = date.toISOString();
  const time = iso.slice(11, 23).replace(/\.000$/, '');
  return timeOnly ? time : `${iso.slice(0, 10)} ${time}`;
}

export function duration(seconds: number): string {
  if (seconds === 0) return '0 s';
  return `${new Intl.NumberFormat('en-US', { maximumFractionDigits: 4 }).format(seconds)} s`;
}

export function label(value: string): string {
  return value.replace(/[_-]+/g, ' ').replace(/^\w/, (letter) => letter.toUpperCase());
}

export function pretty(value: unknown): string {
  return typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}

export function safeUrl(value?: string | null): string | undefined {
  if (!value) return undefined;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : undefined;
  } catch {
    return undefined;
  }
}

export function utcInput(value: string): string {
  return value ? value.replace(/Z$/, '').slice(0, 19) : '';
}

export function fromUtcInput(value: string): string {
  if (!value) return '';
  return `${value.length === 16 ? `${value}:00` : value}Z`;
}

function byteLimitLabel(bytes: number): string {
  return bytes >= 1024 * 1024
    ? `${number(bytes / (1024 * 1024))} MiB`
    : `${number(bytes / 1024)} KiB`;
}

export async function readTextFile(
  file: File,
  extensions: string[],
  maxBytes = MAX_UPLOAD_BYTES,
): Promise<string> {
  if (file.size > maxBytes)
    throw new Error(`This file exceeds the ${byteLimitLabel(maxBytes)} limit.`);
  const extension = file.name.slice(file.name.lastIndexOf('.')).toLowerCase();
  if (!extensions.includes(extension)) {
    throw new Error(`Unsupported file type. Choose ${extensions.join(', ')}.`);
  }
  try {
    return await file.text();
  } catch {
    throw new Error('The file could not be read. Select it again or paste its text.');
  }
}

export function validateContent(content: string, maxBytes = MAX_UPLOAD_BYTES): void {
  if (!content.trim()) throw new Error('Choose a file or paste content before continuing.');
  if (new TextEncoder().encode(content).byteLength > maxBytes) {
    throw new Error(
      `Content exceeds the ${byteLimitLabel(maxBytes)} limit. Reduce its size before submitting.`,
    );
  }
}

export function downloadJson(value: unknown, filename: string): void {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
