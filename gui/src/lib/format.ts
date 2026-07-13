/** Truncate a hex id/hash to `head…tail` for display; the full value stays in `title`/copy. */
export function truncateHex(hex: string, head = 8, tail = 6): string {
	if (hex.length <= head + tail + 1) return hex;
	return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

export async function copyToClipboard(text: string): Promise<boolean> {
	try {
		await navigator.clipboard.writeText(text);
		return true;
	} catch {
		return false;
	}
}

const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];

export function formatBytes(bytes: number): string {
	if (!Number.isFinite(bytes) || bytes < 0) return '—';
	if (bytes === 0) return '0 B';
	const i = Math.min(Math.floor(Math.log2(bytes) / 10), UNITS.length - 1);
	const value = bytes / 2 ** (10 * i);
	return `${value >= 10 || i === 0 ? Math.round(value) : value.toFixed(1)} ${UNITS[i]}`;
}
