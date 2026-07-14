import { apiToken } from './token';
import { reportError } from './errors';
import type {
	AddFriendResult,
	CeremonyAbortResult,
	CeremonyApproveResult,
	CeremonyOpenResult,
	DiscloseResult,
	ExtendResult,
	FetchGrantResult,
	FriendsList,
	PlaceReplicasResult,
	PublishedVault,
	ReplicaMembers,
	SplitResult,
	StatusSnapshot,
	Ticket,
	RecoveryScope,
	ResplitStatus,
	UnfriendResult
} from './types';

/** Everything talks to the same origin the GUI was served from. */
const BASE = '';

class ApiClientError extends Error {
	constructor(
		message: string,
		public status?: number
	) {
		super(message);
	}
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
	let res: Response;
	try {
		res = await fetch(BASE + path, {
			...init,
			headers: {
				...(init?.body ? { 'Content-Type': 'application/json' } : {}),
				Authorization: `Bearer ${apiToken()}`,
				...init?.headers
			}
		});
	} catch (e) {
		const msg = `Could not reach the daemon (${path}). Is it running? (${(e as Error).message})`;
		reportError(msg);
		throw new ApiClientError(msg);
	}

	if (res.status === 401 || res.status === 403) {
		const msg =
			res.status === 401
				? 'The daemon rejected this session (bad or missing token). Reload the page.'
				: 'The daemon refused this request (Host/Origin guard). Reload the page.';
		reportError(msg);
		throw new ApiClientError(msg, res.status);
	}

	if (!res.ok) {
		let detail = res.statusText;
		try {
			const body = await res.json();
			if (typeof body?.error === 'string') detail = body.error;
		} catch {
			// non-JSON error body: keep statusText
		}
		reportError(`${path} failed: ${detail}`);
		throw new ApiClientError(detail, res.status);
	}

	return (await res.json()) as T;
}

/** Like `request` but returns the raw response body as text (for non-JSON endpoints,
 *  e.g. the printable paper-card HTML). Shares the same auth headers + error handling. */
async function requestText(path: string, init?: RequestInit): Promise<string> {
	let res: Response;
	try {
		res = await fetch(BASE + path, {
			...init,
			headers: {
				Authorization: `Bearer ${apiToken()}`,
				...init?.headers
			}
		});
	} catch (e) {
		const msg = `Could not reach the daemon (${path}). Is it running? (${(e as Error).message})`;
		reportError(msg);
		throw new ApiClientError(msg);
	}

	if (res.status === 401 || res.status === 403) {
		const msg =
			res.status === 401
				? 'The daemon rejected this session (bad or missing token). Reload the page.'
				: 'The daemon refused this request (Host/Origin guard). Reload the page.';
		reportError(msg);
		throw new ApiClientError(msg, res.status);
	}

	if (!res.ok) {
		let detail = res.statusText;
		try {
			const body = await res.json();
			if (typeof body?.error === 'string') detail = body.error;
		} catch {
			// non-JSON error body: keep statusText
		}
		reportError(`${path} failed: ${detail}`);
		throw new ApiClientError(detail, res.status);
	}

	return res.text();
}

const get = <T>(path: string) => request<T>(path);
const post = <T>(path: string, body?: unknown) =>
	request<T>(path, { method: 'POST', body: body !== undefined ? JSON.stringify(body) : undefined });

export const api = {
	health: () => get<{ ok: boolean }>('/api/health'),
	status: () => get<StatusSnapshot>('/api/status'),

	listVaults: () => get<{ published: PublishedVault[] }>('/api/vaults'),
	publishVault: (dir: string, vid?: string) =>
		post<{ vid: string; epoch: number }>('/api/vaults', { dir, vid }),

	listReplicas: (vid: string) => get<ReplicaMembers>(`/api/vaults/${vid}/replicas`),
	placeReplicas: (vid: string, peers: { node: string; addrs: string[] }[], r: number) =>
		post<PlaceReplicasResult>(`/api/vaults/${vid}/replicas`, { peers, r }),

	discloseFiles: (vid: string, paths: string[], audience: string[]) =>
		post<DiscloseResult>(`/api/vaults/${vid}/grants`, { paths, audience }),
	fetchGrant: (
		grant_hex: string,
		owner: { node: string; addrs: string[] },
		out_dir: string
	) => post<FetchGrantResult>('/api/grants/fetch', { grant_hex, owner, out_dir }),

	listFriends: () => get<FriendsList>('/api/friends'),
	issueTicket: () => post<Ticket>('/api/friends/ticket'),
	addFriend: (ticket_hex: string, addrs?: string[], grant_bytes?: number) =>
		post<AddFriendResult>('/api/friends', { ticket_hex, addrs, grant_bytes }),
	unfriend: (user_pubkey: string) =>
		post<UnfriendResult>(`/api/friends/${user_pubkey}/unfriend`),
	resplitStatus: (rsid: number) => get<ResplitStatus>(`/api/recovery/${rsid}/resplit-status`),
	// W15 (§8, §10.2): printable paper cards for one owned recovery set. Returns raw HTML
	// (share WORDS - a bearer secret) the caller opens in a print view, never JSON.
	paperCards: (rsid: number) => requestText(`/api/recovery/${rsid}/paper`),
	// §9.3.4: start the re-split the PROMPT was raised for; omit trustees to use the suggested set.
	resplitStart: (rsid: number, trustees?: string[]) =>
		post<ResplitStatus>(`/api/recovery/${rsid}/resplit-start`, trustees ? { trustees } : undefined),

	recoverySplit: (
		rsid: number,
		scope: RecoveryScope,
		m: number,
		n: number,
		allow_over_cap?: boolean
	) => post<SplitResult>('/api/recovery/split', { rsid, scope, m, n, allow_over_cap }),
	recoveryResplit: (
		rsid: number,
		scope: RecoveryScope,
		m: number,
		n: number,
		allow_over_cap?: boolean
	) => post<SplitResult>('/api/recovery/resplit', { rsid, scope, m, n, allow_over_cap }),
	recoveryExtend: (rsid: number, count: number, allow_over_cap?: boolean) =>
		post<ExtendResult>('/api/recovery/extend', { rsid, count, allow_over_cap }),

	ceremonyOpen: (req: {
		subject: string;
		claimant_display: string;
		ceremony_enc: string;
		new_node: string;
		reason: string;
	}) => post<CeremonyOpenResult>('/api/recovery/ceremony/open', req),
	ceremonyApprove: (ceremony_id: string) =>
		post<CeremonyApproveResult>('/api/recovery/ceremony/approve', { ceremony_id }),
	ceremonyAbort: (ceremony_id: string) =>
		post<CeremonyAbortResult>('/api/recovery/ceremony/abort', { ceremony_id })
};
