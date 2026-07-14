// Wire shapes returned by carapace-api (crates/carapace-api/src/handlers.rs).
// Kept as plain interfaces mirroring the JSON exactly - no client-side renaming.

export interface StatusSnapshot {
	node_id: string;
	addr: string[];
	friends: { count: number; list: string[] };
	vaults: { published: PublishedVault[]; held_replicas: string[] };
	share_health: { recovery_sets_owned: number; shares_held: number };
	// W5 (§9.3 step 4): open trustee re-splits after an unfriend, streamed live.
	resplits: ResplitStatus[];
	// §9.3.4: re-splits detected on unfriend but awaiting the user's prompt to start.
	pending_resplits: PendingResplit[];
	reachability: string;
	relay_networks: number;
	relay_diversity_warning: boolean;
}

/** One remaining friend's role + live reachability in a re-split (§9.3 step 4). */
export interface ResplitFriend {
	node: string;
	/** 'new' gets a fresh share; 'old' gets a destroy instruction. */
	role: 'new' | 'old';
	online: boolean;
	done: boolean;
	/** 'done' | 'online' (reachable, step pending) | 'will_queue' (offline, queued). */
	status: 'done' | 'online' | 'will_queue';
}

/** The §9.3 step-4 re-split surface for one unfriended trustee's recovery set. */
export interface ResplitStatus {
	old_rsid: number;
	new_rsid: number;
	ex_trustee: string;
	/** 'awaiting_new_set' | 'ready_to_destroy' | 'complete'. */
	phase: 'awaiting_new_set' | 'ready_to_destroy' | 'complete';
	new_attested: number;
	new_total: number;
	/** True once the new set reached M+slack attestations (the destroy gate). */
	new_set_live: boolean;
	old_destroyed: number;
	old_total: number;
	remaining: ResplitFriend[];
}

/** One suggested new-set trustee in a PendingResplit (§9.3.4): user pubkey, resolved
 *  node (if still a friend), and live reachability. */
export interface PendingTrustee {
	user: string;
	node: string | null;
	online: boolean;
}

/** The §9.3.4 PROMPT surface for one unfriend-detected, not-yet-started re-split. */
export interface PendingResplit {
	old_rsid: number;
	ex_trustee: string;
	/** Pre-filled default new trustee set (the old honest trustees). */
	suggested: PendingTrustee[];
}

export interface UnfriendResult {
	was_friend: boolean;
	resplit_triggered: boolean;
	recovery_set_ids: number[];
}

export interface PublishedVault {
	vid: string;
	epoch: number;
}

export interface FriendsList {
	count: number;
	list: string[];
}

export interface Ticket {
	uri: string;
	ticket_hex: string;
	node_id: string;
	addrs: string[];
}

export interface AddFriendResult {
	friend: string;
	established: number;
}

export interface ReplicaMembers {
	members: string[];
}

export interface PlaceReplicasResult {
	placed: string[];
}

export interface DiscloseResult {
	grant_hex: string;
}

export interface FetchGrantResult {
	written: string[];
}

export type RecoveryScope = { kind: 'root' } | { kind: 'vault'; vid: string };

export interface SplitResult {
	shares: string[];
	warnings: string[];
}

export interface ExtendResult {
	shares: string[];
}

export interface CeremonyOpenResult {
	ceremony_id: string;
	open_hex: string;
	fanout_reached: number;
}

export interface CeremonyApproveResult {
	approve_hex: string;
	broadcast_reached: number;
}

export interface CeremonyAbortResult {
	abort_hex: string;
	broadcast_reached: number;
}

/** A shell-integrity plate (ShellHero.svelte). */
export interface Plate {
	key: string;
	label: string;
	achieved: number;
	target: number;
	valueLabel: string;
	state: 'healthy' | 'at-risk' | 'empty';
	note: string;
}
