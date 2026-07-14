// Wire shapes returned by carapace-api (crates/carapace-api/src/handlers.rs).
// Kept as plain interfaces mirroring the JSON exactly - no client-side renaming.

export interface StatusSnapshot {
	node_id: string;
	addr: string[];
	friends: { count: number; list: string[] };
	vaults: { published: PublishedVault[]; held_replicas: string[] };
	share_health: { recovery_sets_owned: number; shares_held: number };
	reachability: string;
	relay_networks: number;
	relay_diversity_warning: boolean;
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
	phase: string;
}

export interface CeremonyApproveResult {
	approvals: number;
}

export interface CeremonyAbortResult {
	abort_hex: string;
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
