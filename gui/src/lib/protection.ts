import type { Plate, RecoverySetStatus, RecoveryHealth } from './types';

export function recoveryPlate(sets: RecoverySetStatus[], health: RecoveryHealth[], connected: boolean): Plate {
	const roots = sets.filter((set) => set.scope.kind === 'root').map((set) => {
		const verified = health.find((item) => item.rsid === set.rsid);
		return { threshold: set.threshold, delivered: set.trustees.filter((t) => t.delivered).length,
			live: verified?.live ?? 0, target: verified?.target ?? set.threshold + 1 };
	});
	const weakest = roots.reduce<(typeof roots)[number] | undefined>((a, b) =>
		!a || Math.min(b.live, b.delivered) / b.target < Math.min(a.live, a.delivered) / a.target ? b : a, undefined);
	const healthy = connected && roots.length > 0 && roots.every((s) => s.live >= s.target && s.delivered >= s.target);
	return {
		key: 'shares', label: 'Recovery trustees', achieved: weakest ? Math.min(weakest.live, weakest.delivered) : 0,
		target: weakest?.target ?? 1, valueLabel: weakest ? `${weakest.live}/${weakest.target} verified` : 'Not set up',
		state: !connected ? 'at-risk' : roots.length === 0 ? 'empty' : healthy ? 'healthy' : 'at-risk',
		note: !connected ? 'Disconnected — protection cannot be confirmed' : weakest
			? `${weakest.threshold} trustees needed to recover; ${weakest.delivered} shares delivered. Rehearse a restore before relying on recovery.`
			: 'Choose trustees to protect your account',
	};
}
