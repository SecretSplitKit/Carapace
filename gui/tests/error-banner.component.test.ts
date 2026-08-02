import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import ErrorBanner from '$lib/components/ErrorBanner.svelte';
import { reportError } from '$lib/errors';

describe('ErrorBanner', () => {
	it('renders an accessible alert and dismisses it', async () => {
		reportError('The request failed safely.');
		render(ErrorBanner);
		expect(screen.getByRole('alert')).toHaveTextContent('The request failed safely.');
		await fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
		expect(screen.queryByRole('alert')).not.toBeInTheDocument();
	});
});
