// Single prerendered shell; every view after that is client-side routed and
// driven by the loopback API, so there is nothing left for SSR to do.
export const prerender = true;
export const ssr = false;
