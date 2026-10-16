<script lang="ts">
	import Icon from './ui/Icon.svelte';

	/**
	 * The mesh at a glance: this device, the relay and the other devices, joined by
	 * beams. While live, light flows from this device through the relay to the
	 * others; each clip also runs once along the mesh: outward when copied here,
	 * inward when it arrives.
	 * Adapted from Magic UI's Animated Beam as SVG dashes driven by CSS keyframes.
	 */
	interface Props {
		state: 'connected' | 'connecting' | 'disconnected';
		deviceName: string;
		serverHost: string;
		onlineCount: number;
		deviceCount: number;
		/** A clip that just moved through the mesh; a new key replays the pulse. */
		pulse?: { key: string; direction: 'in' | 'out' } | null;
	}

	let { state, deviceName, serverHost, onlineCount, deviceCount, pulse = null }: Props = $props();

	const pulseKey = $derived(pulse?.key ?? null);
	const inward = $derived(pulse?.direction === 'in');

	const live = $derived(state === 'connected');
	const peers = $derived(Math.max(0, deviceCount - 1));
	const peersOnline = $derived(Math.max(0, onlineCount - (live ? 1 : 0)));
	const peerLabel = $derived(peers === 0 ? 'No other devices' : `${peers} other ${peers === 1 ? 'device' : 'devices'}`);
	// The device list is only current while connected
	const peerDetail = $derived(
		peers === 0 ? 'Add one from Devices' : live ? `${Math.min(peersOnline, peers)} online` : 'Status unknown',
	);
</script>

{#snippet light(inward: boolean, animation: string, thickness: number)}
	<!-- A streak with a fading tail behind its head, in the direction it travels -->
	<span
		class="absolute top-1/2 w-10 -translate-y-1/2 rounded-full from-transparent to-accent {inward ? 'bg-linear-to-l' : 'bg-linear-to-r'}"
		style="height: {thickness}px; left: -40px; animation: {inward ? 'beam-in' : 'beam-out'} {animation}"
	></span>
{/snippet}

{#snippet beam(position: 'left' | 'right')}
	<div class="relative mx-1 h-6 flex-1 overflow-hidden" aria-hidden="true">
		<svg class="absolute inset-0 h-full w-full overflow-visible" viewBox="0 0 100 24" preserveAspectRatio="none">
			<path
				d="M0 12 H100"
				pathLength="100"
				vector-effect="non-scaling-stroke"
				class="fill-none stroke-[1.5] transition-[stroke] duration-300 {live
					? 'stroke-border-strong'
					: state === 'connecting'
						? 'stroke-border-strong [stroke-dasharray:3_4]'
						: 'stroke-border [stroke-dasharray:3_4]'}"
			/>
		</svg>
		{#if live}
			<!-- While live, light flows from this device through the relay to the others -->
			{@render light(false, `2.6s ease-in-out ${position === 'right' ? '1.3s' : '0s'} infinite both`, 2)}
			{#key pulseKey}
				{#if pulseKey}
					<!-- Each clip runs once: inward from the peers when it arrives, outward when copied here -->
					{@const first = inward ? position === 'right' : position === 'left'}
					{@render light(inward, `1s var(--ease-out-expo) ${first ? '0s' : '0.45s'} 1 both`, 3)}
				{/if}
			{/key}
		{/if}
	</div>
{/snippet}

{#snippet node(icon: string, title: string, detail: string, emphasis: boolean, flash: boolean)}
	<div class="flex min-w-0 flex-1 basis-24 flex-col items-center text-center max-w-[132px]">
		{#key flash ? pulseKey : null}
			<div
				class="flex h-11 w-11 items-center justify-center rounded-xl border bg-surface shadow-xs transition-colors duration-300
					{emphasis ? 'border-ink text-fg' : 'border-border text-muted'}"
				style={flash && pulseKey ? 'animation: node-flash 0.9s var(--ease-out-expo) 0.7s 1' : undefined}
			>
				<Icon name={icon} size={19} strokeWidth={1.75} />
			</div>
		{/key}
		<p class="mt-2 w-full truncate text-[13px] font-medium text-fg" title={title}>{title}</p>
		<p class="w-full truncate text-xs text-muted" title={detail}>{detail}</p>
	</div>
{/snippet}

<div class="flex items-start" role="img" aria-label="{deviceName} — relay {serverHost} — {peerLabel}, {peerDetail}">
	{@render node('laptop', 'This device', deviceName || '—', true, inward)}
	<div class="flex min-w-12 flex-1 items-center pt-2.5">{@render beam('left')}</div>
	{@render node('server', 'Relay', serverHost || '—', live, false)}
	<div class="flex min-w-12 flex-1 items-center pt-2.5">{@render beam('right')}</div>
	{@render node('network', peerLabel, peerDetail, live && peersOnline > 0, !inward)}
</div>
