<script lang="ts">
	let { class: className = '' }: { class?: string } = $props();
</script>

<div
	class="animate-[shimmer_1.6s_linear_infinite] rounded bg-[linear-gradient(90deg,var(--color-surface-2)_25%,var(--color-surface-3)_50%,var(--color-surface-2)_75%)] bg-[length:200%_100%] {className}"
	aria-hidden="true"
></div>
