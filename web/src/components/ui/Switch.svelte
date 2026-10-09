<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { HTMLInputAttributes } from 'svelte/elements';

  interface Props extends Omit<HTMLInputAttributes, 'type' | 'checked'> {
    checked?: boolean;
    label?: string;
    description?: string;
    class?: string;
    children?: Snippet;
  }

  let { checked = $bindable(false), label, description, class: className = '', id, children, ...rest }: Props = $props();

  const uid = $props.id();
  const inputId = $derived(id ?? `switch-${uid}`);
</script>

<label for={inputId} class="flex cursor-pointer items-start gap-3 select-none {className}">
  <span class="relative mt-0.5 inline-flex h-7 w-12 shrink-0 items-center">
    <input id={inputId} type="checkbox" bind:checked class="peer sr-only" {...rest} />
    <span class="absolute inset-0 rounded-md border-2 border-ink bg-surface-3 shadow-xs transition-colors duration-200 peer-checked:bg-mint peer-focus-visible:outline-3 peer-focus-visible:outline-ink peer-focus-visible:outline-offset-2"></span>
    <span class="pointer-events-none absolute left-1 h-4 w-4 rounded-sm border-2 border-ink bg-ink transition-transform duration-200 ease-[var(--ease-spring)] peer-checked:translate-x-[22px] peer-checked:bg-cream"></span>
  </span>
  {#if label || description || children}
    <span class="flex flex-col">
      {#if label}<span class="text-sm font-semibold text-ink">{label}</span>{/if}
      {#if description}<span class="text-[12px] text-dim">{description}</span>{/if}
      {#if children}{@render children()}{/if}
    </span>
  {/if}
</label>
