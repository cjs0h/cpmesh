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
  <span class="relative mt-0.5 inline-flex h-5 w-9 shrink-0 items-center">
    <input id={inputId} type="checkbox" bind:checked class="peer sr-only" {...rest} />
    <span class="absolute inset-0 rounded-full border border-border bg-surface-3 transition-colors duration-150 peer-checked:border-ink peer-checked:bg-ink peer-focus-visible:outline-2 peer-focus-visible:outline-ink peer-focus-visible:outline-offset-2"></span>
    <span class="pointer-events-none absolute left-0.5 h-4 w-4 rounded-full bg-white shadow-sm transition-transform duration-150 peer-checked:translate-x-4"></span>
  </span>
  {#if label || description || children}
    <span class="flex flex-col">
      {#if label}<span class="text-sm font-medium text-fg">{label}</span>{/if}
      {#if description}<span class="text-xs text-dim">{description}</span>{/if}
      {#if children}{@render children()}{/if}
    </span>
  {/if}
</label>
