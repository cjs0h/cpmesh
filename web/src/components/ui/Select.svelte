<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { HTMLSelectAttributes } from 'svelte/elements';
  import Icon from '../Icon.svelte';

  interface Props extends Omit<HTMLSelectAttributes, 'value'> {
    label?: string;
    hint?: string;
    value?: string | number | null;
    required?: boolean;
    class?: string;
    selectClass?: string;
    children: Snippet;
  }

  let { label, hint, value = $bindable(''), required = false, class: className = '', selectClass = '', id, children, ...rest }: Props = $props();

  const uid = $props.id();
  const selectId = $derived(id ?? `select-${uid}`);
</script>

<div class="flex flex-col gap-1.5 {className}">
  {#if label}
    <label for={selectId} class="flex items-center gap-1 font-head text-[12px] uppercase tracking-[0.06em] text-ink">
      {label}
      {#if required}<span class="text-accent" aria-hidden="true">*</span>{/if}
    </label>
  {/if}
  <div class="relative">
    <select
      id={selectId}
      bind:value
      {required}
      class="h-11 w-full cursor-pointer appearance-none rounded-md border-2 border-ink bg-surface pl-3.5 pr-10 text-sm text-ink shadow-xs outline-none transition-[box-shadow,transform,background-color] duration-150 focus:-translate-x-px focus:-translate-y-px focus:bg-cream focus:shadow-md disabled:cursor-not-allowed disabled:opacity-60 {selectClass}"
      {...rest}
    >
      {@render children()}
    </select>
    <span class="pointer-events-none absolute inset-y-0 right-0 flex w-10 items-center justify-center border-l-2 border-ink bg-yellow text-ink">
      <Icon name="chevrons-up-down" size={14} strokeWidth={2.5} />
    </span>
  </div>
  {#if hint}<p class="text-[12px] text-dim">{hint}</p>{/if}
</div>
