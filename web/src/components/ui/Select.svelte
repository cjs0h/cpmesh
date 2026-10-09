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
    <label for={selectId} class="flex items-center gap-1 text-[13px] font-medium text-fg">
      {label}
      {#if required}<span class="text-dim" aria-hidden="true">*</span>{/if}
    </label>
  {/if}
  <div class="relative">
    <select
      id={selectId}
      bind:value
      {required}
      class="h-10 w-full cursor-pointer appearance-none rounded-md border border-border bg-surface pl-3 pr-9 text-sm text-fg shadow-xs outline-none transition-[border-color,box-shadow] duration-150 hover:border-border-strong focus:border-ink focus:shadow-[0_0_0_3px_rgba(10,10,10,0.08)] disabled:cursor-not-allowed disabled:opacity-60 {selectClass}"
      {...rest}
    >
      {@render children()}
    </select>
    <span class="pointer-events-none absolute inset-y-0 right-3 flex items-center text-dim">
      <Icon name="chevrons-up-down" size={14} />
    </span>
  </div>
  {#if hint}<p class="text-xs text-dim">{hint}</p>{/if}
</div>
