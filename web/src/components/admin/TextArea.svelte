<script lang="ts">
  import type { HTMLTextareaAttributes } from 'svelte/elements';

  /** Multi-line counterpart of `Field`, with an optional character counter. */
  interface Props extends Omit<HTMLTextareaAttributes, 'value'> {
    label?: string;
    hint?: string;
    value?: string;
    /** Shows "used / max" and limits the input. */
    maxlength?: number;
    class?: string;
  }

  let { label, hint, value = $bindable(''), maxlength, class: className = '', id, rows = 3, ...rest }: Props = $props();

  const uid = $props.id();
  const inputId = $derived(id ?? `textarea-${uid}`);
</script>

<div class="flex flex-col gap-1.5 {className}">
  {#if label}<label for={inputId} class="text-[13px] font-medium text-fg">{label}</label>{/if}
  <textarea
    id={inputId}
    bind:value
    {rows}
    {maxlength}
    aria-describedby={hint ? `${inputId}-hint` : undefined}
    class="w-full resize-y rounded-md border border-border bg-surface px-3 py-2.5 text-sm text-fg shadow-xs outline-none transition-[border-color,box-shadow] duration-150 placeholder:text-dim hover:border-border-strong focus:border-ink focus:shadow-[0_0_0_3px_rgba(10,10,10,0.08)] disabled:cursor-not-allowed disabled:bg-surface-2 disabled:opacity-70"
    {...rest}
  ></textarea>
  {#if hint || maxlength}
    <div class="flex items-start justify-between gap-3 text-xs text-dim">
      <p id="{inputId}-hint">{hint ?? ''}</p>
      {#if maxlength}<span class="shrink-0 tabular-nums {(value ?? '').length >= maxlength ? 'text-warning' : ''}">{(value ?? '').length}/{maxlength}</span>{/if}
    </div>
  {/if}
</div>
