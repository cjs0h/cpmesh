<script lang="ts">
  import type { HTMLInputAttributes } from 'svelte/elements';
  import Icon from '../Icon.svelte';

  interface Props extends Omit<HTMLInputAttributes, 'value' | 'type'> {
    label?: string;
    hint?: string;
    error?: string;
    /** Leading icon name. */
    icon?: string;
    type?: 'text' | 'email' | 'password' | 'tel' | 'url' | 'search' | 'number';
    value?: string | number | null;
    /** Marks the label with an asterisk. */
    required?: boolean;
    /** Appends "Optional" to the label. */
    optional?: boolean;
    class?: string;
    inputClass?: string;
  }

  let {
    label,
    hint,
    error,
    icon,
    type = 'text',
    value = $bindable(''),
    required = false,
    optional = false,
    class: className = '',
    inputClass = '',
    id,
    ...rest
  }: Props = $props();

  const uid = $props.id();
  const inputId = $derived(id ?? `field-${uid}`);
  let revealed = $state(false);
  const effectiveType = $derived(type === 'password' && revealed ? 'text' : type);
  const describedBy = $derived(error ? `${inputId}-error` : hint ? `${inputId}-hint` : undefined);
</script>

<div class="flex flex-col gap-1.5 {className}">
  {#if label}
    <label for={inputId} class="flex items-center gap-1 text-[13px] font-medium text-muted">
      {label}
      {#if required}<span class="text-accent" aria-hidden="true">*</span>{/if}
      {#if optional}<span class="ml-auto text-[11px] font-normal text-dim">Optional</span>{/if}
    </label>
  {/if}

  <div class="relative">
    {#if icon}
      <span class="pointer-events-none absolute inset-y-0 left-3 flex items-center text-dim">
        <Icon name={icon} size={15} />
      </span>
    {/if}

    <input
      id={inputId}
      type={effectiveType}
      bind:value
      {required}
      aria-invalid={error ? 'true' : undefined}
      aria-describedby={describedBy}
      class="h-10 w-full rounded-md border bg-surface-2 text-sm text-fg outline-none transition-[border-color,box-shadow,background-color] duration-150 placeholder:text-dim
        focus:border-accent focus:bg-surface-3 focus:shadow-[0_0_0_3px_rgba(255,122,89,0.18)]
        disabled:cursor-not-allowed disabled:opacity-60
        {icon ? 'pl-9' : 'pl-3.5'} {type === 'password' ? 'pr-10' : 'pr-3.5'}
        {error ? 'border-rose/60 focus:border-rose focus:shadow-[0_0_0_3px_rgba(248,113,113,0.18)]' : 'border-border hover:border-border-strong'}
        {inputClass}"
      {...rest}
    />

    {#if type === 'password'}
      <button
        type="button"
        class="absolute inset-y-0 right-0 flex w-10 items-center justify-center text-dim transition-colors hover:text-fg"
        aria-label={revealed ? 'Hide password' : 'Show password'}
        aria-pressed={revealed}
        tabindex="-1"
        onclick={() => (revealed = !revealed)}
      >
        <Icon name={revealed ? 'eye-off' : 'eye'} size={16} />
      </button>
    {/if}
  </div>

  {#if error}
    <p id="{inputId}-error" class="flex items-center gap-1 text-[12px] text-rose" role="alert">
      <Icon name="alert-circle" size={12} />
      {error}
    </p>
  {:else if hint}
    <p id="{inputId}-hint" class="text-[12px] text-dim">{hint}</p>
  {/if}
</div>
