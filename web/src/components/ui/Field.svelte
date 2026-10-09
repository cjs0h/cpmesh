<script lang="ts">
  import type { HTMLInputAttributes } from 'svelte/elements';
  import Icon from '../Icon.svelte';

  interface Props extends Omit<HTMLInputAttributes, 'value' | 'type'> {
    label?: string;
    hint?: string;
    error?: string;
    icon?: string;
    type?: 'text' | 'email' | 'password' | 'tel' | 'url' | 'search' | 'number';
    value?: string | number | null;
    required?: boolean;
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
    <label for={inputId} class="flex items-center gap-1 text-[13px] font-medium text-fg">
      {label}
      {#if required}<span class="text-dim" aria-hidden="true">*</span>{/if}
      {#if optional}<span class="ml-auto text-xs font-normal text-dim">Optional</span>{/if}
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
      class="h-10 w-full rounded-md border bg-surface text-sm text-fg shadow-xs outline-none transition-[border-color,box-shadow] duration-150 placeholder:text-dim
        focus:border-ink focus:shadow-[0_0_0_3px_rgba(10,10,10,0.08)]
        disabled:cursor-not-allowed disabled:bg-surface-2 disabled:opacity-70
        {icon ? 'pl-9' : 'pl-3'} {type === 'password' ? 'pr-10' : 'pr-3'}
        {error ? 'border-danger focus:border-danger focus:shadow-[0_0_0_3px_rgba(220,38,38,0.12)]' : 'border-border hover:border-border-strong'}
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
        <Icon name={revealed ? 'eye-off' : 'eye'} size={15} />
      </button>
    {/if}
  </div>

  {#if error}
    <p id="{inputId}-error" class="text-xs text-danger" role="alert">{error}</p>
  {:else if hint}
    <p id="{inputId}-hint" class="text-xs text-dim">{hint}</p>
  {/if}
</div>
