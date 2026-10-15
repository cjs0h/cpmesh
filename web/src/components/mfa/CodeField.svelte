<script lang="ts">
  import { onMount } from 'svelte';
  import { normalizeOtp } from '../../lib/mfa';
  import Field from '../ui/Field.svelte';

  /** Input for a 6-digit one-time code; `oncomplete` fires once six digits are typed or pasted. */
  interface Props {
    value?: string;
    label?: string;
    hint?: string;
    error?: string;
    disabled?: boolean;
    autofocus?: boolean;
    oncomplete?: (code: string) => void;
  }

  let { value = $bindable(''), label = 'Code', hint, error, disabled = false, autofocus = false, oncomplete }: Props = $props();

  let wrapper = $state<HTMLDivElement | null>(null);

  onMount(() => {
    if (autofocus) wrapper?.querySelector('input')?.focus();
  });

  function handleInput(e: Event) {
    const digits = normalizeOtp((e.currentTarget as HTMLInputElement).value);
    if (digits.length === 6) oncomplete?.(digits);
  }
</script>

<div bind:this={wrapper}>
  <Field
    {label}
    {hint}
    {error}
    {disabled}
    bind:value
    oninput={handleInput}
    inputmode="numeric"
    autocomplete="one-time-code"
    maxlength={9}
    placeholder="000000"
    spellcheck={false}
    inputClass="font-mono text-base tracking-[0.3em]"
  />
</div>
