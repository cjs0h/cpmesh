<script lang="ts">
  import Icon from '../Icon.svelte';

  /** Small "copy to clipboard" button with transient success feedback. */
  let { text, label = 'Copy', size = 14, class: className = '' }: { text: string; label?: string; size?: number; class?: string } = $props();

  let copied = $state(false);
  let timer: ReturnType<typeof setTimeout> | null = null;

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => (copied = false), 1800);
    } catch {
      /* clipboard unavailable (insecure context) */
    }
  }
</script>

<button
  type="button"
  class="inline-flex items-center justify-center rounded p-1 transition-colors {copied ? 'text-mint' : 'text-dim hover:text-fg'} {className}"
  aria-label={copied ? 'Copied' : label}
  title={copied ? 'Copied' : label}
  onclick={copy}
>
  <Icon name={copied ? 'check' : 'copy'} {size} />
</button>
