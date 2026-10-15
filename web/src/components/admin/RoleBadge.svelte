<script lang="ts">
  import Badge from '../ui/Badge.svelte';
  import { roleLabel } from '../../lib/stores/admin.svelte';

  /** A staff role as a badge; owners stand out, members read as a plain badge. */
  let { role, class: className = '' }: { role: string; class?: string } = $props();

  const tones: Record<string, 'ink' | 'cyan' | 'violet' | 'neutral'> = { owner: 'ink', admin: 'cyan', support: 'violet', viewer: 'neutral', user: 'neutral' };
</script>

<Badge tone={tones[role] ?? 'neutral'} icon={role === 'owner' ? 'star' : role === 'user' ? undefined : 'shield'} class={className}>{roleLabel(role)}</Badge>
