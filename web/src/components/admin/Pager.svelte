<script lang="ts">
  import Button from '../ui/Button.svelte';

  /** Footer for a paginated table: the visible range, the total and previous/next. */
  interface Props {
    /** 1-based. */
    page: number;
    perPage: number;
    total: number;
    /** e.g. "users"; shown after the total. */
    noun?: string;
    loading?: boolean;
    onpage: (page: number) => void;
  }

  let { page, perPage, total, noun = '', loading = false, onpage }: Props = $props();

  const pages = $derived(Math.max(1, Math.ceil(total / perPage)));
  const from = $derived(total === 0 ? 0 : (page - 1) * perPage + 1);
  const to = $derived(Math.min(total, page * perPage));
</script>

<nav class="flex flex-col gap-2 border-t border-border bg-bg-deep px-5 py-3 text-[13px] text-muted sm:flex-row sm:items-center sm:justify-between" aria-label="Pagination">
  <p class="tabular-nums">
    {#if total === 0}
      No {noun || 'results'}
    {:else}
      <span class="font-medium text-fg">{from.toLocaleString()}–{to.toLocaleString()}</span> of
      <span class="font-medium text-fg">{total.toLocaleString()}</span>{noun ? ` ${noun}` : ''}
    {/if}
  </p>
  {#if pages > 1}
    <div class="flex items-center gap-2">
      <span class="mr-1 text-xs text-dim tabular-nums">Page {page} of {pages}</span>
      <Button variant="outline" size="xs" icon="chevron-left" disabled={page <= 1 || loading} onclick={() => onpage(page - 1)}>Previous</Button>
      <Button variant="outline" size="xs" iconRight="chevron-right" disabled={page >= pages || loading} onclick={() => onpage(page + 1)}>Next</Button>
    </div>
  {/if}
</nav>
