<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { HTMLButtonAttributes } from 'svelte/elements';
  import Icon from '../Icon.svelte';

  type Variant = 'primary' | 'accent' | 'secondary' | 'outline' | 'ghost' | 'danger' | 'danger-soft' | 'mint' | 'link';
  type Size = 'xs' | 'sm' | 'md' | 'lg' | 'icon' | 'icon-sm';

  interface Props extends HTMLButtonAttributes {
    variant?: Variant;
    size?: Size;
    loading?: boolean;
    /** Render as an anchor instead of a button. */
    href?: string;
    /** Open the link in a new tab (adds rel="noopener"). */
    external?: boolean;
    icon?: string;
    iconRight?: string;
    class?: string;
    children?: Snippet;
  }

  let {
    variant = 'primary',
    size = 'md',
    loading = false,
    href,
    external = false,
    icon,
    iconRight,
    class: className = '',
    children,
    disabled,
    type = 'button',
    ...rest
  }: Props = $props();

  const base =
    'inline-flex items-center justify-center gap-2 whitespace-nowrap select-none rounded-md font-medium ' +
    'transition-[background-color,border-color,color,box-shadow] duration-150 ' +
    'focus-visible:outline-2 focus-visible:outline-ink focus-visible:outline-offset-2 ' +
    'disabled:opacity-50 disabled:pointer-events-none';

  const variants: Record<Variant, string> = {
    primary: 'bg-ink text-white hover:bg-[#333]',
    accent: 'bg-accent text-white hover:bg-accent-hover',
    secondary: 'border border-border bg-surface text-fg shadow-xs hover:border-border-strong hover:bg-bg-deep',
    outline: 'border border-border bg-transparent text-fg hover:border-border-strong hover:bg-bg-deep',
    ghost: 'bg-transparent text-muted hover:bg-surface-2 hover:text-fg',
    danger: 'bg-danger text-white hover:bg-[#b91c1c]',
    'danger-soft': 'border border-red-200 bg-red-50 text-red-700 hover:bg-red-100',
    mint: 'bg-ink text-white hover:bg-[#333]',
    link: 'text-fg underline underline-offset-4 decoration-border-strong hover:decoration-fg',
  };

  const sizes: Record<Size, string> = {
    xs: 'h-7 px-2.5 text-xs',
    sm: 'h-8 px-3 text-[13px]',
    md: 'h-10 px-4 text-sm',
    lg: 'h-11 px-5 text-sm',
    icon: 'h-9 w-9 p-0',
    'icon-sm': 'h-8 w-8 p-0',
  };

  const iconSize = $derived(size === 'xs' ? 13 : size === 'sm' || size === 'icon-sm' ? 14 : 16);
  const classes = $derived([base, variants[variant], variant === 'link' ? '' : sizes[size], className].filter(Boolean).join(' '));
  const isDisabled = $derived(Boolean(disabled) || loading);
</script>

{#snippet content()}
  {#if loading}
    <Icon name="loader" size={iconSize} class="animate-[spin_0.8s_linear_infinite]" />
  {:else if icon}
    <Icon name={icon} size={iconSize} />
  {/if}
  {#if children}{@render children()}{/if}
  {#if iconRight && !loading}
    <Icon name={iconRight} size={iconSize} />
  {/if}
{/snippet}

{#if href}
  <a
    {href}
    class={classes}
    target={external ? '_blank' : undefined}
    rel={external ? 'noopener noreferrer' : undefined}
    aria-disabled={isDisabled || undefined}
    tabindex={isDisabled ? -1 : undefined}
    {...rest as Record<string, unknown>}
  >
    {@render content()}
  </a>
{:else}
  <button {type} class={classes} disabled={isDisabled} aria-busy={loading || undefined} {...rest}>
    {@render content()}
  </button>
{/if}
