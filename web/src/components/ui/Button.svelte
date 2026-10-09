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
    /** Adds a MagicUI-style sheen sweeping across the fill. */
    shine?: boolean;
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
    shine = false,
    class: className = '',
    children,
    disabled,
    type = 'button',
    ...rest
  }: Props = $props();

  // RetroUI button: ink border, hard shadow, lifts on hover and presses flat on click.
  const base =
    'relative inline-flex items-center justify-center gap-2 font-head whitespace-nowrap select-none rounded-md overflow-hidden ' +
    'transition-[background-color,border-color,color,box-shadow,transform] duration-200 ease-out ' +
    'focus-visible:outline-3 focus-visible:outline-ink focus-visible:outline-offset-2 ' +
    'disabled:opacity-60 disabled:pointer-events-none';

  const lift = 'shadow-md hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-lg active:translate-x-1 active:translate-y-1 active:shadow-none';

  const variants: Record<Variant, string> = {
    primary: `border-2 border-ink bg-yellow text-ink hover:bg-yellow-hover ${lift}`,
    accent: `border-2 border-ink bg-accent text-ink hover:bg-accent-hover ${lift}`,
    secondary: `border-2 border-ink bg-ink text-cream hover:bg-[#2a2a2a] ${lift}`,
    outline: `border-2 border-ink bg-surface text-ink hover:bg-surface-2 ${lift}`,
    ghost: 'border-2 border-transparent bg-transparent text-muted hover:border-ink hover:bg-surface-2 hover:text-ink',
    danger: `border-2 border-ink bg-rose text-ink hover:bg-[#ff7474] ${lift}`,
    'danger-soft': 'border-2 border-ink bg-rose/20 text-ink shadow-sm hover:bg-rose/40 hover:-translate-x-px hover:-translate-y-px hover:shadow-md active:translate-x-0.5 active:translate-y-0.5 active:shadow-none',
    mint: `border-2 border-ink bg-mint text-ink hover:bg-[#5ee8ab] ${lift}`,
    link: 'bg-transparent text-ink underline decoration-2 underline-offset-4 decoration-accent hover:decoration-ink',
  };

  const sizes: Record<Size, string> = {
    xs: 'h-7 px-2.5 text-[11px] tracking-wide',
    sm: 'h-9 px-3.5 text-[12.5px] tracking-wide',
    md: 'h-11 px-5 text-[13.5px] tracking-wide',
    lg: 'h-13 px-7 text-[15px] tracking-wide rounded-lg',
    icon: 'h-10 w-10 p-0',
    'icon-sm': 'h-8 w-8 p-0',
  };

  const iconSize = $derived(size === 'lg' ? 18 : size === 'xs' ? 13 : size === 'sm' || size === 'icon-sm' ? 15 : 16);
  const classes = $derived([base, variants[variant], variant === 'link' ? '' : sizes[size], shine ? 'btn-shine' : '', className].filter(Boolean).join(' '));
  const isDisabled = $derived(Boolean(disabled) || loading);
</script>

{#snippet content()}
  {#if loading}
    <Icon name="loader" size={iconSize} class="animate-[spin_0.8s_linear_infinite]" strokeWidth={2.5} />
  {:else if icon}
    <Icon name={icon} size={iconSize} strokeWidth={2.5} />
  {/if}
  {#if children}<span class="relative">{@render children()}</span>{/if}
  {#if iconRight && !loading}
    <Icon name={iconRight} size={iconSize} strokeWidth={2.5} />
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
