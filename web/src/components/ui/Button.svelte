<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { HTMLButtonAttributes } from 'svelte/elements';
  import Icon from '../Icon.svelte';

  type Variant = 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger' | 'danger-soft' | 'mint' | 'link';
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
    'inline-flex items-center justify-center gap-2 font-semibold whitespace-nowrap select-none rounded-md ' +
    'transition-[background-color,border-color,color,box-shadow,transform,filter] duration-200 ease-out ' +
    'focus-visible:outline-2 focus-visible:outline-accent focus-visible:outline-offset-2 ' +
    'disabled:opacity-50 disabled:pointer-events-none active:translate-y-px';

  const variants: Record<Variant, string> = {
    primary: 'btn-sunset shadow-glow hover:brightness-110 hover:-translate-y-0.5',
    secondary: 'bg-surface-3 text-fg border border-border-strong hover:bg-[#1f2e49] hover:border-[#36496c]',
    outline: 'bg-transparent text-muted border border-border hover:text-fg hover:border-border-strong hover:bg-white/[0.03]',
    ghost: 'bg-transparent text-muted hover:text-fg hover:bg-white/[0.05]',
    danger: 'bg-rose text-[#1f0a0a] hover:bg-[#ff8a8a] hover:-translate-y-0.5',
    'danger-soft': 'bg-rose/10 text-rose border border-rose/25 hover:bg-rose/15 hover:border-rose/45',
    mint: 'bg-[linear-gradient(135deg,#8df2d3,#2ad6a0_60%,#1fb888)] text-[#04221a] shadow-glow-mint hover:brightness-110 hover:-translate-y-0.5',
    link: 'bg-transparent text-accent hover:text-accent-hover hover:underline',
  };

  const sizes: Record<Size, string> = {
    xs: 'h-7 px-2.5 text-xs',
    sm: 'h-8 px-3 text-[13px]',
    md: 'h-10 px-4 text-sm',
    lg: 'h-12 px-6 text-[15px] rounded-lg',
    icon: 'h-9 w-9 p-0',
    'icon-sm': 'h-8 w-8 p-0',
  };

  const iconSize = $derived(size === 'lg' ? 18 : size === 'xs' ? 13 : size === 'sm' || size === 'icon-sm' ? 15 : 16);
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
