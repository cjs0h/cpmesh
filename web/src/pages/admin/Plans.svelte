<script lang="ts">
  import { onMount } from 'svelte';
  import { userState } from '../../lib/stores/user.svelte';
  import { adminState, fetchAdminPlans, adminCreatePlan, adminUpdatePlan, adminDeletePlan, type SubscriptionPlan } from '../../lib/stores/admin.svelte';
  import { toast } from '../../lib/stores/toast.svelte';
  import { push } from 'svelte-spa-router';
  import { titleCase } from '../../lib/format';
  import Icon from '../../components/Icon.svelte';
  import Badge from '../../components/ui/Badge.svelte';
  import Button from '../../components/ui/Button.svelte';
  import Card from '../../components/ui/Card.svelte';
  import ConfirmAction from '../../components/ui/ConfirmAction.svelte';
  import Dialog from '../../components/ui/Dialog.svelte';
  import Field from '../../components/ui/Field.svelte';
  import Select from '../../components/ui/Select.svelte';
  import Switch from '../../components/ui/Switch.svelte';
  import EmptyState from '../../components/ui/EmptyState.svelte';
  import Alert from '../../components/ui/Alert.svelte';

  let dialogOpen = $state(false);
  let editing = $state<SubscriptionPlan | null>(null);
  let error = $state('');
  let saving = $state(false);

  let formName = $state('');
  let formDescription = $state('');
  let formPrice = $state<number | null>(0);
  let formCurrency = $state('USD');
  let formBillingPeriod = $state('monthly');
  let formMaxDevices = $state<number | null>(5);
  let formMaxHistory = $state<number | null>(100);
  let formFileTypes = $state('');
  let formIsActive = $state(true);
  let formSortOrder = $state<number | null>(0);

  onMount(() => {
    if (!userState.isAdmin) {
      push('/');
      return;
    }
    fetchAdminPlans();
  });

  const sorted = $derived([...adminState.plans].sort((a, b) => a.sort_order - b.sort_order || a.name.localeCompare(b.name)));

  function startCreate() {
    editing = null;
    formName = '';
    formDescription = '';
    formPrice = 0;
    formCurrency = 'USD';
    formBillingPeriod = 'monthly';
    formMaxDevices = 5;
    formMaxHistory = 100;
    formFileTypes = '';
    formIsActive = true;
    formSortOrder = adminState.plans.length;
    error = '';
    dialogOpen = true;
  }

  function startEdit(plan: SubscriptionPlan) {
    editing = plan;
    formName = plan.name;
    formDescription = plan.description;
    formPrice = plan.price;
    formCurrency = plan.currency;
    formBillingPeriod = plan.billing_period;
    formMaxDevices = plan.max_devices;
    formMaxHistory = plan.max_clipboard_history;
    formFileTypes = plan.allowed_file_types.join(', ');
    formIsActive = plan.is_active;
    formSortOrder = plan.sort_order;
    error = '';
    dialogOpen = true;
  }

  function parseFileTypes(str: string): string[] {
    return str.split(',').map((s) => s.trim()).filter(Boolean);
  }

  async function handleSave(e: Event) {
    e.preventDefault();
    error = '';
    saving = true;
    const data = {
      name: formName.trim(),
      description: formDescription.trim(),
      price: Number(formPrice ?? 0),
      currency: formCurrency,
      billing_period: formBillingPeriod,
      max_devices: Number(formMaxDevices ?? 1),
      max_clipboard_history: Number(formMaxHistory ?? 1),
      allowed_file_types: parseFileTypes(formFileTypes),
      is_active: formIsActive,
      sort_order: Number(formSortOrder ?? 0),
    };
    try {
      if (editing) {
        await adminUpdatePlan(editing.id, data);
        toast.success('Plan updated', `${data.name} was saved.`);
      } else {
        await adminCreatePlan(data);
        toast.success('Plan created', `${data.name} is ready to assign.`);
      }
      dialogOpen = false;
    } catch (err: any) {
      error = err.message;
    } finally {
      saving = false;
    }
  }

  async function handleDelete(plan: SubscriptionPlan) {
    try {
      await adminDeletePlan(plan.id);
      toast.success('Plan deleted', `${plan.name} was removed.`);
    } catch (err: any) {
      toast.error('Could not delete plan', err.message);
    }
  }

  function price(plan: SubscriptionPlan): string {
    if (plan.price === 0) return 'Free';
    return `${plan.currency} ${plan.price.toFixed(2)}`;
  }
</script>

<div class="mb-4 flex flex-wrap items-center justify-between gap-3">
  <div class="flex items-center gap-2">
    <Badge tone="neutral">{adminState.plans.length} plans</Badge>
    <Badge tone="mint">{adminState.plans.filter((p) => p.is_active).length} active</Badge>
  </div>
  <Button icon="plus" size="sm" onclick={startCreate}>New plan</Button>
</div>

{#if sorted.length === 0}
  <EmptyState icon="star" title="No plans yet" description="Plans define how many devices and clipboard entries a user can have. Create one, then assign it from the Users page.">
    <Button icon="plus" size="sm" onclick={startCreate}>Create the first plan</Button>
  </EmptyState>
{:else}
  <div class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
    {#each sorted as plan (plan.id)}
      <article class="group relative flex flex-col rounded-lg border border-border bg-surface p-5 transition-[border-color,box-shadow] duration-150 hover:border-border-strong hover:shadow-sm {plan.is_active ? '' : 'opacity-70'}">
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0">
            <div class="flex items-center gap-2">
              <h3 class="truncate text-base font-semibold tracking-tight text-fg">{plan.name}</h3>
              {#if !plan.is_active}<Badge tone="neutral">Inactive</Badge>{/if}
            </div>
            {#if plan.description}<p class="mt-0.5 line-clamp-2 text-[13px] text-muted">{plan.description}</p>{/if}
          </div>
          <span class="font-mono text-[11px] text-dim">#{plan.sort_order}</span>
        </div>

        <div class="mt-4 flex items-baseline gap-1.5">
          <span class="text-3xl font-semibold tracking-tight text-fg">{price(plan)}</span>
          {#if plan.price > 0}<span class="text-[12.5px] text-dim">/ {plan.billing_period === 'lifetime' ? 'once' : plan.billing_period.replace('ly', '')}</span>{/if}
        </div>

        <dl class="mt-5 grid grid-cols-2 gap-2 text-[13px]">
          <div class="rounded-md border border-border bg-bg-deep px-3 py-2">
            <dt class="flex items-center gap-1 text-xs text-muted"><Icon name="monitor" size={11} /> Devices</dt>
            <dd class="mt-0.5 font-medium text-fg">{plan.max_devices}</dd>
          </div>
          <div class="rounded-md border border-border bg-bg-deep px-3 py-2">
            <dt class="flex items-center gap-1 text-xs text-muted"><Icon name="history" size={11} /> History</dt>
            <dd class="mt-0.5 font-medium text-fg">{plan.max_clipboard_history.toLocaleString()}</dd>
          </div>
        </dl>

        <div class="mt-3 flex flex-wrap gap-1.5">
          {#if plan.allowed_file_types.length === 0}
            <Badge tone="cyan" icon="check">All content types</Badge>
          {:else}
            {#each plan.allowed_file_types as t (t)}<Badge tone="neutral">{titleCase(t)}</Badge>{/each}
          {/if}
        </div>

        <div class="mt-auto flex items-center justify-between pt-5">
          <Button variant="outline" size="xs" icon="edit" onclick={() => startEdit(plan)}>Edit</Button>
          <ConfirmAction size="xs" label="Delete" confirmLabel="Delete" prompt="Delete plan?" onconfirm={() => handleDelete(plan)} />
        </div>
      </article>
    {/each}
  </div>
{/if}

<Dialog bind:open={dialogOpen} title={editing ? `Edit ${editing.name}` : 'New plan'} description="Limits apply immediately to every user on this plan." size="lg">
  <form id="plan-form" class="grid grid-cols-1 gap-4 sm:grid-cols-2" onsubmit={handleSave}>
    {#if error}<div class="sm:col-span-2"><Alert tone="danger">{error}</Alert></div>{/if}
    <Field label="Name" bind:value={formName} required placeholder="Pro" />
    <Field label="Sort order" type="number" bind:value={formSortOrder} hint="Lower numbers show first" />
    <Field label="Description" bind:value={formDescription} placeholder="For power users with many devices" class="sm:col-span-2" />
    <Field label="Price" type="number" bind:value={formPrice} step="0.01" min="0" />
    <Select label="Currency" bind:value={formCurrency}>
      <option value="USD">USD</option>
      <option value="EUR">EUR</option>
      <option value="GBP">GBP</option>
    </Select>
    <Select label="Billing period" bind:value={formBillingPeriod}>
      <option value="monthly">Monthly</option>
      <option value="yearly">Yearly</option>
      <option value="lifetime">Lifetime</option>
    </Select>
    <div></div>
    <Field label="Max devices" type="number" bind:value={formMaxDevices} min="1" required />
    <Field label="Max clipboard history" type="number" bind:value={formMaxHistory} min="1" required />
    <Field label="Allowed file types" bind:value={formFileTypes} placeholder="text, image, file" hint="Comma-separated; leave empty to allow everything" class="sm:col-span-2" />
    <div class="sm:col-span-2">
      <Switch bind:checked={formIsActive} label="Active" description="Inactive plans stay assigned but can't be chosen for new users." />
    </div>
  </form>
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (dialogOpen = false)}>Cancel</Button>
    <Button type="submit" form="plan-form" loading={saving}>{editing ? 'Save changes' : 'Create plan'}</Button>
  {/snippet}
</Dialog>
