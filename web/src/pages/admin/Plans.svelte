<script lang="ts">
  import { userState } from '../../lib/stores/user.svelte';
  import {
    adminState,
    fetchAdminPlans,
    adminCreatePlan,
    adminUpdatePlan,
    adminDeletePlan,
    type SubscriptionPlan,
  } from '../../lib/stores/admin.svelte';
  import { push } from 'svelte-spa-router';

  let editing = $state<SubscriptionPlan | null>(null);
  let creating = $state(false);
  let error = $state('');
  let deleteConfirm = $state<string | null>(null);

  // Form fields
  let formName = $state('');
  let formDescription = $state('');
  let formPrice = $state(0);
  let formCurrency = $state('USD');
  let formBillingPeriod = $state('monthly');
  let formMaxDevices = $state(5);
  let formMaxHistory = $state(100);
  let formFileTypes = $state('');
  let formIsActive = $state(true);
  let formSortOrder = $state(0);

  $effect(() => {
    if (!userState.isAdmin) {
      push('/');
      return;
    }
    fetchAdminPlans();
  });

  function resetForm() {
    formName = '';
    formDescription = '';
    formPrice = 0;
    formCurrency = 'USD';
    formBillingPeriod = 'monthly';
    formMaxDevices = 5;
    formMaxHistory = 100;
    formFileTypes = '';
    formIsActive = true;
    formSortOrder = 0;
    error = '';
  }

  function startCreate() {
    resetForm();
    creating = true;
    editing = null;
  }

  function startEdit(plan: SubscriptionPlan) {
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
    editing = plan;
    creating = false;
    error = '';
  }

  function cancelForm() {
    creating = false;
    editing = null;
    error = '';
  }

  function parseFileTypes(str: string): string[] {
    if (!str.trim()) return [];
    return str.split(',').map((s) => s.trim()).filter(Boolean);
  }

  async function handleSave() {
    error = '';
    const data = {
      name: formName,
      description: formDescription,
      price: formPrice,
      currency: formCurrency,
      billing_period: formBillingPeriod,
      max_devices: formMaxDevices,
      max_clipboard_history: formMaxHistory,
      allowed_file_types: parseFileTypes(formFileTypes),
      is_active: formIsActive,
      sort_order: formSortOrder,
    };

    try {
      if (editing) {
        await adminUpdatePlan(editing.id, data);
      } else {
        await adminCreatePlan(data);
      }
      cancelForm();
    } catch (err: any) {
      error = err.message;
    }
  }

  async function handleDelete(id: string) {
    try {
      await adminDeletePlan(id);
      deleteConfirm = null;
    } catch (err: any) {
      error = err.message;
      deleteConfirm = null;
    }
  }
</script>

<div>
  <div class="flex items-center justify-between mb-5">
    <h2 class="text-xl font-semibold">Subscription Plans</h2>
    {#if !creating && !editing}
      <button class="inline-flex items-center gap-1.5 px-4 py-2 border-none rounded text-[13px] font-medium transition-all duration-150 bg-primary text-white hover:bg-primary-hover hover:shadow-primary" onclick={startCreate}>+ New Plan</button>
    {/if}
  </div>

  {#if error}
    <div class="flex items-center gap-2 bg-danger-glow border border-danger/30 text-danger px-3.5 py-2.5 rounded text-[13px] mb-4">{error}</div>
  {/if}

  {#if creating || editing}
    <div class="bg-bg-card border border-border rounded-xl p-6 mb-5">
      <h3 class="text-base font-semibold mb-4">{editing ? 'Edit Plan' : 'New Plan'}</h3>
      <form onsubmit={(e) => { e.preventDefault(); handleSave(); }}>
        <div class="grid grid-cols-2 gap-x-5 gap-y-3.5">
          <label class="flex flex-col gap-1.5">
            <span class="text-[13px] text-muted font-medium">Name *</span>
            <input type="text" bind:value={formName} required class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]" />
          </label>
          <label class="flex flex-col gap-1.5">
            <span class="text-[13px] text-muted font-medium">Price</span>
            <input type="number" bind:value={formPrice} step="0.01" min="0" class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]" />
          </label>
          <label class="flex flex-col gap-1.5">
            <span class="text-[13px] text-muted font-medium">Currency</span>
            <select bind:value={formCurrency} class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]">
              <option value="USD">USD</option>
              <option value="EUR">EUR</option>
              <option value="GBP">GBP</option>
            </select>
          </label>
          <label class="flex flex-col gap-1.5">
            <span class="text-[13px] text-muted font-medium">Billing Period</span>
            <select bind:value={formBillingPeriod} class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]">
              <option value="monthly">Monthly</option>
              <option value="yearly">Yearly</option>
              <option value="lifetime">Lifetime</option>
            </select>
          </label>
          <label class="flex flex-col gap-1.5">
            <span class="text-[13px] text-muted font-medium">Max Devices</span>
            <input type="number" bind:value={formMaxDevices} min="1" class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]" />
          </label>
          <label class="flex flex-col gap-1.5">
            <span class="text-[13px] text-muted font-medium">Max Clipboard History</span>
            <input type="number" bind:value={formMaxHistory} min="1" class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]" />
          </label>
          <label class="flex flex-col gap-1.5 col-span-full">
            <span class="text-[13px] text-muted font-medium">Description</span>
            <input type="text" bind:value={formDescription} class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]" />
          </label>
          <label class="flex flex-col gap-1.5 col-span-full">
            <span class="text-[13px] text-muted font-medium">Allowed File Types (comma-separated, empty = all)</span>
            <input type="text" bind:value={formFileTypes} placeholder="text, image, file" class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]" />
          </label>
          <label class="flex flex-col gap-1.5">
            <span class="text-[13px] text-muted font-medium">Sort Order</span>
            <input type="number" bind:value={formSortOrder} class="py-2.5 px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]" />
          </label>
          <label class="flex flex-row items-center gap-2 pt-6">
            <input type="checkbox" bind:checked={formIsActive} class="w-4 h-4 accent-primary" />
            <span class="text-[13px] text-muted font-medium">Active</span>
          </label>
        </div>
        <div class="flex gap-2.5 mt-5">
          <button type="submit" class="inline-flex items-center gap-1.5 px-4 py-2 border-none rounded text-[13px] font-medium transition-all duration-150 bg-primary text-white hover:bg-primary-hover hover:shadow-primary">Save</button>
          <button type="button" class="inline-flex items-center gap-1.5 px-4 py-2 border border-border rounded text-[13px] font-medium transition-all duration-150 bg-transparent text-muted hover:bg-bg-hover hover:text-text hover:border-border-hover" onclick={cancelForm}>Cancel</button>
        </div>
      </form>
    </div>
  {/if}

  <div class="bg-bg-card border border-border rounded-xl overflow-hidden">
    <table class="w-full border-collapse">
      <thead>
        <tr>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Name</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Price</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Billing</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Devices</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">History</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">File Types</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Active</th>
          <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold"></th>
        </tr>
      </thead>
      <tbody>
        {#each adminState.plans as plan}
          <tr class="transition-colors duration-150 hover:bg-bg-hover">
            <td class="px-[18px] py-[13px] text-sm border-b border-border font-semibold">{plan.name}</td>
            <td class="px-[18px] py-[13px] text-sm border-b border-border">{plan.price} {plan.currency}</td>
            <td class="px-[18px] py-[13px] text-sm border-b border-border">{plan.billing_period}</td>
            <td class="px-[18px] py-[13px] text-sm border-b border-border">{plan.max_devices}</td>
            <td class="px-[18px] py-[13px] text-sm border-b border-border">{plan.max_clipboard_history}</td>
            <td class="px-[18px] py-[13px] text-[13px] border-b border-border text-muted">{plan.allowed_file_types.length > 0 ? plan.allowed_file_types.join(', ') : 'All'}</td>
            <td class="px-[18px] py-[13px] text-sm border-b border-border">
              {#if plan.is_active}
                <span class="inline-block px-2.5 py-[3px] rounded-full bg-success-glow text-success text-[11px] font-semibold border border-success/20">Active</span>
              {:else}
                <span class="inline-block px-2.5 py-[3px] rounded-full bg-bg-input text-muted text-[11px] font-semibold border border-border">Inactive</span>
              {/if}
            </td>
            <td class="px-[18px] py-[13px] text-sm border-b border-border">
              <div class="flex items-center gap-2">
                <button class="border border-border rounded text-[13px] font-medium py-1.5 px-3 transition-all duration-150 bg-transparent text-muted hover:bg-bg-hover hover:text-text hover:border-border-hover" onclick={() => startEdit(plan)}>Edit</button>
                {#if deleteConfirm === plan.id}
                  <div class="flex items-center gap-2">
                    <span class="text-[13px] text-warning font-medium">Delete?</span>
                    <button class="border-none rounded text-[13px] font-medium py-1.5 px-3 transition-all duration-150 bg-danger text-white hover:bg-danger-hover" onclick={() => handleDelete(plan.id)}>Yes</button>
                    <button class="border border-border rounded text-[13px] font-medium py-1.5 px-3 transition-all duration-150 bg-transparent text-muted hover:bg-bg-hover hover:text-text hover:border-border-hover" onclick={() => (deleteConfirm = null)}>No</button>
                  </div>
                {:else}
                  <button class="border border-border rounded text-[13px] font-medium py-1.5 px-3 transition-all duration-150 bg-transparent text-muted hover:bg-bg-hover hover:text-text hover:border-border-hover" onclick={() => (deleteConfirm = plan.id)}>Delete</button>
                {/if}
              </div>
            </td>
          </tr>
        {:else}
          <tr><td colspan="8" class="text-muted text-center p-6">No plans created yet.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>
