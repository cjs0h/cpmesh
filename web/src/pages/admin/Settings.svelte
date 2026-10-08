<script lang="ts">
  import { onMount } from 'svelte';
  import { userState } from '../../lib/stores/user.svelte';
  import { adminTestSmtp, adminTestOidc } from '../../lib/stores/admin.svelte';
  import { toast } from '../../lib/stores/toast.svelte';
  import { push } from 'svelte-spa-router';
  import Icon from '../../components/Icon.svelte';
  import Button from '../../components/ui/Button.svelte';
  import Card from '../../components/ui/Card.svelte';
  import Field from '../../components/ui/Field.svelte';
  import Badge from '../../components/ui/Badge.svelte';

  type Result = { ok: boolean; message: string; at: number } | null;

  let testing = $state<string | null>(null);
  let smtpTestEmail = $state('');
  let smtpResult = $state<Result>(null);
  let oidcResult = $state<Result>(null);

  onMount(() => {
    if (!userState.isAdmin) push('/');
  });

  async function testSmtp(e: Event) {
    e.preventDefault();
    if (!smtpTestEmail) return;
    testing = 'smtp';
    try {
      const result = await adminTestSmtp(smtpTestEmail);
      if (result.error) {
        smtpResult = { ok: false, message: result.error, at: Date.now() };
        toast.error('SMTP test failed', result.error);
      } else {
        smtpResult = { ok: true, message: result.message || `Test email sent to ${smtpTestEmail}.`, at: Date.now() };
        toast.success('SMTP works', smtpResult.message);
      }
    } catch (err: any) {
      smtpResult = { ok: false, message: err.message, at: Date.now() };
      toast.error('SMTP test failed', err.message);
    } finally {
      testing = null;
    }
  }

  async function testOidc() {
    testing = 'oidc';
    try {
      const result = await adminTestOidc();
      if (result.error) {
        oidcResult = { ok: false, message: result.error, at: Date.now() };
        toast.error('OIDC test failed', result.error);
      } else {
        oidcResult = { ok: true, message: `Discovery OK · issuer ${result.issuer}`, at: Date.now() };
        toast.success('OIDC works', `Issuer ${result.issuer}`);
      }
    } catch (err: any) {
      oidcResult = { ok: false, message: err.message, at: Date.now() };
      toast.error('OIDC test failed', err.message);
    } finally {
      testing = null;
    }
  }

  const envGroups = [
    { title: 'SMTP / Email', icon: 'mail', vars: ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USERNAME', 'SMTP_PASSWORD', 'SMTP_FROM', 'SMTP_TLS'] },
    { title: 'Social login (OIDC)', icon: 'globe', vars: ['OIDC_ISSUER_URL', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET', 'OIDC_CALLBACK_URL'] },
    { title: 'Core', icon: 'server', vars: ['DATABASE_URL', 'BASE_URL', 'ALLOWED_ORIGINS', 'TRUST_PROXY_HEADERS', 'DOWNLOADS_DIR'] },
  ];
</script>

{#snippet resultLine(r: Result)}
  {#if r}
    <p class="mt-3 flex items-start gap-2 text-[12.5px] {r.ok ? 'text-mint' : 'text-rose'}">
      <Icon name={r.ok ? 'check-circle' : 'alert-circle'} size={14} class="mt-0.5 shrink-0" />
      <span class="break-all">{r.message}</span>
    </p>
  {/if}
{/snippet}

<div class="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
  <div class="flex flex-col gap-6">
    <Card title="Email delivery" description="Send a real message through the configured SMTP server" icon="mail" accent="accent">
      <form class="flex flex-col gap-3 sm:flex-row sm:items-end" onsubmit={testSmtp}>
        <Field label="Recipient" type="email" icon="at-sign" bind:value={smtpTestEmail} placeholder="you@example.com" required class="flex-1" />
        <Button type="submit" variant="secondary" icon="send" loading={testing === 'smtp'} disabled={!smtpTestEmail}>Send test email</Button>
      </form>
      {@render resultLine(smtpResult)}
    </Card>

    <Card title="Social login" description="Fetch the OIDC discovery document for the configured issuer" icon="globe" accent="cyan">
      <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <p class="text-[13px] text-muted">Confirms <code class="rounded bg-surface-2 px-1 py-0.5 text-[12px] text-fg">OIDC_ISSUER_URL</code> is reachable and advertises an authorization endpoint.</p>
        <Button variant="secondary" icon="shield-check" loading={testing === 'oidc'} onclick={testOidc}>Test discovery</Button>
      </div>
      {@render resultLine(oidcResult)}
    </Card>
  </div>

  <Card title="Configuration" description="Everything is set through environment variables" icon="sliders" accent="gold" padded={false}>
    <div class="divide-y divide-border">
      {#each envGroups as group (group.title)}
        <div class="px-5 py-4">
          <p class="mb-2 flex items-center gap-2 text-[12px] font-semibold uppercase tracking-[0.1em] text-dim"><Icon name={group.icon} size={12} /> {group.title}</p>
          <div class="flex flex-wrap gap-1.5">
            {#each group.vars as v (v)}<code class="mono-chip">{v}</code>{/each}
          </div>
        </div>
      {/each}
      <div class="flex items-start gap-2 px-5 py-4 text-[12.5px] text-muted">
        <Icon name="info" size={14} class="mt-0.5 shrink-0 text-cyan" />
        <span>Edit <code class="text-fg">.env</code> or <code class="text-fg">docker-compose.yml</code>, then restart the server. <Badge tone="neutral" class="ml-1 align-middle">restart required</Badge></span>
      </div>
    </div>
  </Card>
</div>
