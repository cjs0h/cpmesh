<script lang="ts">
  import { onMount } from 'svelte';
  import { push } from 'svelte-spa-router';
  import { can, userState } from '../../lib/stores/user.svelte';
  import {
    adminState,
    adminTestOidc,
    adminTestSmtp,
    adminUpdateSettings,
    BANNER_MAX_LENGTH,
    errorMessage,
    fetchAdminSettings,
    isMfaRequired,
    type BannerTone,
  } from '../../lib/stores/admin.svelte';
  import { toast } from '../../lib/stores/toast.svelte';
  import Icon from '../../components/Icon.svelte';
  import Alert from '../../components/ui/Alert.svelte';
  import Badge from '../../components/ui/Badge.svelte';
  import Button from '../../components/ui/Button.svelte';
  import Card from '../../components/ui/Card.svelte';
  import Field from '../../components/ui/Field.svelte';
  import Select from '../../components/ui/Select.svelte';
  import Skeleton from '../../components/ui/Skeleton.svelte';
  import Switch from '../../components/ui/Switch.svelte';
  import AdminGate from '../../components/admin/AdminGate.svelte';
  import TextArea from '../../components/admin/TextArea.svelte';

  type Result = { ok: boolean; message: string; at: number } | null;

  let loadError = $state('');
  let registrationOpen = $state(false);
  let savingRegistration = $state(false);
  let bannerMessage = $state('');
  let bannerTone = $state('info');
  let savingBanner = $state<'save' | 'remove' | null>(null);

  let testing = $state<string | null>(null);
  let smtpTestEmail = $state('');
  let smtpResult = $state<Result>(null);
  let oidcResult = $state<Result>(null);

  const canEdit = $derived(can('manage_settings'));
  const settings = $derived(adminState.settings);
  const bannerDirty = $derived(
    bannerMessage.trim() !== (settings?.banner?.message ?? '') || (Boolean(settings?.banner) && bannerTone !== settings?.banner?.tone),
  );

  onMount(() => {
    if (!userState.isAdmin) {
      push('/');
      return;
    }
    load();
  });

  async function load() {
    try {
      const next = await fetchAdminSettings();
      registrationOpen = next.registration_open.value;
      bannerMessage = next.banner?.message ?? '';
      bannerTone = next.banner?.tone ?? 'info';
      loadError = '';
    } catch (err) {
      if (!isMfaRequired(err)) loadError = errorMessage(err);
    }
  }

  /** `null` goes back to REGISTRATION_OPEN. */
  async function setRegistration(open: boolean | null) {
    savingRegistration = true;
    try {
      const next = await adminUpdateSettings({ registration_open: open });
      registrationOpen = next.registration_open.value;
      const now = next.registration_open.value ? 'Anyone can create an account.' : 'New people can’t sign up.';
      toast.success(open === null ? 'Registration follows the default' : open ? 'Registration opened' : 'Registration closed', now);
    } catch (err) {
      registrationOpen = adminState.settings?.registration_open.value ?? registrationOpen;
      if (!isMfaRequired(err)) toast.error('Could not change registration', errorMessage(err));
    } finally {
      savingRegistration = false;
    }
  }

  async function saveBanner(e: SubmitEvent) {
    e.preventDefault();
    const message = bannerMessage.trim();
    if (!message) return;
    const live = Boolean(settings?.banner);
    savingBanner = 'save';
    try {
      const next = await adminUpdateSettings({ banner: { message, tone: bannerTone as BannerTone } });
      bannerMessage = next.banner?.message ?? '';
      bannerTone = next.banner?.tone ?? 'info';
      toast.success(live ? 'Banner updated' : 'Banner published', 'It shows at the top of the dashboard for everyone.');
    } catch (err) {
      if (!isMfaRequired(err)) toast.error('Could not save the banner', errorMessage(err));
    } finally {
      savingBanner = null;
    }
  }

  async function removeBanner() {
    savingBanner = 'remove';
    try {
      await adminUpdateSettings({ banner: null });
      bannerMessage = '';
      bannerTone = 'info';
      toast.success('Banner removed');
    } catch (err) {
      if (!isMfaRequired(err)) toast.error('Could not remove the banner', errorMessage(err));
    } finally {
      savingBanner = null;
    }
  }

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
    } catch (err) {
      if (isMfaRequired(err)) return;
      smtpResult = { ok: false, message: errorMessage(err), at: Date.now() };
      toast.error('SMTP test failed', errorMessage(err));
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
    } catch (err) {
      if (isMfaRequired(err)) return;
      oidcResult = { ok: false, message: errorMessage(err), at: Date.now() };
      toast.error('OIDC test failed', errorMessage(err));
    } finally {
      testing = null;
    }
  }

  // Mirrors the banner shown at the top of the dashboard (components/layout/AnnouncementBanner.svelte)
  const previewTones: Record<BannerTone, { box: string; icon: string; iconColor: string }> = {
    info: { box: 'border-border bg-bg-deep', icon: 'info', iconColor: 'text-muted' },
    warning: { box: 'border-warning/25 bg-warning/5', icon: 'alert-triangle', iconColor: 'text-warning' },
    danger: { box: 'border-danger/25 bg-danger/5', icon: 'alert-circle', iconColor: 'text-danger' },
  };

  const envGroups = [
    { title: 'Core', icon: 'server', vars: ['DATABASE_URL', 'BASE_URL', 'ALLOWED_ORIGINS', 'TRUST_PROXY_HEADERS'] },
    { title: 'Accounts and security', icon: 'shield', vars: ['REGISTRATION_OPEN', 'MFA_REQUIRED', 'WEBAUTHN_RP_ID', 'WEBAUTHN_ORIGINS'] },
    { title: 'Releases and downloads', icon: 'download', vars: ['DOWNLOADS_DIR', 'DOWNLOAD_URL_PREFIXES', 'UPDATER_PUBLIC_KEY'] },
    { title: 'SMTP / Email', icon: 'mail', vars: ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USERNAME', 'SMTP_PASSWORD', 'SMTP_FROM', 'SMTP_TLS'] },
    { title: 'Social login (OIDC)', icon: 'globe', vars: ['OIDC_ISSUER_URL', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET', 'OIDC_CALLBACK_URL'] },
  ];
</script>

{#snippet resultLine(r: Result)}
  {#if r}
    <p class="mt-3 flex items-start gap-2 text-[12.5px] {r.ok ? 'text-success' : 'text-danger'}">
      <Icon name={r.ok ? 'check-circle' : 'alert-circle'} size={14} class="mt-0.5 shrink-0" />
      <span class="break-all">{r.message}</span>
    </p>
  {/if}
{/snippet}

{#snippet configRow(label: string, env: string, value: string, ok: boolean | null, list: string[] = [])}
  <div class="grid grid-cols-1 gap-x-6 gap-y-1 px-5 py-3.5 sm:grid-cols-[auto_minmax(0,1fr)]">
    <dt>
      <span class="block font-medium text-fg">{label}</span>
      <code class="text-[11.5px] text-dim">{env}</code>
    </dt>
    <dd class="inline-flex items-center gap-1.5 sm:justify-self-end sm:text-right {ok === false ? 'text-muted' : 'text-fg'}">
      {#if ok !== null}<Icon name={ok ? 'check-circle' : 'minus'} size={13} class={ok ? 'text-success' : 'text-dim'} />{/if}
      {value}
    </dd>
    {#if list.length}
      <dd class="mt-1 flex flex-wrap gap-1 sm:col-span-2">
        {#each list as item (item)}<code class="mono-chip break-all">{item}</code>{/each}
      </dd>
    {/if}
  </div>
{/snippet}

{#snippet loadingRows()}
  <div class="flex flex-col gap-3" aria-busy="true"><Skeleton class="h-4 w-1/2" /><Skeleton class="h-3 w-3/4" /></div>
{/snippet}

<AdminGate onunlock={load}>
  {#if loadError && !settings}
    <Alert tone="danger" title="Could not load the settings" class="mb-6">
      {loadError}
      <Button variant="link" class="ml-1" onclick={load}>Try again</Button>
    </Alert>
  {/if}
  {#if !canEdit}
    <Alert tone="info" class="mb-6">Your role can view these settings but not change them.</Alert>
  {/if}

  <div class="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
    <div class="flex flex-col gap-6">
      <Card title="Registration" description="Whether new people can create an account" icon="user-plus">
        {#if settings}
          <Switch
            bind:checked={registrationOpen}
            disabled={!canEdit || savingRegistration}
            onchange={(e) => setRegistration(e.currentTarget.checked)}
            label="Open registration"
            description={registrationOpen ? 'Anyone can create an account.' : 'New people can’t sign up; existing accounts are not affected.'}
          />
          <div class="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4 text-[13px]">
            <p class="text-muted">
              {#if settings.registration_open.override === null}
                Following the default: <code class="font-mono text-[12px] text-fg">REGISTRATION_OPEN</code> is {settings.registration_open.default ? 'on' : 'off'}.
              {:else}
                Set here. The default (<code class="font-mono text-[12px] text-fg">REGISTRATION_OPEN</code>) is {settings.registration_open.default ? 'on' : 'off'}.
              {/if}
            </p>
            {#if canEdit && settings.registration_open.override !== null}
              <Button variant="outline" size="xs" icon="refresh" disabled={savingRegistration} onclick={() => setRegistration(null)}>Use default</Button>
            {/if}
          </div>
        {:else}
          {@render loadingRows()}
        {/if}
      </Card>

      <Card title="Announcement banner" description="A notice at the top of the dashboard for everyone" icon="bell">
        {#snippet actions()}
          {#if settings?.banner}<Badge tone="mint" dot>Live</Badge>{/if}
        {/snippet}
        {#if settings}
          <form class="flex flex-col gap-4" onsubmit={saveBanner}>
            <TextArea
              label="Message"
              bind:value={bannerMessage}
              maxlength={BANNER_MAX_LENGTH}
              rows={3}
              disabled={!canEdit}
              placeholder="Maintenance on Sunday 02:00–03:00 UTC: sync may pause for a few minutes."
            />
            <Select label="Tone" bind:value={bannerTone} disabled={!canEdit} class="sm:max-w-[220px]">
              <option value="info">Info</option>
              <option value="warning">Warning</option>
              <option value="danger">Danger</option>
            </Select>
            <div>
              <p class="mb-1.5 text-[13px] font-medium text-fg">Preview</p>
              {#if bannerMessage.trim()}
                {@const look = previewTones[bannerTone as BannerTone] ?? previewTones.info}
                <div class="flex items-start gap-3 rounded-md border px-4 py-2.5 text-[13px] leading-relaxed text-fg {look.box}">
                  <span class="mt-0.5 shrink-0 {look.iconColor}"><Icon name={look.icon} size={15} /></span>
                  <p class="min-w-0 flex-1 break-words">{bannerMessage.trim()}</p>
                  <span class="-mr-1 shrink-0 p-1 text-dim" aria-hidden="true"><Icon name="x" size={14} /></span>
                </div>
              {:else}
                <p class="rounded-md border border-dashed border-border-strong px-3.5 py-3 text-[13px] text-dim">Write a message to preview the banner.</p>
              {/if}
            </div>
            {#if canEdit}
              <div class="flex flex-wrap items-center justify-end gap-2">
                {#if settings.banner}
                  <Button variant="ghost" icon="trash" loading={savingBanner === 'remove'} disabled={savingBanner !== null} onclick={removeBanner}>Remove banner</Button>
                {/if}
                <Button type="submit" icon="send" loading={savingBanner === 'save'} disabled={!bannerMessage.trim() || !bannerDirty || savingBanner !== null}>
                  {settings.banner ? 'Update banner' : 'Publish banner'}
                </Button>
              </div>
            {/if}
          </form>
        {:else}
          {@render loadingRows()}
        {/if}
      </Card>

      <Card title="Email delivery" description="Send a real message through the configured SMTP server" icon="mail">
        <form class="flex flex-col gap-3 sm:flex-row sm:items-end" onsubmit={testSmtp}>
          <Field label="Recipient" type="email" icon="at-sign" bind:value={smtpTestEmail} placeholder="you@example.com" required disabled={!canEdit} class="flex-1" />
          <Button type="submit" variant="secondary" icon="send" loading={testing === 'smtp'} disabled={!smtpTestEmail || !canEdit}>Send test email</Button>
        </form>
        {@render resultLine(smtpResult)}
      </Card>

      <Card title="Social login" description="Fetch the OIDC discovery document for the configured issuer" icon="globe">
        <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <p class="text-[13px] text-muted">Confirms <code class="rounded bg-surface-2 px-1 py-0.5 text-[12px] text-fg">OIDC_ISSUER_URL</code> is reachable and advertises an authorization endpoint.</p>
          <Button variant="secondary" icon="shield-check" loading={testing === 'oidc'} disabled={!canEdit} onclick={testOidc}>Test discovery</Button>
        </div>
        {@render resultLine(oidcResult)}
      </Card>
    </div>

    <div class="flex flex-col gap-6">
      <Card title="Configuration" description="Read from the environment when the server starts" icon="server" padded={false}>
        {#if settings}
          <dl class="divide-y divide-border text-[13px]">
            {@render configRow('Two-factor authentication', 'MFA_REQUIRED', settings.mfa_policy === 'all' ? 'Required for every account' : 'Required for staff, optional for members', null)}
            {@render configRow('Passkeys', 'WEBAUTHN_RP_ID', settings.passkeys.enabled ? `On for ${settings.passkeys.rp_id}` : 'Off', settings.passkeys.enabled, settings.passkeys.enabled ? settings.passkeys.origins : [])}
            {@render configRow('Installer uploads', 'DOWNLOADS_DIR', settings.uploads.downloads_dir_configured ? 'On' : 'Off: no downloads directory', settings.uploads.downloads_dir_configured)}
            {@render configRow('Update signatures', 'UPDATER_PUBLIC_KEY', settings.uploads.signature_required ? 'Required for every upload' : 'Not checked', settings.uploads.signature_required)}
            {@render configRow('Download URLs', 'DOWNLOAD_URL_PREFIXES', settings.download_url_prefixes.length ? 'Only under these prefixes' : 'Any https URL or uploaded file', null, settings.download_url_prefixes)}
            {@render configRow('Email', 'SMTP_HOST', settings.smtp_configured ? 'Configured' : 'Not configured', settings.smtp_configured)}
            {@render configRow('Social login', 'OIDC_ISSUER_URL', settings.oidc_configured ? 'Configured' : 'Not configured', settings.oidc_configured)}
          </dl>
        {:else}
          <div class="p-5">{@render loadingRows()}</div>
        {/if}
      </Card>

      <Card title="Environment variables" description="Everything else is set through the environment" icon="sliders" padded={false}>
        <div class="divide-y divide-border">
          {#each envGroups as group (group.title)}
            <div class="px-5 py-4">
              <p class="mb-2 flex items-center gap-2 text-xs font-medium text-muted"><Icon name={group.icon} size={12} /> {group.title}</p>
              <div class="flex flex-wrap gap-1.5">
                {#each group.vars as v (v)}<code class="mono-chip">{v}</code>{/each}
              </div>
            </div>
          {/each}
          <div class="flex items-start gap-2 px-5 py-4 text-[12.5px] text-muted">
            <Icon name="info" size={14} class="mt-0.5 shrink-0 text-dim" />
            <span>Edit <code class="text-fg">.env</code> or <code class="text-fg">docker-compose.yml</code>, then restart the server. <Badge tone="neutral" class="ml-1 align-middle">restart required</Badge></span>
          </div>
        </div>
      </Card>
    </div>
  </div>
</AdminGate>
