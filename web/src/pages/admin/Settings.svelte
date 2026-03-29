<script lang="ts">
  import { userState } from '../../lib/stores/user.svelte';
  import {
    adminTestSmtp,
    adminTestOidc,
  } from '../../lib/stores/admin.svelte';
  import { push } from 'svelte-spa-router';

  let testing = $state<string | null>(null);
  let message = $state('');
  let messageType = $state<'success' | 'error'>('success');
  let smtpTestEmail = $state('');

  $effect(() => {
    if (!userState.isAdmin) {
      push('/');
    }
  });

  function showMessage(msg: string, type: 'success' | 'error' = 'success') {
    message = msg;
    messageType = type;
    setTimeout(() => (message = ''), 4000);
  }

  async function testSmtp() {
    if (!smtpTestEmail) {
      showMessage('Enter a recipient email address to send a test email.', 'error');
      return;
    }
    testing = 'smtp';
    try {
      const result = await adminTestSmtp(smtpTestEmail);
      if (result.error) {
        showMessage(`SMTP test failed: ${result.error}`, 'error');
      } else {
        showMessage(result.message || 'Test email sent successfully.');
      }
    } catch (e: any) {
      showMessage(`SMTP test failed: ${e.message}`, 'error');
    } finally {
      testing = null;
    }
  }

  async function testOidc() {
    testing = 'oidc';
    try {
      const result = await adminTestOidc();
      if (result.error) {
        showMessage(`OIDC test failed: ${result.error}`, 'error');
      } else {
        showMessage(`OIDC OK: issuer=${result.issuer}`);
      }
    } catch (e: any) {
      showMessage(`OIDC test failed: ${e.message}`, 'error');
    } finally {
      testing = null;
    }
  }
</script>

<div>
  <h2 class="text-xl font-semibold mb-6">Settings</h2>

  {#if message}
    <div class="flex items-center gap-2 {messageType === 'success' ? 'bg-success-glow border-success/30 text-success' : 'bg-danger-glow border-danger/30 text-danger'} border px-3.5 py-2.5 rounded text-[13px] mb-4">{message}</div>
  {/if}

  <div class="bg-bg-card border border-border rounded-xl p-6 mb-5 transition-colors duration-200 hover:border-border-hover">
    <h3 class="text-base font-semibold mb-4">SMTP / Email</h3>
    <p class="text-[13px] text-muted mb-4">SMTP is configured via environment variables (<code>SMTP_HOST</code>, <code>SMTP_PORT</code>, <code>SMTP_USERNAME</code>, <code>SMTP_PASSWORD</code>, <code>SMTP_FROM</code>, <code>SMTP_TLS</code>). Use the test below to verify the configuration.</p>
    <div class="flex items-center gap-2 flex-wrap">
      <input type="email" bind:value={smtpTestEmail} placeholder="test@example.com" class="py-2 px-3 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)] w-56" />
      <button class="border border-border rounded text-sm font-medium py-2 px-4 transition-all duration-150 bg-bg-elevated text-text hover:border-primary hover:text-primary disabled:opacity-60" disabled={testing === 'smtp'} onclick={testSmtp}>
        {testing === 'smtp' ? 'Sending...' : 'Test SMTP'}
      </button>
    </div>
  </div>

  <div class="bg-bg-card border border-border rounded-xl p-6 mb-5 transition-colors duration-200 hover:border-border-hover">
    <h3 class="text-base font-semibold mb-4">Social Login (OIDC)</h3>
    <p class="text-[13px] text-muted mb-4">OIDC is configured via environment variables (<code>OIDC_ISSUER_URL</code>, <code>OIDC_CLIENT_ID</code>, <code>OIDC_CLIENT_SECRET</code>, <code>OIDC_CALLBACK_URL</code>). Use the test below to verify the discovery endpoint.</p>
    <button class="border border-border rounded text-sm font-medium py-2 px-4 transition-all duration-150 bg-bg-elevated text-text hover:border-primary hover:text-primary disabled:opacity-60" disabled={testing === 'oidc'} onclick={testOidc}>
      {testing === 'oidc' ? 'Testing...' : 'Test OIDC'}
    </button>
  </div>

  <div class="bg-bg-card border border-border rounded-xl p-6 mb-5 transition-colors duration-200 hover:border-border-hover">
    <h3 class="text-base font-semibold mb-4">Other Settings</h3>
    <p class="text-[13px] text-muted">All settings are managed via environment variables. See the <code>.env</code> file or <code>docker-compose.yml</code> for the full list. A server restart is required after changes.</p>
  </div>
</div>
