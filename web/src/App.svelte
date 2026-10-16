<script lang="ts">
  import { onMount } from 'svelte';
  import Router, { router } from 'svelte-spa-router';
  import { wrap } from 'svelte-spa-router/wrap';
  import { setReauthHandler } from './lib/api';
  import { authSession, parseAppSignIn } from './lib/auth';
  import { fetchCurrentUser, userState } from './lib/stores/user.svelte';
  import { prependEntry, parseClipboardEntry } from './lib/stores/clipboard.svelte';
  import { updateDeviceStatus } from './lib/stores/devices.svelte';
  import { markActivity } from './lib/stores/connection.svelte';
  import { requestStepUp } from './lib/stores/reauth.svelte';
  import { loadPublicSettings } from './lib/stores/settings.svelte';
  import { connectWS, disconnectWS, onWSMessage } from './lib/ws';
  import Layout from './components/layout/Layout.svelte';
  import Toaster from './components/ui/Toaster.svelte';
  import Logo from './components/Logo.svelte';
  import EnrollGate from './components/mfa/EnrollGate.svelte';
  import StepUpDialog from './components/mfa/StepUpDialog.svelte';
  import Home from './pages/Home.svelte';
  import Login from './pages/Login.svelte';
  import Dashboard from './pages/Dashboard.svelte';
  import Clipboard from './pages/Clipboard.svelte';
  import Devices from './pages/Devices.svelte';
  import Settings from './pages/Settings.svelte';
  import NotFound from './pages/NotFound.svelte';
  import AuthCallback from './pages/AuthCallback.svelte';
  import Mcp from './pages/Mcp.svelte';
  import Agents from './pages/Agents.svelte';

  const publicRoutes = {
    '/': Home,
    '/login': Login,
    '/mcp': Mcp,
    '/auth/callback': AuthCallback,
    // Deep links into the app while signed out land on the sign-in screen.
    '*': Login,
  };

  const appRoutes = {
    '/': Dashboard,
    '/clipboard': Clipboard,
    '/devices': Devices,
    '/settings': Settings,
    '/mcp': Agents,
    // The admin console loads on demand, so members never download it
    '/admin/users': wrap({ asyncComponent: () => import('./pages/admin/Users.svelte') }),
    '/admin/users/:id': wrap({ asyncComponent: () => import('./pages/admin/UserDetail.svelte') }),
    '/admin/plans': wrap({ asyncComponent: () => import('./pages/admin/Plans.svelte') }),
    '/admin/downloads': wrap({ asyncComponent: () => import('./pages/admin/Downloads.svelte') }),
    '/admin/settings': wrap({ asyncComponent: () => import('./pages/admin/Settings.svelte') }),
    '/admin/releases': wrap({ asyncComponent: () => import('./pages/admin/Releases.svelte') }),
    '/admin/stats': wrap({ asyncComponent: () => import('./pages/admin/Stats.svelte') }),
    '/admin/audit': wrap({ asyncComponent: () => import('./pages/admin/Audit.svelte') }),
    '/admin/tokens': wrap({ asyncComponent: () => import('./pages/admin/ApiTokens.svelte') }),
    '*': NotFound,
  };

  const loggedIn = $derived($authSession);

  // Sign-in pages stay reachable with a session: SSO callbacks, the desktop app's
  // "Sign in with browser", and the sign-in screen once the session has ended.
  const signInPage = $derived(
    router.location === '/auth/callback' ||
      (router.location === '/login' && (!loggedIn || parseAppSignIn(router.querystring) !== null)),
  );
  // Two-factor authentication is required but not set up yet (an older session, or reset by an admin)
  const mustEnroll = $derived(userState.id !== '' && userState.mfa.required && !userState.mfa.enabled);

  onMount(() => {
    // Announcement banner, sign-up and passkey availability
    loadPublicSettings();
  });

  $effect(() => {
    if (!loggedIn) return;
    // Sensitive actions answer `reauth_required`: confirm it's the user, then retry
    setReauthHandler(() => requestStepUp());
    fetchCurrentUser();
    connectWS();
    // Keep the shared stores live so every page reflects pushes immediately.
    const unsub = onWSMessage((msg) => {
      markActivity();
      const payload = msg.payload;
      if (!payload || typeof payload !== 'object') return;
      if (msg.type === 'clipboard_new' && 'entry' in payload) {
        try { prependEntry(parseClipboardEntry(payload.entry)); }
        catch (error) { console.warn('Invalid clipboard event', error); }
      } else if (msg.type === 'device_status' && 'device_id' in payload && 'online' in payload
        && typeof payload.device_id === 'string' && typeof payload.online === 'boolean') {
        updateDeviceStatus(payload.device_id, payload.online);
      }
    });
    return () => {
      setReauthHandler(null);
      unsub();
      disconnectWS();
    };
  });
</script>

{#if !loggedIn || signInPage}
  <Router routes={publicRoutes} />
{:else if !userState.loaded}
  <div class="flex h-dvh flex-col items-center justify-center gap-5 bg-bg">
    <Logo size={40} />
    <div class="flex items-center gap-2 text-[13px] text-muted">
      <span class="inline-block h-4 w-4 rounded-full border-2 border-border-strong border-t-ink animate-[spin_0.7s_linear_infinite]"></span>
      Unlocking your workspace…
    </div>
  </div>
{:else if userState.error}
    <div class="wrap py-12" role="alert">
      <p>{userState.error}</p>
      <button type="button" onclick={fetchCurrentUser}>Retry account loading</button>
    </div>
{:else if mustEnroll}
  <EnrollGate />
{:else}
  <Layout>
    <Router routes={appRoutes} />
  </Layout>
{/if}

{#if loggedIn && !signInPage}
  <StepUpDialog />
{/if}
<Toaster />
