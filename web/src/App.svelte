<script lang="ts">
  import Router from 'svelte-spa-router';
  import { isLoggedIn } from './lib/auth';
  import { fetchCurrentUser, userState } from './lib/stores/user.svelte';
  import { prependEntry } from './lib/stores/clipboard.svelte';
  import { updateDeviceStatus } from './lib/stores/devices.svelte';
  import { markActivity } from './lib/stores/connection.svelte';
  import { connectWS, disconnectWS, onWSMessage } from './lib/ws';
  import Layout from './components/layout/Layout.svelte';
  import Toaster from './components/ui/Toaster.svelte';
  import Logo from './components/Logo.svelte';
  import Home from './pages/Home.svelte';
  import Login from './pages/Login.svelte';
  import Dashboard from './pages/Dashboard.svelte';
  import Clipboard from './pages/Clipboard.svelte';
  import Devices from './pages/Devices.svelte';
  import Settings from './pages/Settings.svelte';
  import AdminUsers from './pages/admin/Users.svelte';
  import AdminStats from './pages/admin/Stats.svelte';
  import AdminPlans from './pages/admin/Plans.svelte';
  import AdminDownloads from './pages/admin/Downloads.svelte';
  import AdminSettings from './pages/admin/Settings.svelte';
  import AdminReleases from './pages/admin/Releases.svelte';
  import NotFound from './pages/NotFound.svelte';
  import AuthCallback from './pages/AuthCallback.svelte';

  const publicRoutes = {
    '/': Home,
    '/login': Login,
    '/auth/callback': AuthCallback,
    // Deep links into the app while signed out land on the sign-in screen.
    '*': Login,
  };

  const appRoutes = {
    '/': Dashboard,
    '/clipboard': Clipboard,
    '/devices': Devices,
    '/settings': Settings,
    '/admin/users': AdminUsers,
    '/admin/plans': AdminPlans,
    '/admin/downloads': AdminDownloads,
    '/admin/settings': AdminSettings,
    '/admin/releases': AdminReleases,
    '/admin/stats': AdminStats,
    '*': NotFound,
  };

  let loggedIn = $state(isLoggedIn());

  $effect(() => {
    if (!loggedIn) return;
    fetchCurrentUser();
    connectWS();
    // Keep the shared stores live so every page reflects pushes immediately.
    const unsub = onWSMessage((msg) => {
      markActivity();
      if (msg.type === 'clipboard_new' && msg.payload?.entry) prependEntry(msg.payload.entry);
      else if (msg.type === 'device_status' && msg.payload) updateDeviceStatus(msg.payload.device_id, msg.payload.online);
    });
    return () => {
      unsub();
      disconnectWS();
    };
  });
</script>

{#if !loggedIn}
  <Router routes={publicRoutes} />
{:else if !userState.loaded}
  <div class="dot-grid flex h-dvh flex-col items-center justify-center gap-5 bg-bg">
    <div class="animate-[float-y_3s_ease-in-out_infinite]">
      <Logo size={48} />
    </div>
    <div class="flex items-center gap-2 font-head text-[12px] uppercase tracking-[0.1em] text-muted">
      <span class="inline-block h-4 w-4 rounded-full border-[3px] border-ink/20 border-t-ink animate-[spin_0.7s_linear_infinite]"></span>
      Unlocking your workspace…
    </div>
  </div>
{:else}
  <Layout>
    <Router routes={appRoutes} />
  </Layout>
{/if}

<Toaster />
