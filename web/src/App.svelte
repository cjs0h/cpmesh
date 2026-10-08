<script lang="ts">
  import Router from 'svelte-spa-router';
  import { isLoggedIn } from './lib/auth';
  import { fetchCurrentUser, userState } from './lib/stores/user.svelte';
  import { connectWS, disconnectWS } from './lib/ws';
  import Layout from './components/layout/Layout.svelte';
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
    if (loggedIn) {
      fetchCurrentUser();
      connectWS();
      return () => disconnectWS();
    }
  });
</script>

{#if !loggedIn}
  <Router routes={publicRoutes} />
{:else if !userState.loaded}
  <div class="flex items-center justify-center h-screen">
    <div class="w-8 h-8 border-3 border-border border-t-primary rounded-full animate-[spin_0.6s_linear_infinite]"></div>
  </div>
{:else}
  <Layout>
    <Router routes={appRoutes} />
  </Layout>
{/if}
