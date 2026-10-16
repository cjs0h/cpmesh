// Applies the saved light/dark choice before the app loads, so dark users don't see a white flash.
// Kept in step with src/lib/theme.svelte.ts.
(function () {
	var preference = 'system';
	try {
		preference = localStorage.getItem('cpmesh.theme') || 'system';
	} catch (e) {}
	var dark = preference === 'dark' || (preference !== 'light' && window.matchMedia('(prefers-color-scheme: dark)').matches);
	var root = document.documentElement;
	root.classList.add(dark ? 'dark' : 'light');
	root.style.colorScheme = dark ? 'dark' : 'light';
	root.style.backgroundColor = dark ? '#0a0a0a' : '#ffffff';
})();
