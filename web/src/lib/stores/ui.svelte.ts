/** UI chrome state shared between the layout components. */
export const uiState: { sidebarOpen: boolean } = $state({ sidebarOpen: false });

export function openSidebar() {
  uiState.sidebarOpen = true;
}

export function closeSidebar() {
  uiState.sidebarOpen = false;
}

export function toggleSidebar() {
  uiState.sidebarOpen = !uiState.sidebarOpen;
}
