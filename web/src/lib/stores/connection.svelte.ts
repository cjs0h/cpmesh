import { onWSStatus, type WSStatus } from '../ws';
import { onSessionEnd } from '../auth';

/** Reactive mirror of the WebSocket connection status for the UI. */
export const connectionState: { status: WSStatus; lastEventAt: number | null } = $state({
  status: 'offline',
  lastEventAt: null,
});

onWSStatus((status) => {
  connectionState.status = status;
  if (status === 'online') connectionState.lastEventAt = Date.now();
});

export function markActivity() {
  connectionState.lastEventAt = Date.now();
}

onSessionEnd(() => { connectionState.status = 'offline'; connectionState.lastEventAt = null; });
