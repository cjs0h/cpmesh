import { api } from '../api';
import { onSessionEnd } from '../auth';
import { toast } from './toast.svelte';

export interface DeviceInfo {
  id: string;
  name: string;
  last_seen: string;
  online: boolean;
  status: 'pending' | 'approved' | 'rejected' | 'revoked';
}

export const devicesState: { list: DeviceInfo[]; loading: boolean; error: string } = $state({
  list: [],
  loading: false,
  error: '',
});
let requestVersion = 0;

export async function fetchDevices() {
  const request = ++requestVersion;
  devicesState.loading = true;
  devicesState.error = '';
  try {
    const devices = await api<DeviceInfo[]>('/api/devices');
    if (request === requestVersion) devicesState.list = devices;
  } catch (error) {
    if (request !== requestVersion) return;
    devicesState.error = error instanceof Error ? error.message : String(error);
    toast.error('Could not load devices', devicesState.error);
  } finally {
    if (request === requestVersion) devicesState.loading = false;
  }

}

onSessionEnd(() => {
  requestVersion++;
  Object.assign(devicesState, { list: [], loading: false, error: '' });
});

export function updateDeviceStatus(deviceId: string, online: boolean) {
  const device = devicesState.list.find((d) => d.id === deviceId);
  if (device) device.online = online;
}
