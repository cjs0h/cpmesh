import { api } from '../api';

export interface DeviceInfo {
  id: string;
  name: string;
  last_seen: string;
  online: boolean;
  status: 'pending' | 'approved' | 'rejected' | 'revoked';
}

export const devicesState: { list: DeviceInfo[]; loading: boolean } = $state({
  list: [],
  loading: false,
});

export async function fetchDevices() {
  devicesState.loading = true;
  try {
    devicesState.list = await api<DeviceInfo[]>('/api/devices');
  } catch {
    devicesState.list = [];
  } finally {
    devicesState.loading = false;
  }
}

export function updateDeviceStatus(deviceId: string, online: boolean) {
  const device = devicesState.list.find((d) => d.id === deviceId);
  if (device) device.online = online;
}
