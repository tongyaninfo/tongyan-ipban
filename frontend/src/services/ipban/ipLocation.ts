import { requestManagement } from './management';

export const ipLocationDatabases = ['CZ88', 'ip2location', 'ip2region', 'dbip', 'ipinfo', 'geolite2'] as const;
export type IpLocationSettings = {
  enabled: boolean;
  protocol: 'http' | 'https';
  host: string;
  port: number;
  database: (typeof ipLocationDatabases)[number];
  timeoutSeconds: number;
};
export const defaultIpLocationSettings: IpLocationSettings = {
  enabled: false, protocol: 'https', host: 'ip.tongyaninfo.com', port: 443, database: 'CZ88', timeoutSeconds: 2,
};
export type IpLocationStatus = 'disabled' | 'private' | 'reserved' | 'network' | 'invalid' | 'queued' | 'resolved' | 'notFound' | 'timeout' | 'failed' | 'busy';
export type IpLocationResult = {
  ip: string;
  status: IpLocationStatus;
  country?: string | null;
  province?: string | null;
  city?: string | null;
  district?: string | null;
  region?: string | null;
  isp?: string | null;
  asn?: string | null;
  asName?: string | null;
  database?: string | null;
  version?: string | null;
  attribution?: string | null;
  licenseUrl?: string | null;
};
export type IpLocationBatch = { enabled: boolean; revision: string; items: IpLocationResult[] };
const mutationHeaders = { 'X-IPBan-Management': '1' };
export const queryIpLocationSettings = (signal?: AbortSignal) => requestManagement<IpLocationSettings>(
  '/api/admin/v1/ip-location/settings', { signal },
);
export const updateIpLocationSettings = (settings: IpLocationSettings) => requestManagement<IpLocationSettings>(
  '/api/admin/v1/ip-location/settings', { method: 'PUT', headers: mutationHeaders, body: JSON.stringify(settings) },
);
export const queryIpLocations = (ips: string[], signal?: AbortSignal) => requestManagement<IpLocationBatch>(
  '/api/admin/v1/ip-location/lookup', { method: 'POST', headers: mutationHeaders, body: JSON.stringify({ ips }), signal },
);
