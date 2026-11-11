export type OverviewTrendPoint = { time: string; atUtc: string; success: number; failure: number; observeOnly: number };
export type OverviewData = {
  ready: boolean;
  firewallProvider: string;
  firewallStatus: string | number;
  activeConnections: number;
  activeSessions: number;
  todayLoginSuccess: number;
  todayLoginFailures: number;
  todayObserveOnly: number;
  activeBans: number;
  expiringBans: number;
  host?: {
    osVersion: string;
    computerName: string;
    ipAddresses: string[];
    startedAtUtc: string | null;
  };
  trend: OverviewTrendPoint[];
  topSourceIps: { ip: string; count: number; success?: number; failure?: number; observeOnly?: number }[];
  observeOnlyWithoutIp?: number;
  protocols: { protocol: string; count: number }[];
  recentEvents: { occurredAtUtc: string; protocol: string | number; success: boolean; remoteIp?: string | null; username?: string | null; remotePort?: number | null; localIp?: string | null; localPort?: number | null; processName?: string | null; completenessLevel?: string; collector?: string; evidenceSource?: string | null }[];
  storage: { databaseBytes: number; logBytes: number; archiveBytes: number; oldestEventUtc?: string | null; lastWriteUtc?: string | null; lastRotationUtc?: string | null; lastBackupUtc?: string | null };
};
export type OverviewResult = { success: boolean; code: string; message: string; data: OverviewData };
export type OverviewRange = '24h' | '7d' | '1m';
export const emptyOverview: OverviewData = {
  ready: false, firewallProvider: 'none', firewallStatus: 'Unsupported', activeConnections: 0, activeSessions: 0,
  todayLoginSuccess: 0, todayLoginFailures: 0, todayObserveOnly: 0, activeBans: 0, expiringBans: 0,
  trend: [], topSourceIps: [], protocols: [], recentEvents: [], storage: { databaseBytes: 0, logBytes: 0, archiveBytes: 0 },
};
export async function queryOverview(range: OverviewRange = '24h'): Promise<OverviewResult> {
  try {
    const response = await fetch(`/api/admin/v1/overview?range=${range}`, { headers: { Accept: 'application/json' } });
    const result = await response.json() as OverviewResult;
    return { ...result, data: result.data ?? emptyOverview };
  } catch (_error) {
    return { success: false, code: 'NETWORK_ERROR', message: '运行总览接口暂时不可用。', data: emptyOverview };
  }
}
