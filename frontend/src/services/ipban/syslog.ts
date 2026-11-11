import { requestManagement } from './management';

export type SyslogProtocol = 'udp' | 'tcp' | 'tls' | 'relp';
export type SyslogSeverity = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7;

export type SyslogTarget = {
  id: string;
  name: string;
  enabled: boolean;
  host: string;
  port: number;
  protocol: SyslogProtocol;
  maxSeverity: SyslogSeverity;
  ignoreSslErrors: boolean;
  framing: 'octet' | 'lf';
  deliveryTargetVersion: string;
};

export type SyslogSettings = {
  enabled: boolean;
  configRevision: string;
  targets: SyslogTarget[];
};

export type SyslogTestResult = {
  testId: string;
  targetId: string;
  protocol: SyslogProtocol;
  stage: string;
  message: string;
  completedAtUtc: string;
};

export type SyslogTargetStatus = {
  targetId: string;
  deliveryTargetVersion: string;
  state: string;
  queuedCount: number;
  queuedBytes: number;
  oldestQueuedAtUtc?: string | null;
  lastSentAtUtc?: string | null;
  lastAcknowledgedAtUtc?: string | null;
  failedCount: number;
  retryCount: number;
  droppedCount: number;
  priorityDroppedCount: number;
  lastError?: string | null;
  truncatedCount?: number;
  firstPriorityDroppedAtUtc?: string | null;
  lastPriorityDroppedAtUtc?: string | null;
};

export type SyslogProcessStatus = {
  sourceProcess: string;
  appliedRevision?: string | null;
  configurationState: 'loading' | 'ready' | 'unknown';
  targets: SyslogTargetStatus[];
  droppedCount: number;
  priorityDroppedCount: number;
  lastError?: string | null;
};

export type SyslogStatus = {
  desiredRevision: string;
  api: SyslogProcessStatus;
  agent?: SyslogProcessStatus | null;
  agentErrorCode?: string | null;
};

const base = '/api/admin/v1/syslog';
const headers = { 'X-IPBan-Management': '1' };

export const getSyslogSettings = (signal?: AbortSignal) =>
  requestManagement<SyslogSettings>(`${base}/settings`, { signal, cache: 'no-store' });

export const saveSyslogSettings = (settings: SyslogSettings) =>
  requestManagement<SyslogSettings>(`${base}/settings`, {
    method: 'PUT', headers, body: JSON.stringify(settings),
  });

export const testSyslogTarget = (targetId: string, configRevision: string) =>
  requestManagement<SyslogTestResult>(`${base}/test`, {
    method: 'POST', headers, body: JSON.stringify({ targetId, configRevision }),
  });

export const getSyslogStatus = (signal?: AbortSignal) =>
  requestManagement<SyslogStatus>(`${base}/status`, { signal, cache: 'no-store' });
