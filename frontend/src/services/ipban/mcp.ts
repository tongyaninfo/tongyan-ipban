import { requestManagement } from './management';

const base = '/api/admin/v1/mcp';
const mutationHeaders = { 'X-IPBan-Management': '1' };

export type McpSettings = {
  enabled: boolean;
  auditRetentionDays: number;
};

export type McpTool = {
  id: string;
  group: string;
  label: string;
  description: string;
  isWrite: boolean;
  isDangerous: boolean;
};

export type McpKeyMode = 'read' | 'write';

export type McpKey = {
  id: string;
  name: string;
  prefix: string;
  mode: McpKeyMode;
  scopes: string[];
  createdAtUtc: string;
  expiresAtUtc?: string | null;
  revokedAtUtc?: string | null;
};

export type McpKeyRequest = {
  name: string;
  mode: McpKeyMode;
  scopes: string[];
  expiresAtUtc: string | null;
};

export type McpAuditRow = {
  id: string;
  occurredAtUtc: string;
  keyId?: string | null;
  keyName?: string | null;
  keyPrefix?: string | null;
  remoteIp?: string | null;
  method?: string | null;
  tool?: string | null;
  status: string;
  httpStatus?: number | null;
  durationMs?: number | null;
  traceId: string;
};

export type McpAuditDetail = McpAuditRow & {
  path: string;
  requestHeaders?: string | null;
  requestBody?: string | null;
  responseHeaders?: string | null;
  responseBody?: string | null;
};

export type McpAuditQuery = {
  page: number;
  pageSize: number;
  fromUtc?: string;
  toUtc?: string;
  keyId?: string;
  tool?: string;
  status?: string;
};

const keyPath = (id: string) => `${base}/keys/${encodeURIComponent(id)}`;

export const getMcpSettings = (signal?: AbortSignal) =>
  requestManagement<McpSettings>(`${base}/settings`, { signal });

export const updateMcpSettings = (settings: Partial<McpSettings> & { confirmShorter?: boolean }) =>
  requestManagement<McpSettings>(`${base}/settings`, {
    method: 'PUT',
    headers: mutationHeaders,
    body: JSON.stringify(settings),
  });

export const listMcpTools = (signal?: AbortSignal) =>
  requestManagement<McpTool[]>(`${base}/tools`, { signal });

export const listMcpKeys = (signal?: AbortSignal) =>
  requestManagement<McpKey[]>(`${base}/keys`, { signal });

export const createMcpKey = (key: McpKeyRequest) =>
  requestManagement<{ key: McpKey; secret: string }>(`${base}/keys`, {
    method: 'POST',
    headers: mutationHeaders,
    body: JSON.stringify(key),
    cache: 'no-store',
  });

export const copyMcpKey = (id: string) =>
  requestManagement<{ secret: string }>(`${keyPath(id)}/copy`, {
    method: 'POST',
    headers: mutationHeaders,
    cache: 'no-store',
  });

export const revokeMcpKey = (id: string) =>
  requestManagement<McpKey>(`${keyPath(id)}/revoke`, { method: 'POST', headers: mutationHeaders });

export const deleteMcpKey = (id: string) =>
  requestManagement<boolean>(keyPath(id), { method: 'DELETE', headers: mutationHeaders });

export function listMcpAudits(query: McpAuditQuery, signal?: AbortSignal) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== '') params.set(key, String(value));
  }
  return requestManagement<{ items: McpAuditRow[]; total: number }>(`${base}/audits?${params}`, {
    signal,
  });
}

export const getMcpAudit = (id: string, signal?: AbortSignal) =>
  requestManagement<McpAuditDetail>(`${base}/audits/${encodeURIComponent(id)}`, {
    signal,
    cache: 'no-store',
  });
