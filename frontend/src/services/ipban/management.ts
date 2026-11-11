export type ApiResult<T> = {
  success: boolean;
  code: string;
  message: string;
  data: T;
};

export type UserSummary = {
  id: number;
  username: string;
  displayName: string;
  enabled: boolean;
  createdAtUtc: string;
  lastLoginAtUtc?: string | null;
};

export type SystemSetting = {
  key: string;
  value?: string | null;
  isSecret: boolean;
  updatedAtUtc: string;
  updatedBy?: string | null;
};

export type CertificateMetadata = {
  id: number;
  certificatePath: string;
  subject: string;
  issuer?: string | null;
  thumbprint: string;
  notBeforeUtc: string;
  notAfterUtc: string;
  uploadedAtUtc: string;
  active: boolean;
};

export type AuditRecord = {
  id: number;
  occurredAtUtc: string;
  action: string;
  category: string;
  actorUsername?: string | null;
  target?: string | null;
  detailJson?: string | null;
  remoteIp?: string | null;
  success: boolean;
};

export type LoginEvent = {
  id: number;
  occurredAtUtc: string;
  protocol: string | number;
  success: boolean;
  username?: string | null;
  remoteIp?: string | null;
  remotePort?: number | null;
  localIp?: string | null;
  localPort?: number | null;
  localProcessName?: string | null;
  completenessLevel: string;
  usernameAvailability: string | number;
  endpointAvailability: string | number;
  processAvailability: string | number;
  collector: string;
  rawEventId?: string | null;
  evidenceSource: string;
};

export type BackupRecord = {
  id: number;
  backupKind: string;
  backupPath: string;
  sizeBytes: number;
  sha256?: string | null;
  createdAtUtc: string;
  status: string;
  errorMessage?: string | null;
};

export type AccessListEntry = {
  id: number;
  address: string;
  entryType: string;
  source: string;
  reason?: string | null;
  priority: number;
  status: string;
  createdBy?: string | null;
  createdAtUtc: string;
  effectiveAtUtc?: string | null;
  expiresAtUtc?: string | null;
  releasedAtUtc?: string | null;
};

export type BanPolicy = {
  id: number;
  name: string;
  enabled: boolean;
  threshold: number;
  windowSeconds: number;
  observeSeconds: number;
  cooldownSeconds: number;
  banDurationSeconds: number;
  action: string;
  protocol?: string | null;
  description?: string | null;
  version: number;
  createdAtUtc: string;
  updatedAtUtc: string;
};

export type FirewallAction = {
  id: string | number;
  createdAtUtc: string;
  sourceIp: string;
  action: string;
  status: string;
  provider: string;
  errorCode?: string | null;
  errorMessage?: string | null;
  completedAtUtc?: string | null;
  canUnban?: boolean;
  currentStatus?: string;
};

export type LogFileInfo = {
  name: string;
  fullPath?: string;
  sizeBytes: number;
  lastWriteTimeUtc: string;
  compressed: boolean;
  /** 仅服务端明确允许的已轮转文件可删除；旧版本缺失此字段时保持只读。 */
  canDelete?: boolean;
};

export async function requestManagement<T>(path: string, init: RequestInit = {}): Promise<ApiResult<T>> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      headers: { Accept: 'application/json', ...(init.body ? { 'Content-Type': 'application/json' } : {}), ...(init.headers ?? {}) },
    });
  } catch (_error) {
    return { success: false, code: 'NETWORK_ERROR', message: '管理 API 暂时不可用。', data: undefined as T };
  }

  // 收到 HTTP 响应说明请求已到达服务端；空响应或非 JSON 不能伪装成网络故障。
  const invalidResponse = (): ApiResult<T> => ({
    success: false,
    code: response.ok ? 'INVALID_RESPONSE' : `HTTP_${response.status}`,
    message: response.status === 400
      ? '请求参数无效，请检查输入后重试。'
      : response.ok ? '管理 API 返回格式异常，请稍后重试。' : `请求处理失败（HTTP ${response.status}），请稍后重试。`,
    data: undefined as T,
  });
  let result: ApiResult<T>;
  try {
    const body: unknown = await response.json();
    if (!body || typeof body !== 'object'
      || !('success' in body) || typeof body.success !== 'boolean'
      || !('code' in body) || typeof body.code !== 'string'
      || !('message' in body) || typeof body.message !== 'string')
      return invalidResponse();
    result = body as ApiResult<T>;
  } catch (_error) {
    return invalidResponse();
  }
  if (!response.ok) return { ...result, success: false, code: result.code || `HTTP_${response.status}` };
  return result;
}

export const queryUsers = () => requestManagement<UserSummary[]>('/api/admin/v1/users');
export async function upsertUser(user: { username: string; displayName: string; password?: string; enabled: boolean }, id?: number) {
  return requestManagement<UserSummary>(`/api/admin/v1/users${id ? `/${id}` : ''}`, { method: 'PUT', body: JSON.stringify(user) });
}
export const querySettings = () => requestManagement<SystemSetting[]>('/api/admin/v1/settings');
export const queryCertificates = () => requestManagement<CertificateMetadata[]>('/api/admin/v1/certificates');
export const queryAudit = (limit = 200) => requestManagement<AuditRecord[]>(`/api/admin/v1/audit?limit=${limit}`);
export const queryBackups = (limit = 200) => requestManagement<BackupRecord[]>(`/api/admin/v1/backups?limit=${limit}`);
export const queryAccessList = () => requestManagement<AccessListEntry[]>('/api/admin/v1/access-list');
export const queryPolicies = () => requestManagement<BanPolicy[]>('/api/admin/v1/policies');
export const queryFirewallActions = (status?: string, limit = 200) => requestManagement<FirewallAction[]>(`/api/admin/v1/firewall-actions?${new URLSearchParams({ limit: String(limit), ...(status ? { status } : {}) }).toString()}`);
export const unbanSource = (sourceAddress: string, actionId: string) => requestManagement('/api/admin/v1/bans/unban', {
  method: 'POST', body: JSON.stringify({ sourceAddress, actionId }),
});
export const queryLogFiles = () => requestManagement<LogFileInfo[]>('/api/admin/v1/logs/files');
export const deleteLogFile = (fileName: string) => requestManagement<null>(`/api/admin/v1/logs/files/${encodeURIComponent(fileName)}`, { method: 'DELETE' });
export const queryLoginEvents = (limit = 500) => requestManagement<LoginEvent[]>(`/api/admin/v1/login-events?limit=${limit}`);

export async function queryLogs(
  fileName?: string, keyword?: string, limit = 300,
  filters?: { severity?: number; appName?: string },
) {
  const params = new URLSearchParams({ limit: String(limit) });
  if (fileName) params.set('fileName', fileName);
  if (keyword) params.set('keyword', keyword);
  if (filters?.severity !== undefined) params.set('severity', String(filters.severity));
  if (filters?.appName) params.set('appName', filters.appName);
  return requestManagement<string[]>(`/api/admin/v1/logs?${params.toString()}`);
}

export async function updateSetting(key: string, value: string, isSecret = false) {
  return requestManagement<SystemSetting>(`/api/admin/v1/settings/${encodeURIComponent(key)}`, {
    method: 'PUT',
    body: JSON.stringify({ value, isSecret }),
  });
}

export async function createBackup() {
  return requestManagement<BackupRecord>('/api/admin/v1/backups', { method: 'POST' });
}

export async function upsertAccessList(entry: Omit<AccessListEntry, 'id' | 'createdAtUtc' | 'releasedAtUtc'>, id?: number) {
  return requestManagement<AccessListEntry>(`/api/admin/v1/access-list${id ? `/${id}` : ''}`, { method: 'PUT', body: JSON.stringify(entry) });
}

export const deleteAccessList = (id: number) => requestManagement<null>(`/api/admin/v1/access-list/${id}`, { method: 'DELETE' });

export async function upsertPolicy(policy: Omit<BanPolicy, 'id' | 'version' | 'createdAtUtc' | 'updatedAtUtc'>, id?: number) {
  return requestManagement<BanPolicy>(`/api/admin/v1/policies${id ? `/${id}` : ''}`, { method: 'PUT', body: JSON.stringify(policy) });
}

export const deletePolicy = (id: number) => requestManagement<null>(`/api/admin/v1/policies/${id}`, { method: 'DELETE' });

export async function uploadCertificate(file: File) {
  const form = new FormData();
  form.append('certificate', file);
  try {
    const response = await fetch('/api/admin/v1/certificates/upload', { method: 'POST', body: form, headers: { Accept: 'application/json' } });
    return (await response.json()) as ApiResult<CertificateMetadata>;
  } catch (_error) {
    return { success: false, code: 'NETWORK_ERROR', message: '证书上传接口暂时不可用。', data: undefined as unknown as CertificateMetadata };
  }
}
