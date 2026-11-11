export type ApiResult<T> = {
  success: boolean;
  code: string;
  message: string;
  data: T;
};

export type ConnectionSnapshot = {
  protocol: string;
  state: string;
  remoteIp: string;
  remotePort?: number | null;
  localIp?: string | null;
  localPort?: number | null;
  processId?: number | null;
  processName?: string | null;
  observedAtUtc: string;
};

export type FieldAvailability =
  | 'available'
  | 'notProvided'
  | 'notCollected'
  | 'correlationFailed'
  | 'notApplicable'
  | number;

export type LoginSession = {
  protocol: string;
  sessionId: string;
  username?: string | null;
  usernameAvailability: FieldAvailability;
  remoteIp: string;
  remotePort?: number | null;
  localIp?: string | null;
  localPort?: number | null;
  processName?: string | null;
  processAvailability: FieldAvailability;
  startedAtUtc: string;
  lastObservedAtUtc?: string | null;
  canDisconnect: boolean;
};

export type ManualBanResult = {
  firewallAction: {
    provider: string;
    sourceAddress: string;
    actionStatus: string;
    firewallStatus: string;
    errorCode?: string | null;
    errorMessage?: string | null;
    completedAtUtc: string;
  };
  existingConnectionTermination: {
    success: boolean;
    attempted: number;
    terminated: number;
    error?: string | null;
  };
  durationSeconds: number;
};

async function requestApi<T>(
  path: string,
  init: RequestInit = {},
): Promise<ApiResult<T>> {
  try {
    const response = await fetch(path, {
      ...init,
      headers: {
        Accept: 'application/json',
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...(init.headers || {}),
      },
    });
    const result = (await response.json()) as ApiResult<T>;
    if (!response.ok) {
      return {
        success: false,
        code: result.code || `HTTP_${response.status}`,
        message: result.message || '请求失败。',
        data: result.data,
      };
    }
    return result;
  } catch (_error) {
    return {
      success: false,
      code: 'NETWORK_ERROR',
      message: '管理 API 暂时不可用。',
      data: undefined as T,
    };
  }
}

export async function queryConnections(options?: Record<string, unknown>) {
  void options;
  return requestApi<ConnectionSnapshot[]>('/api/admin/v1/connections');
}

export async function querySessions(options?: Record<string, unknown>) {
  void options;
  return requestApi<LoginSession[]>('/api/admin/v1/sessions');
}

export async function banAddress(
  sourceAddress: string,
  durationSeconds = 180,
  disconnectExisting = true,
  reason?: string,
) {
  return requestApi<ManualBanResult>('/api/admin/v1/bans', {
    method: 'POST',
    body: JSON.stringify({
      sourceAddress,
      durationSeconds,
      disconnectExisting,
      reason,
    }),
  });
}

export type ConnectionTermination = {
  success: boolean;
  attempted: number;
  terminated: number;
  error?: string | null;
};

export async function disconnectConnection(connection: ConnectionSnapshot) {
  return requestApi<ConnectionTermination>('/api/admin/v1/connections/disconnect', {
    method: 'POST',
    body: JSON.stringify(connection),
  });
}

export async function disconnectSession(sessionId: string) {
  return requestApi<ConnectionTermination>(
    `/api/admin/v1/sessions/${encodeURIComponent(sessionId)}/disconnect`,
    { method: 'POST' },
  );
}
