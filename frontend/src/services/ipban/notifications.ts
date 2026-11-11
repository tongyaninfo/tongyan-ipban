import { requestManagement } from './management';

export type NotificationEventType = 'loginSuccess' | 'loginFailure' | 'ban' | 'unban';
export type NotificationStatus = 'queued' | 'sending' | 'retry' | 'sent' | 'failed' | 'expired' | 'cancelled';
export type NotificationRule = { eventType: NotificationEventType; enabled: boolean; intervalSeconds: number };
export type NotificationSettings = {
  enabled: boolean;
  host: string;
  port: number;
  security: 'ssl' | 'starttls' | 'none';
  fromAddress: string;
  username: string;
  fromName: string;
  recipients: string[];
  hasCredential: boolean;
  maxPerMinute: number;
  maxPerHour: number;
  retryCount: number;
  retentionDays: number;
  queueLifetimeHours: number;
  revision: string;
  enabledSinceUtc?: string | null;
  rules: NotificationRule[];
};
export const defaultNotificationSettings: NotificationSettings = {
  enabled: false, host: '', port: 465, security: 'ssl', fromAddress: '', username: '',
  fromName: '通研技术', recipients: [], hasCredential: false, maxPerMinute: 10,
  maxPerHour: 60, retryCount: 3, retentionDays: 30, queueLifetimeHours: 24, revision: '',
  rules: [
    { eventType: 'loginSuccess', enabled: true, intervalSeconds: 300 },
    { eventType: 'loginFailure', enabled: true, intervalSeconds: 600 },
    { eventType: 'ban', enabled: true, intervalSeconds: 60 },
    { eventType: 'unban', enabled: true, intervalSeconds: 60 },
  ],
};
export type NotificationMessage = {
  id: string;
  eventType: NotificationEventType | 'test';
  status: NotificationStatus;
  recipient: string;
  subject: string;
  sourceIp?: string | null;
  eventCount: number;
  attempts: number;
  createdAtUtc: string;
  sentAtUtc?: string | null;
  nextAttemptAtUtc?: string | null;
  lastErrorCode?: string | null;
  lastErrorMessage?: string | null;
};
export type NotificationMessagePage = {
  items: NotificationMessage[];
  total: number;
  page: number;
  pageSize: number;
  pendingEvents: number;
  suppressedEvents: number;
};
export type NotificationEvent = {
  eventType: string;
  sourceId: string;
  hostName: string;
  sourceIp?: string | null;
  protocol?: string | null;
  username?: string | null;
  occurredAtUtc: string;
  status: string;
  action?: string | null;
  reason?: string | null;
  durationSeconds?: number | null;
  provider?: string | null;
  originalActionId?: string | null;
};
export type NotificationMessageDetail = {
  message: NotificationMessage;
  htmlBody: string;
  textBody: string;
  templateVersion: string;
  messageId: string;
  events: NotificationEvent[];
};
export type NotificationPreview = {
  subject: string;
  htmlBody: string;
  textBody: string;
  templateVersion: string;
};
export type NotificationMessageQuery = { page: number; pageSize: number; status?: NotificationStatus; eventType?: NotificationEventType | 'test' };

const base = '/api/admin/v1/notifications';
const mutationHeaders = { 'X-IPBan-Management': '1' };
export const getNotificationSettings = (signal?: AbortSignal) => requestManagement<NotificationSettings>(`${base}/settings`, { signal, cache: 'no-store' });
export const updateNotificationSettings = (settings: NotificationSettings, credential?: string, clearCredential = false) => requestManagement<NotificationSettings>(`${base}/settings`, {
  method: 'PUT', headers: mutationHeaders, cache: 'no-store',
  // 未输入新授权码时省略字段，避免掩码或空字符串覆盖现有凭据。
  body: JSON.stringify({ settings, ...(clearCredential ? { credential: null, clearCredential: true } : credential ? { credential } : {}) }),
});
export const sendTestNotification = (recipient: string) => requestManagement<{ messageIds: string[] }>(`${base}/test`, {
  method: 'POST', headers: mutationHeaders, body: JSON.stringify({ recipient }),
});
export const listNotificationMessages = (query: NotificationMessageQuery, signal?: AbortSignal) => {
  const params = new URLSearchParams({ page: String(query.page), pageSize: String(query.pageSize) });
  if (query.status) params.set('status', query.status);
  if (query.eventType) params.set('eventType', query.eventType);
  return requestManagement<NotificationMessagePage>(`${base}/messages?${params.toString()}`, { signal, cache: 'no-store' });
};
export const getNotificationMessage = (id: string, signal?: AbortSignal) => requestManagement<NotificationMessageDetail>(`${base}/messages/${encodeURIComponent(id)}`, { signal, cache: 'no-store' });
export const previewNotification = (eventType: NotificationEventType, signal?: AbortSignal) => requestManagement<NotificationPreview>(`${base}/preview/${encodeURIComponent(eventType)}`, { signal, cache: 'no-store' });
