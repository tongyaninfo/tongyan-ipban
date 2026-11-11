import { afterEach, describe, expect, it, vi } from 'vitest';
import { defaultNotificationSettings, getNotificationMessage, listNotificationMessages, sendTestNotification, updateNotificationSettings } from './notifications';

afterEach(() => vi.unstubAllGlobals());

function mockApi() {
  const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ success: true, code: 'OK', message: '', data: {} }), { status: 200 }));
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

describe('notification API contracts', () => {
  it('preserves the stored credential when no replacement is supplied and sends the configuration revision', async () => {
    const fetchMock = mockApi();
    await updateNotificationSettings({ ...defaultNotificationSettings, revision: 'revision-1' }, '');
    const [path, request] = fetchMock.mock.calls[0];
    expect(path).toBe('/api/admin/v1/notifications/settings');
    expect(request.headers['X-IPBan-Management']).toBe('1');
    expect(request.cache).toBe('no-store');
    expect(JSON.parse(request.body)).toEqual({ settings: { ...defaultNotificationSettings, revision: 'revision-1' } });
  });

  it('passes a replacement credential only in the write request and a test only to the explicit recipient', async () => {
    const fetchMock = mockApi();
    await updateNotificationSettings(defaultNotificationSettings, 'synthetic-credential');
    expect(JSON.parse(fetchMock.mock.calls[0][1].body).credential).toBe('synthetic-credential');
    await sendTestNotification('operator@example.com');
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({ recipient: 'operator@example.com' });
  });

  it('sends an explicit credential clear without a replacement secret', async () => {
    const fetchMock = mockApi();
    await updateNotificationSettings(defaultNotificationSettings, undefined, true);
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ settings: defaultNotificationSettings, credential: null, clearCredential: true });
  });

  it('encodes server-side paging and filters, omitting empty filters', async () => {
    const fetchMock = mockApi();
    await listNotificationMessages({ page: 2, pageSize: 50, status: 'sent', eventType: 'loginFailure' });
    expect(fetchMock.mock.calls[0][0]).toBe('/api/admin/v1/notifications/messages?page=2&pageSize=50&status=sent&eventType=loginFailure');
    await listNotificationMessages({ page: 1, pageSize: 20 });
    expect(fetchMock.mock.calls[1][0]).toBe('/api/admin/v1/notifications/messages?page=1&pageSize=20');
    await getNotificationMessage('9223372036854775807');
    expect(fetchMock.mock.calls[2][0]).toBe('/api/admin/v1/notifications/messages/9223372036854775807');
  });
});
