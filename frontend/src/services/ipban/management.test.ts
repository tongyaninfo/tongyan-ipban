import { afterEach, describe, expect, it, vi } from 'vitest';
import { deleteLogFile, requestManagement, unbanSource } from './management';

afterEach(() => vi.restoreAllMocks());

describe('single log file deletion request', () => {
  it('encodes the exact filename and uses the shared DELETE contract', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      success: true, code: 'OK', message: '', data: null,
    }), { status: 200 }));
    const name = 'rotated log #1.ndjson.gz';
    expect(await deleteLogFile(name)).toMatchObject({ success: true, data: null });
    expect(fetchMock).toHaveBeenCalledWith(`/api/admin/v1/logs/files/${encodeURIComponent(name)}`, expect.objectContaining({ method: 'DELETE' }));
  });

  it('preserves a protected-file conflict for localized display', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      success: false, code: 'LOG_FILE_PROTECTED', message: 'protected', data: null,
    }), { status: 409 }));
    expect(await deleteLogFile('active.ndjson')).toMatchObject({ success: false, code: 'LOG_FILE_PROTECTED' });
  });
});

describe('manual unban request', () => {
  it('preserves long action IDs and posts the specific source through the authenticated same-origin API', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true, json: async () => ({ success: true, code: 'OK', message: '', data: {} }),
    } as Response);
    const id = '9223372036854775806';
    await unbanSource('192.0.2.42', id);
    expect(fetchMock).toHaveBeenCalledWith('/api/admin/v1/bans/unban', expect.objectContaining({
      method: 'POST', body: JSON.stringify({ sourceAddress: '192.0.2.42', actionId: id }),
    }));
  });

  it('retains a conflict result so the page can refresh stale decisions', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false, status: 409,
      json: async () => ({ success: false, code: 'BAN_NOT_CURRENT', message: 'stale', data: null }),
    } as Response);
    const result = await unbanSource('192.0.2.42', '123');
    expect(result.success).toBe(false);
    expect(result.code).toBe('BAN_NOT_CURRENT');
  });
});

describe('management response failures', () => {
  it('preserves a field validation response from HTTP 400', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      success: false, code: 'INVALID_BAN_POLICY_DURATION', message: 'invalid duration', data: null,
    }), { status: 400 }));
    expect(await requestManagement('/api/admin/v1/policies')).toMatchObject({
      success: false, code: 'INVALID_BAN_POLICY_DURATION', message: 'invalid duration',
    });
  });

  it.each([400, 500])('does not disguise a non-JSON HTTP %s response as a network error', async (status) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('<html>failure</html>', { status }));
    const result = await requestManagement('/api/admin/v1/policies');
    expect(result).toMatchObject({ success: false, code: `HTTP_${status}` });
    expect(result.message).not.toContain('暂时不可用');
  });

  it('reports malformed successful responses separately', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('null', { status: 200 }));
    expect(await requestManagement('/api/admin/v1/policies')).toMatchObject({ success: false, code: 'INVALID_RESPONSE' });
  });

  it('rejects incomplete JSON contracts before page error handling', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{"success":false}', { status: 200 }));
    expect(await requestManagement('/api/admin/v1/policies')).toMatchObject({ success: false, code: 'INVALID_RESPONSE' });
  });

  it('uses NETWORK_ERROR only when fetch itself fails', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('fetch failed'));
    expect(await requestManagement('/api/admin/v1/policies')).toMatchObject({ success: false, code: 'NETWORK_ERROR' });
  });
});
