import { afterEach, describe, expect, it, vi } from 'vitest';
import { defaultIpLocationSettings, ipLocationDatabases, queryIpLocations, updateIpLocationSettings } from './ipLocation';

afterEach(() => vi.unstubAllGlobals());
describe('IP location HTTP contract', () => {
  it('sends the six supported databases and explicit management headers', async () => {
    const fetch = vi.fn(async () => new Response(JSON.stringify({ success: true, code: 'OK', message: '', data: defaultIpLocationSettings })));
    vi.stubGlobal('fetch', fetch);
    expect(ipLocationDatabases).toEqual(['CZ88', 'ip2location', 'ip2region', 'dbip', 'ipinfo', 'geolite2']);
    await updateIpLocationSettings(defaultIpLocationSettings);
    await queryIpLocations(['1.1.1.1', '2001:4860:4860::8888']);
    expect(fetch).toHaveBeenNthCalledWith(1, '/api/admin/v1/ip-location/settings', expect.objectContaining({
      method: 'PUT', headers: expect.objectContaining({ 'X-IPBan-Management': '1' }), body: JSON.stringify(defaultIpLocationSettings),
    }));
    expect(fetch).toHaveBeenNthCalledWith(2, '/api/admin/v1/ip-location/lookup', expect.objectContaining({
      method: 'POST', headers: expect.objectContaining({ 'X-IPBan-Management': '1' }), body: JSON.stringify({ ips: ['1.1.1.1', '2001:4860:4860::8888'] }),
    }));
  });
});
