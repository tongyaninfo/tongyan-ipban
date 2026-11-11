import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { defaultIpLocationSettings, type IpLocationBatch, type IpLocationSettings } from './ipLocation';
import { createIpLocationStore } from './ipLocationStore';

const ok = <T>(data: T) => ({ success: true, code: 'OK', message: '', data });
const enabled: IpLocationSettings = { ...defaultIpLocationSettings, enabled: true };
const subscriptions: Array<() => void> = [];
const fixture = (settingsValue = enabled) => {
  const settings = vi.fn(async () => ok(settingsValue));
  const lookup = vi.fn(async (ips: string[], _signal?: AbortSignal) => ok<IpLocationBatch>({
    enabled: true, revision: '1', items: ips.map((ip) => ({ ip, status: 'resolved', country: '中国', city: '杭州' })),
  }));
  const store = createIpLocationStore({ settings, lookup });
  const subscribe = (ip: string) => { const cleanup = store.subscribe(ip, vi.fn()); subscriptions.push(cleanup); return cleanup; };
  return { store, settings, lookup, subscribe };
};

beforeEach(() => { vi.useFakeTimers(); });
afterEach(() => { subscriptions.splice(0).forEach((cleanup) => cleanup()); vi.useRealTimers(); });

describe('shared IP location lookup queue', () => {
  it('deduplicates repeated cells and batches at most 100 source IPs', async () => {
    const { subscribe, lookup } = fixture();
    subscribe('1.1.1.1');
    subscribe('1.1.1.1');
    for (let index = 0; index < 104; index += 1) subscribe(`203.0.113.${index}`);
    await vi.advanceTimersByTimeAsync(50);
    expect(lookup.mock.calls.map(([ips]) => ips.length)).toEqual([100, 5]);
    expect(lookup.mock.calls.flatMap(([ips]) => ips).filter((ip) => ip === '1.1.1.1')).toHaveLength(1);
  });

  it('does not start location lookups when disabled and detects changes from another tab', async () => {
    const { subscribe, lookup, settings, store } = fixture(defaultIpLocationSettings);
    subscribe('1.1.1.1');
    await vi.advanceTimersByTimeAsync(25);
    expect(lookup).not.toHaveBeenCalled();
    settings.mockResolvedValue(ok(enabled));
    await vi.advanceTimersByTimeAsync(30_000);
    expect(lookup).toHaveBeenCalledTimes(1);
    expect(store.getSnapshot('1.1.1.1')?.status).toBe('resolved');
  });

  it('retains the cached result when a second component subscribes', async () => {
    const { subscribe, lookup, store } = fixture();
    subscribe('1.1.1.1');
    await vi.advanceTimersByTimeAsync(25);
    subscribe('1.1.1.1');
    await vi.advanceTimersByTimeAsync(25);
    expect(lookup).toHaveBeenCalledTimes(1);
    expect(store.getSnapshot('1.1.1.1')?.city).toBe('杭州');
  });

  it('polls queued results and stops timers after the last subscription ends', async () => {
    const { subscribe, lookup } = fixture();
    lookup.mockResolvedValue(ok({ enabled: true, revision: '1', items: [{ ip: '1.1.1.1', status: 'queued' }] }));
    const cleanup = subscribe('1.1.1.1');
    await vi.advanceTimersByTimeAsync(1_025);
    expect(lookup).toHaveBeenCalledTimes(2);
    cleanup();
    await vi.advanceTimersByTimeAsync(90_000);
    expect(lookup).toHaveBeenCalledTimes(2);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('backs off a congested result after ten polls', async () => {
    const { subscribe, lookup } = fixture();
    lookup.mockResolvedValue(ok({ enabled: true, revision: '1', items: [{ ip: '1.1.1.1', status: 'busy' }] }));
    subscribe('1.1.1.1');
    await vi.advanceTimersByTimeAsync(29_000);
    expect(lookup).toHaveBeenCalledTimes(10);
  });

  it('aborts in-flight work and rejects stale results after configuration changes', async () => {
    const { subscribe, lookup, store } = fixture();
    let complete: ((value: ReturnType<typeof ok<IpLocationBatch>>) => void) | undefined;
    lookup.mockImplementationOnce(() => new Promise((resolve) => { complete = resolve; }));
    subscribe('1.1.1.1');
    await vi.advanceTimersByTimeAsync(25);
    const signal = lookup.mock.calls[0][1];
    store.invalidate(defaultIpLocationSettings);
    expect(signal?.aborted).toBe(true);
    complete?.(ok({ enabled: true, revision: 'old', items: [{ ip: '1.1.1.1', status: 'resolved', country: '旧结果' }] }));
    await vi.advanceTimersByTimeAsync(25);
    expect(store.getSnapshot('1.1.1.1')?.status).toBe('disabled');
    expect(lookup).toHaveBeenCalledTimes(1);
  });

  it('does not overwrite existing cells with a result for another IP', async () => {
    const { subscribe, lookup, store } = fixture();
    lookup.mockResolvedValue(ok({ enabled: true, revision: '1', items: [{ ip: '8.8.8.8', status: 'resolved', country: '美国' }] }));
    subscribe('1.1.1.1');
    await vi.advanceTimersByTimeAsync(25);
    expect(store.getSnapshot('1.1.1.1')?.status).toBe('failed');
  });

  it('shows an unavailable state and backs off when the first configuration read fails', async () => {
    const { subscribe, settings, lookup, store } = fixture();
    settings.mockRejectedValueOnce(new Error('temporary failure'));
    subscribe('1.1.1.1');
    await vi.advanceTimersByTimeAsync(25);
    expect(store.getSnapshot('1.1.1.1')?.status).toBe('failed');
    expect(lookup).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(29_000);
    expect(settings).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(store.getSnapshot('1.1.1.1')?.status).toBe('resolved');
  });
});
