import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import messages from '@/locales/zh-CN/ipLocation';
import type { IpLocationResult } from '@/services/ipban/ipLocation';
import IpLocationText, { locationDescription } from './index';

const state = vi.hoisted(() => ({ result: undefined as IpLocationResult | undefined, listeners: new Set<() => void>() }));
vi.mock('@umijs/max', () => ({ useIntl: () => ({ formatMessage: ({ id }: { id: string }) => messages[id as keyof typeof messages] ?? id }) }));
vi.mock('@/services/ipban/ipLocationStore', () => ({ ipLocationStore: {
  subscribe: (_ip: string, listener: () => void) => { state.listeners.add(listener); return () => state.listeners.delete(listener); },
  getSnapshot: () => state.result,
} }));
beforeEach(() => { state.result = undefined; });
afterEach(() => cleanup());
const update = (result: IpLocationResult) => act(() => { state.result = result; state.listeners.forEach((listener) => { listener(); }); });

describe('source IP presentation', () => {
  it('renders IPv6 and port immediately, then adds the returned location on a second line', () => {
    render(<IpLocationText ip="2001:4860:4860::8888" port={443} endpoint />);
    const ip = screen.getByText('[2001:4860:4860::8888]:443');
    update({ ip: '2001:4860:4860::8888', status: 'resolved', country: '美国', province: '加利福尼亚州', city: '山景城', district: '示例区', region: '示例归属地' });
    const location = screen.getByText('示例归属地 · 美国 · 加利福尼亚州 · 山景城 · 示例区');
    expect(ip).toBeInTheDocument();
    expect(location).toHaveStyle({ display: 'block' });
  });

  it('keeps the source address visible when lookup times out or is disabled', () => {
    render(<IpLocationText ip="1.1.1.1" />);
    update({ ip: '1.1.1.1', status: 'timeout' });
    expect(screen.getByText('1.1.1.1')).toBeInTheDocument();
    expect(screen.getByText('归属地解析超时')).toBeInTheDocument();
    update({ ip: '1.1.1.1', status: 'disabled' });
    expect(screen.getByText('1.1.1.1')).toBeInTheDocument();
    expect(screen.queryByText('归属地解析超时')).not.toBeInTheDocument();
  });

  it('does not invent missing subdivision fields and identifies CIDR ranges', () => {
    expect(locationDescription({ ip: '1.1.1.1', status: 'resolved', country: '中国', province: '上海', city: '上海' })).toBe('中国 · 上海');
    expect(locationDescription({ ip: '1.1.1.1', status: 'resolved', country: '澳大利亚', province: '昆士兰', region: '昆士兰', city: 'Brisbane' })).toBe('澳大利亚 · 昆士兰 · Brisbane');
    expect(locationDescription({ ip: '1.1.1.1', status: 'resolved', isp: 'Cloudflare', asName: 'Cloudflare', asn: 'AS13335' })).toBe('Cloudflare · AS13335');
    render(<IpLocationText ip="192.0.2.0/24" />);
    update({ ip: '192.0.2.0/24', status: 'network' });
    expect(screen.getByText('CIDR 网段，不解析单点归属地')).toBeInTheDocument();
  });
});
