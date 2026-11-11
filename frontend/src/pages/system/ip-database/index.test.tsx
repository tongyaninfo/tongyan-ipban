import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { PropsWithChildren, ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import messages from '@/locales/zh-CN/ipLocation';
import { defaultIpLocationSettings, queryIpLocationSettings, updateIpLocationSettings } from '@/services/ipban/ipLocation';
import { ipLocationStore } from '@/services/ipban/ipLocationStore';
import routes from '../../../../config/routes';
import IpDatabasePage, { isIpLocationHost } from './index';

vi.mock('@umijs/max', () => ({ useIntl: () => ({ formatMessage: ({ id }: { id: string }) => messages[id as keyof typeof messages] ?? id }) }));
vi.mock('@ant-design/pro-components', () => ({ PageContainer: ({ children, title }: PropsWithChildren<{ title: ReactNode }>) => <main><h1>{title}</h1>{children}</main> }));
vi.mock('@/services/ipban/ipLocation', async (original) => ({ ...await original<typeof import('@/services/ipban/ipLocation')>(), queryIpLocationSettings: vi.fn(), updateIpLocationSettings: vi.fn() }));
vi.mock('@/services/ipban/ipLocationStore', () => ({ ipLocationStore: { invalidate: vi.fn() } }));
const ok = <T,>(data: T) => ({ success: true, code: 'OK', message: '', data });
beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(queryIpLocationSettings).mockResolvedValue(ok(defaultIpLocationSettings));
  vi.mocked(updateIpLocationSettings).mockImplementation(async (settings) => ok(settings));
});
afterEach(() => cleanup());

describe('IP database configuration page', () => {
  it('identifies the TongYan adapter and keeps the official source separate from a configured host', async () => {
    vi.mocked(queryIpLocationSettings).mockResolvedValue(ok({ ...defaultIpLocationSettings, host: 'custom.example.com' }));
    render(<IpDatabasePage />);
    expect(screen.getByText('通研IP适配器')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'ip.tongyaninfo.com' })).toHaveAttribute('href', 'https://ip.tongyaninfo.com/');
    expect(await screen.findByLabelText('服务地址')).toHaveValue('custom.example.com');
  });

  it('loads the disabled default and saves the selected configuration', async () => {
    render(<IpDatabasePage />);
    const host = await screen.findByLabelText('服务地址');
    expect(host).toHaveValue('ip.tongyaninfo.com');
    expect(Number((screen.getByLabelText('解析超时（秒）') as HTMLInputElement).value)).toBe(2);
    expect(screen.getByRole('switch')).not.toBeChecked();
    fireEvent.click(screen.getByRole('switch'));
    fireEvent.click(screen.getByRole('button', { name: /保存配置/ }));
    await waitFor(() => expect(updateIpLocationSettings).toHaveBeenCalledWith({ ...defaultIpLocationSettings, enabled: true }));
    expect(ipLocationStore.invalidate).toHaveBeenCalledWith({ ...defaultIpLocationSettings, enabled: true });
    expect(routes.find((route) => route.path === '/system')?.routes).toContainEqual(expect.objectContaining({ path: '/system/ip-database', component: './system/ip-database' }));
  });

  it('rejects a full URL in the host field before sending configuration', async () => {
    render(<IpDatabasePage />);
    const host = await screen.findByLabelText('服务地址');
    fireEvent.change(host, { target: { value: 'https://example.com/path' } });
    fireEvent.click(screen.getByRole('button', { name: /保存配置/ }));
    expect(await screen.findByText('请输入合法域名或 IP，不包含协议、端口、路径或账户信息。')).toBeInTheDocument();
    expect(updateIpLocationSettings).not.toHaveBeenCalled();
  });

  it('shows load failures without allowing a default to overwrite unavailable settings', async () => {
    vi.mocked(queryIpLocationSettings).mockResolvedValue({ success: false, code: 'FAILED', message: '配置加载失败', data: defaultIpLocationSettings });
    render(<IpDatabasePage />);
    expect(await screen.findByText('配置加载失败')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /保存配置/ })).toBeDisabled();
    expect(updateIpLocationSettings).not.toHaveBeenCalled();
  });

  it('keeps the form and cached configuration unchanged when saving fails', async () => {
    vi.mocked(updateIpLocationSettings).mockResolvedValue({ success: false, code: 'FAILED', message: '配置保存失败', data: defaultIpLocationSettings });
    render(<IpDatabasePage />);
    await screen.findByLabelText('服务地址');
    fireEvent.click(screen.getByRole('button', { name: /保存配置/ }));
    expect(await screen.findByText('配置保存失败')).toBeInTheDocument();
    expect(ipLocationStore.invalidate).not.toHaveBeenCalled();
  });

  it.each(['ip.tongyaninfo.com', '192.0.2.1', '2001:db8::1', '[2001:db8::1]'])('accepts a host: %s', (value) => {
    expect(isIpLocationHost(value)).toBe(true);
  });
  it.each(['', 'https://example.com', 'example.com:80', 'name@example.com', 'example.com/path', 'fe80::1%en0'])('rejects an invalid host: %s', (value) => {
    expect(isIpLocationHost(value)).toBe(false);
  });
});
