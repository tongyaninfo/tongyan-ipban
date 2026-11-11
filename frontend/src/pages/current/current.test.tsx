import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { ConfigProvider, Table } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { useEffect, useImperativeHandle, useState, type PropsWithChildren, type ReactNode, type Ref } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import messages from '@/locales/zh-CN/pages';
import { subscribeManagementRealtime } from '@/services/ipban/realtime';
import {
  banAddress,
  disconnectConnection,
  disconnectSession,
  queryConnections,
  querySessions,
  type ConnectionSnapshot,
  type LoginSession,
} from '@/services/ipban/system';
import routes from '../../../config/routes';
import ConnectionsPage from './connections';
import SessionsPage from './sessions';

vi.mock('@/services/ipban/ipLocation', async (original) => {
  const service = await original<typeof import('@/services/ipban/ipLocation')>();
  return { ...service, queryIpLocationSettings: vi.fn(async () => ({ success: true, code: 'OK', message: '', data: service.defaultIpLocationSettings })) };
});
vi.mock('@umijs/max', () => ({
  useIntl: () => ({
    formatMessage: ({
      id,
      defaultMessage,
    }: {
      id: string;
      defaultMessage: string;
    }) => messages[id as keyof typeof messages] ?? defaultMessage,
  }),
}));
vi.mock('@ant-design/pro-components', () => ({
  // 保留真实 antd 表格及操作弹窗，仅隔离依赖 Umi 的 ProTable 请求调度。
  ProTable: ({ actionRef, request, columns, toolBarRender, rowKey, locale, scroll }: {
    actionRef: Ref<{ reload: () => Promise<void> }>;
    request: () => Promise<{ data: any[] }>;
    columns: any[];
    toolBarRender: () => ReactNode[];
    rowKey: (record: any) => string;
    locale: { emptyText: ReactNode };
    scroll: { x: number };
  }) => {
    const [data, setData] = useState<any[]>([]);
    const reload = async () => { setData((await request()).data); };
    useEffect(() => { void reload(); }, []);
    useImperativeHandle(actionRef, () => ({ reload }));
    return <>{toolBarRender()}<Table dataSource={data} columns={columns} rowKey={rowKey} locale={locale} scroll={scroll} pagination={false} /></>;
  },
  PageContainer: ({
    children,
    title,
    content,
  }: PropsWithChildren<{ title: ReactNode; content: ReactNode }>) => (
    <main>
      <h1>{title}</h1>
      {content}
      {children}
    </main>
  ),
}));
vi.mock('@/services/ipban/system', () => ({
  queryConnections: vi.fn(),
  querySessions: vi.fn(),
  disconnectConnection: vi.fn(),
  disconnectSession: vi.fn(),
  banAddress: vi.fn(),
}));
vi.mock('@/services/ipban/realtime', () => ({
  subscribeManagementRealtime: vi.fn(),
}));

const connection: ConnectionSnapshot = {
  protocol: 'tcp',
  state: 'ESTAB',
  remoteIp: '2001:db8::1',
  remotePort: 51000,
  localIp: '2001:db8::2',
  localPort: 5985,
  processName: 'svchost',
  processId: 44,
  observedAtUtc: '2026-01-01T00:00:00Z',
};
const session: LoginSession = {
  protocol: 'WinRm',
  sessionId: 'WinRm:44:[2001:db8::1]:51000',
  usernameAvailability: 'notCollected',
  remoteIp: connection.remoteIp,
  remotePort: connection.remotePort,
  localIp: connection.localIp,
  localPort: connection.localPort,
  processName: 'svchost',
  processAvailability: 'available',
  canDisconnect: true,
  startedAtUtc: '2026-01-01T00:00:00Z',
  lastObservedAtUtc: '2026-01-01T00:00:01Z',
};
const ok = <T,>(data: T) => ({ success: true, code: 'OK', message: '', data });
const renderPage = (page: ReactNode) =>
  render(
    <ConfigProvider locale={zhCN} theme={{ token: { motion: false } }}>
      {page}
    </ConfigProvider>,
  );

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(queryConnections).mockResolvedValue(ok([connection]));
  vi.mocked(querySessions).mockResolvedValue(ok([session]));
  const termination = { success: true, attempted: 1, terminated: 1 };
  vi.mocked(disconnectConnection).mockResolvedValue(ok(termination));
  vi.mocked(disconnectSession).mockResolvedValue(ok(termination));
  vi.mocked(banAddress).mockResolvedValue(ok({
    firewallAction: { provider: 'Windows', sourceAddress: connection.remoteIp, actionStatus: 'Applied', firewallStatus: 'Enabled', completedAtUtc: connection.observedAtUtc },
    existingConnectionTermination: termination, durationSeconds: 180,
  }));
  vi.mocked(subscribeManagementRealtime).mockImplementation(async () =>
    vi.fn<() => void>(),
  );
});
afterEach(() => cleanup());

describe('separate current pages', () => {
  it('defaults live state to the restored sessions page before network connections', () => {
    const current = routes.find((route) => route.path === '/current');
    expect(current?.routes?.[0]).toMatchObject({
      redirect: '/current/sessions',
    });
    expect(current?.routes?.slice(1).map((route) => route.path)).toEqual([
      '/current/sessions',
      '/current/connections',
    ]);
    expect(current?.routes?.[1]).toMatchObject({
      name: 'sessions',
      component: './current/sessions',
    });
  });

  it('queries only network connections and displays translated states without session columns', async () => {
    renderPage(<ConnectionsPage />);
    expect(await screen.findByText('已建立')).toBeInTheDocument();
    expect(screen.getByText('WinRM')).toBeInTheDocument();
    expect(screen.getByText('[2001:db8::1]:51000')).toBeInTheDocument();
    expect(
      screen.queryByRole('columnheader', { name: '用户名' }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('columnheader', { name: '会话 ID' }),
    ).not.toBeInTheDocument();
    expect(querySessions).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: /刷新/ }));
    await waitFor(() => expect(queryConnections).toHaveBeenCalledTimes(2));
  });

  it('sends the unmodified connection when disconnecting and then refreshes', async () => {
    renderPage(<ConnectionsPage />);
    fireEvent.click(await screen.findByRole('button', { name: /下\s*线/ }));
    await waitFor(() => expect(screen.getAllByRole('button', { name: /下\s*线/ })).toHaveLength(2));
    const buttons = screen.getAllByRole('button', { name: /下\s*线/ });
    fireEvent.click(buttons[buttons.length - 1]);
    await waitFor(() =>
      expect(disconnectConnection).toHaveBeenCalledWith(connection),
    );
    await waitFor(() => expect(queryConnections).toHaveBeenCalledTimes(2));
    expect(vi.mocked(disconnectConnection).mock.calls[0][0].state).toBe(
      'ESTAB',
    );
    expect(vi.mocked(disconnectConnection).mock.calls[0][0].protocol).toBe(
      'tcp',
    );
  });

  it('refreshes sessions on both channels and manually, and releases subscriptions', async () => {
    const cleanups = [vi.fn(), vi.fn()];
    vi.mocked(subscribeManagementRealtime)
      .mockResolvedValueOnce(cleanups[0])
      .mockResolvedValueOnce(cleanups[1]);
    const view = renderPage(<SessionsPage />);
    expect(await screen.findByText(session.sessionId)).toBeInTheDocument();
    expect(
      screen.getByRole('columnheader', { name: '用户名' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('columnheader', { name: '观测时间' }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole('columnheader', { name: '开始时间' }),
    ).not.toBeInTheDocument();
    expect(subscribeManagementRealtime).toHaveBeenCalledWith(
      'connections',
      expect.any(Function),
    );
    expect(subscribeManagementRealtime).toHaveBeenCalledWith(
      'security-events',
      expect.any(Function),
    );
    vi.mocked(querySessions).mockResolvedValue(
      ok([{ ...session, username: 'operator' }]),
    );
    const listeners = vi.mocked(subscribeManagementRealtime).mock.calls;
    act(() =>
      listeners.find(([channel]) => channel === 'security-events')?.[1]({
        channel: 'security-events',
      }),
    );
    expect(await screen.findByText('operator')).toBeInTheDocument();
    act(() =>
      listeners.find(([channel]) => channel === 'connections')?.[1]({
        channel: 'connections',
      }),
    );
    await waitFor(() => expect(querySessions).toHaveBeenCalledTimes(3));
    fireEvent.click(screen.getByRole('button', { name: /刷新/ }));
    await waitFor(() => expect(querySessions).toHaveBeenCalledTimes(4));
    expect(queryConnections).not.toHaveBeenCalled();
    view.unmount();
    for (const unsubscribe of cleanups)
      expect(unsubscribe).toHaveBeenCalledOnce();
  });

  it('disconnects a session using its original ID and refreshes the list', async () => {
    renderPage(<SessionsPage />);
    fireEvent.click(await screen.findByRole('button', { name: /下\s*线/ }));
    await waitFor(() => expect(screen.getAllByRole('button', { name: /下\s*线/ })).toHaveLength(2));
    const buttons = screen.getAllByRole('button', { name: /下\s*线/ });
    fireEvent.click(buttons[buttons.length - 1]);
    await waitFor(() =>
      expect(disconnectSession).toHaveBeenCalledWith(session.sessionId),
    );
    await waitFor(() => expect(querySessions).toHaveBeenCalledTimes(2));
    expect(banAddress).not.toHaveBeenCalled();
  });

  it('cleans up subscriptions that complete after leaving the sessions page', async () => {
    const resolveSubscriptions: Array<(cleanup: () => void) => void> = [];
    vi.mocked(subscribeManagementRealtime).mockImplementation(
      () => new Promise((resolve) => resolveSubscriptions.push(resolve)),
    );
    const view = renderPage(<SessionsPage />);
    view.unmount();
    const cleanups = [vi.fn(), vi.fn()];
    await act(async () => {
      for (const [index, resolve] of resolveSubscriptions.entries()) resolve(cleanups[index]);
    });
    for (const unsubscribe of cleanups)
      expect(unsubscribe).toHaveBeenCalledOnce();
  });
});
