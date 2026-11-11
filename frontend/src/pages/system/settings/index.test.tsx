import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { ConfigProvider } from 'antd';
import type { PropsWithChildren } from 'react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import messages from '@/locales/zh-CN/syslog';
import {
  getSyslogSettings,
  getSyslogStatus,
  saveSyslogSettings,
  testSyslogTarget,
  type SyslogSettings,
} from '@/services/ipban/syslog';
import SettingsPage from './index';

vi.mock('@umijs/max', () => ({
  useIntl: () => ({
    formatMessage: (
      { id, defaultMessage }: { id: string; defaultMessage?: string },
      values?: Record<string, string | number>,
    ) => {
      let message =
        messages[id as keyof typeof messages] ?? defaultMessage ?? id;
      for (const [key, value] of Object.entries(values ?? {})) {
        message = message.replace(`{${key}}`, String(value));
      }
      return message;
    },
  }),
}));
vi.mock('@ant-design/pro-components', () => ({
  PageContainer: ({ children }: PropsWithChildren) => <main>{children}</main>,
}));
vi.mock('@/services/ipban/syslog', () => ({
  getSyslogSettings: vi.fn(),
  getSyslogStatus: vi.fn(),
  saveSyslogSettings: vi.fn(),
  testSyslogTarget: vi.fn(),
}));

const ok = <T,>(data: T) => ({ success: true, code: 'OK', message: '', data });
const initial: SyslogSettings = {
  enabled: false,
  configRevision: '0',
  targets: [],
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getSyslogSettings).mockResolvedValue(ok(initial));
  vi.mocked(getSyslogStatus).mockResolvedValue(
    ok({
      desiredRevision: '0',
      api: {
        sourceProcess: 'api',
        configurationState: 'ready',
        appliedRevision: '0',
        targets: [],
        droppedCount: 0,
        priorityDroppedCount: 0,
      },
      agent: null,
    }),
  );
});
afterEach(cleanup);

it('tests a newly saved target by server-assigned ID and revision while forwarding is disabled', async () => {
  vi.mocked(saveSyslogSettings).mockImplementation(async (settings) =>
    ok({
      ...settings,
      configRevision: 'new-revision',
      targets: settings.targets.map((target) => ({
        ...target,
        id: 'assigned-target',
        deliveryTargetVersion: 'v1',
      })),
    }),
  );
  vi.mocked(testSyslogTarget).mockResolvedValue(
    ok({
      testId: 'test-id',
      targetId: 'assigned-target',
      protocol: 'tls',
      stage: 'tlsWritten',
      message: '',
      completedAtUtc: '2026-11-11T00:00:00Z',
    }),
  );
  render(
    <ConfigProvider theme={{ token: { motion: false } }}>
      <SettingsPage />
    </ConfigProvider>,
  );
  fireEvent.click(await screen.findByRole('button', { name: /添加服务器/ }));
  expect(
    screen.getByRole('checkbox', { name: '忽略 SSL 错误' }),
  ).not.toBeChecked();
  expect(screen.getByRole('button', { name: /测试发送/ })).toBeDisabled();
  fireEvent.change(screen.getByLabelText('名称'), {
    target: { value: '接收器' },
  });
  fireEvent.change(screen.getByLabelText('服务器地址'), {
    target: { value: 'receiver.example.test' },
  });
  fireEvent.click(screen.getByRole('button', { name: /保存$/ }));
  await waitFor(() =>
    expect(screen.getByRole('button', { name: /测试发送/ })).toBeEnabled(),
  );
  expect(saveSyslogSettings).toHaveBeenCalledWith(
    expect.objectContaining({
      enabled: false,
      configRevision: '0',
      targets: [
        expect.objectContaining({
          protocol: 'tls',
          port: 6514,
          ignoreSslErrors: false,
        }),
      ],
    }),
  );
  fireEvent.click(screen.getByRole('button', { name: /测试发送/ }));
  expect(await screen.findByText('测试编号 test-id')).toBeInTheDocument();
  expect(testSyslogTarget).toHaveBeenCalledWith(
    'assigned-target',
    'new-revision',
  );
});

it('blocks configuration edits if the saved settings cannot be loaded', async () => {
  vi.mocked(getSyslogSettings).mockResolvedValue({
    success: false,
    code: 'HTTP_503',
    message: '配置暂不可用。',
    data: initial,
  });
  render(<SettingsPage />);
  expect(await screen.findByText('配置暂不可用。')).toBeInTheDocument();
  expect(
    screen.queryByRole('button', { name: /添加服务器/ }),
  ).not.toBeInTheDocument();
  expect(saveSyslogSettings).not.toHaveBeenCalled();
});

it('omits the legacy facility field when saving a target', async () => {
  const target = {
    id: 'saved-target',
    deliveryTargetVersion: 'v1',
    name: '接收器',
    enabled: true,
    host: 'receiver.example.test',
    port: 6514,
    protocol: 'tls',
    maxSeverity: 4,
    ignoreSslErrors: false,
    framing: 'octet',
  } as const;
  vi.mocked(getSyslogSettings).mockResolvedValue(
    ok({ ...initial, targets: [{ ...target, facility: 23 }] }),
  );
  vi.mocked(saveSyslogSettings).mockImplementation(async (settings) =>
    ok(settings),
  );
  render(<SettingsPage />);
  const name = await screen.findByLabelText('名称');
  expect(screen.queryByLabelText(/设施/)).not.toBeInTheDocument();
  fireEvent.change(name, { target: { value: '新接收器' } });
  fireEvent.click(screen.getByRole('button', { name: /保存$/ }));
  await waitFor(() =>
    expect(saveSyslogSettings).toHaveBeenCalledWith({
      ...initial,
      targets: [{ ...target, name: '新接收器' }],
    }),
  );
});
