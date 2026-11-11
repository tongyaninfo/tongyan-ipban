import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { PropsWithChildren, ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import messages from '@/locales/zh-CN/notifications';
import { defaultNotificationSettings, getNotificationMessage, getNotificationSettings, listNotificationMessages, previewNotification, sendTestNotification, updateNotificationSettings, type NotificationMessage, type NotificationSettings } from '@/services/ipban/notifications';
import routes from '../../../../config/routes';
import NotificationsPage, { isNotificationHost } from './index';
import MailRecords, { MailDetail } from './MailRecords';

vi.mock('@umijs/max', () => ({ useIntl: () => ({ locale: 'zh-CN', formatMessage: ({ id }: { id: string }, values?: Record<string, string | number>) => {
  let value: string = messages[id as keyof typeof messages] ?? id;
  for (const [key, replacement] of Object.entries(values ?? {})) value = value.replace(`{${key}}`, String(replacement));
  return value;
} }) }));
vi.mock('@ant-design/pro-components', () => ({ PageContainer: ({ children, title }: PropsWithChildren<{ title: ReactNode }>) => <main><h1>{title}</h1>{children}</main> }));
vi.mock('@/services/ipban/notifications', async (original) => ({ ...await original<typeof import('@/services/ipban/notifications')>(),
  getNotificationSettings: vi.fn(), updateNotificationSettings: vi.fn(), sendTestNotification: vi.fn(),
  listNotificationMessages: vi.fn(), getNotificationMessage: vi.fn(), previewNotification: vi.fn(),
}));

const ok = <T,>(data: T) => ({ success: true, code: 'OK', message: '', data });
const configured = (): NotificationSettings => ({ ...structuredClone(defaultNotificationSettings), host: 'smtp.example.com', fromAddress: 'ipban@example.com', username: 'ipban@example.com', recipients: ['admin@example.com'], hasCredential: true, revision: 'revision-1' });
const sentMessage: NotificationMessage = {
  id: '9223372036854775807', eventType: 'ban', status: 'sent', recipient: 'admin@example.com',
  subject: '通研IPBan-封禁通知', sourceIp: '192.0.2.45', eventCount: 1, attempts: 1,
  createdAtUtc: '2026-11-10T01:00:00Z', sentAtUtc: '2026-11-10T01:00:10Z',
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getNotificationSettings).mockResolvedValue(ok(configured()));
  vi.mocked(updateNotificationSettings).mockImplementation(async (settings) => ok({ ...settings, revision: 'revision-2' }));
  vi.mocked(sendTestNotification).mockResolvedValue(ok({ messageIds: ['test-1'] }));
  vi.mocked(listNotificationMessages).mockResolvedValue(ok({ items: [], total: 0, page: 1, pageSize: 20, pendingEvents: 0, suppressedEvents: 0 }));
  vi.mocked(previewNotification).mockResolvedValue(ok({ subject: '通研IPBan-登录成功通知', htmlBody: '<p>示例登录</p>', textBody: '示例登录', templateVersion: '1' }));
  vi.mocked(getNotificationMessage).mockResolvedValue(ok({ message: sentMessage, htmlBody: '<p>历史邮件</p><img src="https://external.invalid/pixel">', textBody: '历史纯文本邮件', templateVersion: '1', messageId: '<message-1@example.com>', events: [] }));
});
afterEach(() => cleanup());

describe('notification settings page', () => {
  it('adds the system menu and defaults to encrypted mail without revealing a saved credential', async () => {
    render(<NotificationsPage />);
    await waitFor(() => expect(screen.getByLabelText('SMTP 服务器地址')).toHaveValue('smtp.example.com'));
    expect(screen.getByRole('checkbox', { name: '启用 SSL/TLS' })).toBeChecked();
    expect(screen.getByLabelText('授权码 / SMTP 密码')).toHaveValue('');
    expect(screen.getByText('已配置；留空保留现有授权码。')).toBeInTheDocument();
    expect(routes.find((route) => route.path === '/system')?.routes).toContainEqual(expect.objectContaining({ path: '/system/notifications', component: './system/notifications' }));
    fireEvent.click(screen.getByRole('button', { name: /保存设置/ }));
    await waitFor(() => expect(updateNotificationSettings).toHaveBeenCalledWith(expect.objectContaining({ security: 'ssl', revision: 'revision-1', hasCredential: true }), ''));
  });

  it('does not let a failed load overwrite existing configuration with defaults', async () => {
    vi.mocked(getNotificationSettings).mockResolvedValue({ success: false, code: 'FAILED', message: '配置加载失败', data: configured() });
    render(<NotificationsPage />);
    expect(await screen.findByText('配置加载失败')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /保存设置/ })).toBeDisabled();
    expect(updateNotificationSettings).not.toHaveBeenCalled();
  });

  it('retains input after a failed save and prevents testing unsaved changes', async () => {
    vi.mocked(updateNotificationSettings).mockResolvedValue({ success: false, code: 'CONFLICT', message: '配置已经更新，请刷新后重试。', data: configured() });
    render(<NotificationsPage />);
    const host = await screen.findByLabelText('SMTP 服务器地址');
    await waitFor(() => expect(host).toHaveValue('smtp.example.com'));
    fireEvent.change(host, { target: { value: 'new.example.com' } });
    expect(screen.getByRole('button', { name: /发送测试邮件/ })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: /保存设置/ }));
    expect(await screen.findByText('配置已经更新，请刷新后重试。')).toBeInTheDocument();
    expect(host).toHaveValue('new.example.com');
    expect(sendTestNotification).not.toHaveBeenCalled();
  });

  it('rejects full SMTP URLs before saving and maps the SSL checkbox to the security contract', async () => {
    render(<NotificationsPage />);
    const host = await screen.findByLabelText('SMTP 服务器地址');
    await waitFor(() => expect(host).toHaveValue('smtp.example.com'));
    fireEvent.change(host, { target: { value: 'smtp://name:password@example.com' } });
    fireEvent.click(screen.getByRole('button', { name: /保存设置/ }));
    expect(await screen.findByText('请输入合法域名或 IP，不包含协议、端口、路径或账户信息。')).toBeInTheDocument();
    expect(updateNotificationSettings).not.toHaveBeenCalled();
    fireEvent.change(host, { target: { value: 'smtp.example.com' } });
    fireEvent.click(screen.getByRole('checkbox', { name: '启用 SSL/TLS' }));
    fireEvent.click(screen.getByRole('button', { name: /保存设置/ }));
    await waitFor(() => expect(updateNotificationSettings).toHaveBeenCalledWith(expect.objectContaining({ security: 'none' }), ''));
  });

  it('sends an explicit test recipient using saved settings while automatic notifications are off', async () => {
    render(<NotificationsPage />);
    await waitFor(() => expect(screen.getByRole('button', { name: /发送测试邮件/ })).toBeEnabled());
    fireEvent.change(screen.getByLabelText('测试收件邮箱'), { target: { value: 'operator@example.com' } });
    fireEvent.click(screen.getByRole('button', { name: /发送测试邮件/ }));
    await waitFor(() => expect(sendTestNotification).toHaveBeenCalledWith('operator@example.com'));
    expect(await screen.findByText('测试邮件已加入发送队列，可在邮件记录中查看结果。')).toBeInTheDocument();
  });

  it('previews sample content in a sandbox with remote resources blocked', async () => {
    render(<NotificationsPage />);
    await waitFor(() => expect(screen.getByLabelText('SMTP 服务器地址')).toHaveValue('smtp.example.com'));
    fireEvent.click(screen.getByRole('tab', { name: '通知规则' }));
    fireEvent.click(screen.getAllByRole('button', { name: /预览模板/ })[0]);
    const frame = await screen.findByTitle('邮件模板预览');
    expect(frame).toHaveAttribute('sandbox', '');
    expect(frame).toHaveAttribute('referrerpolicy', 'no-referrer');
    expect(frame.getAttribute('srcdoc')).toContain("default-src 'none'");
    expect(frame.getAttribute('srcdoc')).toContain('示例登录');
  });

  it('requires confirmation to clear a saved credential while disabled and resets credential availability', async () => {
    vi.mocked(updateNotificationSettings).mockImplementation(async (settings, _credential, clear) => ok({ ...settings, hasCredential: !clear, revision: 'revision-2' }));
    render(<NotificationsPage />);
    const clearButton = await screen.findByRole('button', { name: '清除已保存授权码' });
    expect(clearButton).toBeEnabled();
    fireEvent.click(clearButton);
    expect(updateNotificationSettings).not.toHaveBeenCalled();
    fireEvent.click(await screen.findByRole('button', { name: '确认清除' }));
    await waitFor(() => expect(updateNotificationSettings).toHaveBeenCalledWith(expect.objectContaining({ enabled: false, hasCredential: true, revision: 'revision-1' }), undefined, true));
    expect(await screen.findByText('尚未配置，请输入邮件服务商提供的授权码。')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /发送测试邮件/ })).toBeDisabled();
  });

  it('blocks credential clearing while automatic notifications are enabled or changes are unsaved', async () => {
    vi.mocked(getNotificationSettings).mockResolvedValue(ok({ ...configured(), enabled: true }));
    render(<NotificationsPage />);
    expect(await screen.findByRole('button', { name: '清除已保存授权码' })).toBeDisabled();
    fireEvent.click(screen.getByRole('switch', { name: '启用邮件通知' }));
    expect(screen.getByRole('button', { name: '清除已保存授权码' })).toBeDisabled();
    expect(updateNotificationSettings).not.toHaveBeenCalled();
  });

  it.each(['smtp.example.com', '192.0.2.1', '2001:db8::1', '[2001:db8::1]'])('accepts SMTP host %s', (host) => expect(isNotificationHost(host)).toBe(true));
  it.each(['', 'https://example.com', 'example.com:465', 'name@example.com', 'example.com/path', 'fe80::1%en0'])('rejects SMTP host %s', (host) => expect(isNotificationHost(host)).toBe(false));
});

describe('email records', () => {
  it('shows each retained event independently and reports when the full event count exceeds the sample', async () => {
    vi.mocked(getNotificationMessage).mockResolvedValue(ok({
      message: { ...sentMessage, eventCount: 120 }, htmlBody: '<p>历史邮件</p>', textBody: '历史邮件', templateVersion: '1', messageId: '<sample@example.com>',
      events: [
        { eventType: 'ban', sourceId: 'first', hostName: 'host', sourceIp: '192.0.2.1', protocol: 'Ssh', username: 'first-user', occurredAtUtc: '2026-11-10T01:00:00Z', status: 'Applied', reason: 'first-reason' },
        { eventType: 'ban', sourceId: 'second', hostName: 'host', sourceIp: '192.0.2.2', protocol: null, username: null, occurredAtUtc: '2026-11-10T01:00:01Z', status: 'Failed', reason: 'second-reason' },
      ],
    }));
    render(<MailDetail id={sentMessage.id} onClose={() => {}} />);
    expect(await screen.findByText('共 120 条，保存前 2 条事件样本。')).toBeInTheDocument();
    expect(screen.getByText('192.0.2.1')).toBeInTheDocument();
    expect(screen.getByText('192.0.2.2')).toBeInTheDocument();
    expect(screen.getByText('Applied')).toBeInTheDocument();
    expect(screen.getByText('Failed')).toBeInTheDocument();
    expect(screen.getByText('second-reason')).toBeInTheDocument();
    expect(screen.getAllByText('未提供')).toHaveLength(2);
  });

  it('defaults to sent emails and shows the saved body and delivery metadata', async () => {
    vi.mocked(listNotificationMessages).mockResolvedValue(ok({ items: [sentMessage], total: 1, page: 1, pageSize: 20, pendingEvents: 2, suppressedEvents: 3 }));
    render(<MailRecords />);
    expect(await screen.findByText('通研IPBan-封禁通知')).toBeInTheDocument();
    expect(listNotificationMessages).toHaveBeenCalledWith({ page: 1, pageSize: 20, status: 'sent' }, expect.any(AbortSignal));
    fireEvent.click(screen.getByRole('button', { name: '查看详情' }));
    const frame = await screen.findByTitle('邮件内容快照');
    expect(getNotificationMessage).toHaveBeenCalledWith('9223372036854775807', expect.any(AbortSignal));
    expect(frame).toHaveAttribute('sandbox', '');
    expect(frame.getAttribute('srcdoc')).toContain('历史邮件');
    expect(screen.getByText('<message-1@example.com>')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('tab', { name: '纯文本正文' }));
    expect(screen.getByText('历史纯文本邮件')).toBeInTheDocument();
  });

  it('shows a failed records request without keeping stale rows', async () => {
    vi.mocked(listNotificationMessages).mockResolvedValue({ success: false, code: 'FAILED', message: '邮件记录暂不可用', data: { items: [], total: 0, page: 1, pageSize: 20, pendingEvents: 0, suppressedEvents: 0 } });
    render(<MailRecords />);
    expect(await screen.findByText('邮件记录暂不可用')).toBeInTheDocument();
    expect(screen.getByText('暂无邮件记录')).toBeInTheDocument();
  });
});
