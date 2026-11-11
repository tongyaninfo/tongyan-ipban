import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import type { PropsWithChildren } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import messages from '@/locales/zh-CN/pages';
import { queryPolicies, upsertPolicy, type BanPolicy } from '@/services/ipban/management';
import PoliciesPage from './index';

vi.mock('@umijs/max', () => ({
  useIntl: () => ({ formatMessage: ({ id, defaultMessage }: { id: string; defaultMessage: string }) =>
    messages[id as keyof typeof messages] ?? defaultMessage }),
}));
vi.mock('@ant-design/pro-components', () => ({
  PageContainer: ({ children }: PropsWithChildren) => <main>{children}</main>,
}));
vi.mock('@/services/ipban/management', () => ({
  queryPolicies: vi.fn(), upsertPolicy: vi.fn(), deletePolicy: vi.fn(),
}));

const policy: BanPolicy = {
  id: 1, name: 'Test policy', enabled: true, threshold: 5, windowSeconds: 300,
  observeSeconds: 0, cooldownSeconds: 900, banDurationSeconds: 1800,
  action: 'Ban', protocol: 'ALL', version: 1,
  createdAtUtc: '2026-01-01T00:00:00Z', updatedAtUtc: '2026-01-01T00:00:00Z',
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(queryPolicies).mockResolvedValue({ success: true, code: 'OK', message: '', data: [policy] });
  vi.mocked(upsertPolicy).mockResolvedValue({ success: true, code: 'OK', message: '', data: policy });
});
afterEach(() => cleanup());

async function editPolicy() {
  render(<ConfigProvider locale={zhCN} theme={{ token: { motion: false } }}><PoliciesPage /></ConfigProvider>);
  fireEvent.click(await screen.findByRole('button', { name: /编辑/ }));
  return screen.findByRole('dialog');
}

async function selectExpiry(label: string) {
  fireEvent.click(screen.getByRole('radio', { name: label }));
  await waitFor(() => expect(screen.getByRole('radio', { name: label })).toBeChecked());
}

describe('automatic ban policy duration', () => {
  it.each(['999999999999', '-1', '1.5', '', '1e3', 'abc'])('keeps invalid finite duration %j in the form without sending a request', async (value) => {
    const dialog = await editPolicy();
    const input = within(dialog).getByRole('textbox', { name: '封禁时长（秒）' });
    fireEvent.focus(input);
    fireEvent.change(input, { target: { value } });
    expect(input).toHaveValue(value);
    fireEvent.blur(input);
    expect(input).toHaveValue(value);
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定/ }));
    expect(await screen.findByText(messages['pages.access.policies.validation.banDurationSeconds'])).toBeInTheDocument();
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input).toHaveValue(value);
    expect(upsertPolicy).not.toHaveBeenCalled();
  });

  it('preserves zero while focused, after blur and on save, and saves Observe without a third expiry option', async () => {
    const dialog = await editPolicy();
    const input = within(dialog).getByRole('textbox', { name: '封禁时长（秒）' });
    fireEvent.focus(input);
    fireEvent.change(input, { target: { value: '0' } });
    expect(input).toHaveValue('0');
    fireEvent.blur(input);
    expect(input).toHaveValue('0');
    expect(await screen.findByText(messages['pages.access.policies.durationZeroHelp'])).toBeInTheDocument();
    expect(within(dialog).queryByRole('combobox', { name: '动作' })).not.toBeInTheDocument();
    expect(within(dialog).getAllByRole('radio')).toHaveLength(2);
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定/ }));
    await waitFor(() => expect(upsertPolicy).toHaveBeenCalledWith(expect.objectContaining({ banDurationSeconds: 0, action: 'Observe' }), 1));
  });

  it('offers only limited and permanent radio options, submits minus one, and hides the finite field', async () => {
    const dialog = await editPolicy();
    expect(within(dialog).getAllByRole('radio')).toHaveLength(2);
    await selectExpiry('永久封禁');
    await waitFor(() => expect(within(dialog).queryByRole('textbox', { name: '封禁时长（秒）' })).not.toBeInTheDocument());
    expect(screen.getByText(messages['pages.access.policies.permanentHelp'])).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定/ }));
    await waitFor(() => expect(upsertPolicy).toHaveBeenCalledWith(expect.objectContaining({ banDurationSeconds: -1 }), 1));
  });

  it('submits a validated finite duration as a number without truncation', async () => {
    const dialog = await editPolicy();
    const input = within(dialog).getByRole('textbox', { name: '封禁时长（秒）' });
    fireEvent.change(input, { target: { value: '2147483647' } });
    fireEvent.blur(input);
    expect(input).toHaveValue('2147483647');
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定/ }));
    await waitFor(() => expect(upsertPolicy).toHaveBeenCalledWith(expect.objectContaining({ banDurationSeconds: 2147483647 }), 1));
  });

  it.each([-1, 0])('renders saved Ban duration %i as permanent, edits it as permanent, and restores a finite default when switched', async (duration) => {
    vi.mocked(queryPolicies).mockResolvedValue({ success: true, code: 'OK', message: '', data: [{ ...policy, banDurationSeconds: duration }] });
    const dialog = await editPolicy();
    expect(within(screen.getByRole('table')).getByText('永久封禁')).toBeVisible();
    expect(within(dialog).getByRole('radio', { name: '永久封禁' })).toBeChecked();
    expect(within(dialog).queryByRole('textbox', { name: '封禁时长（秒）' })).not.toBeInTheDocument();
    await selectExpiry('限时封禁');
    const input = await within(dialog).findByRole('textbox', { name: '封禁时长（秒）' });
    expect(input).toHaveValue('1800');
    fireEvent.change(input, { target: { value: '60' } });
    await selectExpiry('永久封禁');
    await selectExpiry('限时封禁');
    expect(await within(dialog).findByRole('textbox', { name: '封禁时长（秒）' })).toHaveValue('60');
  });

  it('renders zero Observe as no ban and allows changing it back to a positive ban duration', async () => {
    vi.mocked(queryPolicies).mockResolvedValue({ success: true, code: 'OK', message: '', data: [{ ...policy, banDurationSeconds: 0, action: 'Observe' }] });
    const dialog = await editPolicy();
    expect(within(screen.getByRole('table')).getByText('不封禁')).toBeInTheDocument();
    expect(within(dialog).getByRole('radio', { name: '限时封禁' })).toBeChecked();
    const input = within(dialog).getByRole('textbox', { name: '封禁时长（秒）' });
    expect(input).toHaveValue('0');
    fireEvent.change(input, { target: { value: '1' } });
    await within(dialog).findByRole('combobox', { name: '动作' });
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定/ }));
    await waitFor(() => expect(upsertPolicy).toHaveBeenCalledWith(expect.objectContaining({ banDurationSeconds: 1, action: 'Ban' }), 1));
  });

  it('normalizes a legacy permanent duration to minus one when disabling a policy', async () => {
    vi.mocked(queryPolicies).mockResolvedValue({ success: true, code: 'OK', message: '', data: [{ ...policy, banDurationSeconds: 0 }] });
    render(<ConfigProvider locale={zhCN}><PoliciesPage /></ConfigProvider>);
    fireEvent.click(await screen.findByRole('switch'));
    await waitFor(() => expect(upsertPolicy).toHaveBeenCalledWith(expect.objectContaining({ enabled: false, banDurationSeconds: -1 }), 1));
  });

  it('maps server duration validation to the field without showing a network failure', async () => {
    vi.mocked(upsertPolicy).mockResolvedValue({ success: false, code: 'INVALID_BAN_POLICY_DURATION', message: 'server field validation', data: policy });
    const dialog = await editPolicy();
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定/ }));
    await waitFor(() => expect(within(dialog).getByText(messages['pages.access.policies.validation.banDurationSeconds'])).toBeInTheDocument());
    expect(screen.queryByText('管理 API 暂时不可用。')).not.toBeInTheDocument();
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });
});
