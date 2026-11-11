import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { ConfigProvider, message } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import type { PropsWithChildren } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import zhCNMessages from '@/locales/zh-CN/pages';
import zhTWMessages from '@/locales/zh-TW/pages';
import enUSMessages from '@/locales/en-US/pages';
import {
  deleteLogFile,
  queryLogFiles,
  queryLogs,
  type LogFileInfo,
} from '@/services/ipban/management';
import routes from '../../../../config/routes';
import SystemLogsPage from './index';

const localeState = vi.hoisted(() => ({ value: 'zh-CN' }));
const locales: Record<string, Record<string, string>> = {
  'zh-CN': zhCNMessages,
  'zh-TW': zhTWMessages,
  'en-US': enUSMessages,
};
vi.mock('@umijs/max', () => ({
  useIntl: () => ({
    formatMessage: ({
      id,
      defaultMessage,
    }: {
      id: string;
      defaultMessage: string;
    }) => locales[localeState.value][id] ?? defaultMessage,
  }),
}));
vi.mock('@ant-design/pro-components', () => ({
  PageContainer: ({ children }: PropsWithChildren) => <main>{children}</main>,
}));
vi.mock('@/services/ipban/management', () => ({
  queryLogFiles: vi.fn(),
  queryLogs: vi.fn(),
  deleteLogFile: vi.fn(),
}));

const archived: LogFileInfo = {
  name: 'ipban-20260101-010000.ndjson.gz',
  sizeBytes: 1024,
  lastWriteTimeUtc: '2026-01-01T00:00:00Z',
  compressed: true,
  canDelete: true,
};
const rotated: LogFileInfo = {
  ...archived,
  name: 'ipban-20260101-020000.ndjson',
  compressed: false,
};
const active: LogFileInfo = {
  ...rotated,
  name: 'ipban-20260101.ndjson',
  canDelete: false,
};
const legacy: LogFileInfo = {
  ...archived,
  name: 'legacy.ndjson.gz',
  canDelete: undefined,
};
const files = [archived, rotated, active, legacy];
const ok = <T,>(data: T) => ({ success: true, code: 'OK', message: '', data });
const fail = (code: string) => ({
  success: false,
  code,
  message: 'Do not display this untranslated server message',
  data: null,
});

beforeEach(() => {
  vi.clearAllMocks();
  localeState.value = 'zh-CN';
  vi.mocked(queryLogFiles).mockResolvedValue(ok(files));
  vi.mocked(queryLogs).mockResolvedValue(ok(['initial log line']));
  vi.mocked(deleteLogFile).mockResolvedValue(ok(null));
  vi.spyOn(message, 'success').mockImplementation(
    () => (() => undefined) as ReturnType<typeof message.success>,
  );
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const showPage = () =>
  render(
    <ConfigProvider locale={zhCN} theme={{ token: { motion: false } }}>
      <SystemLogsPage />
    </ConfigProvider>,
  );
const rowFor = (name: string) =>
  screen.getByRole('row', {
    name: new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
  });
async function openDelete(name = archived.name) {
  const row = rowFor(name);
  const button = within(row).getByRole('button', {
    name: new RegExp(locales[localeState.value]['pages.common.delete']),
  });
  await waitFor(() => expect(button).toBeEnabled());
  fireEvent.click(button);
  return screen.findByRole('button', {
    name: locales[localeState.value]['pages.system.logs.delete.confirm'],
  });
}

describe('system log file deletion', () => {
  it('only allows explicit server permission, including plain rotated files and gzip archives', async () => {
    showPage();
    await screen.findByText(archived.name);
    for (const record of [archived, rotated])
      expect(
        within(rowFor(record.name)).getByRole('button', { name: /删除/ }),
      ).toBeEnabled();
    for (const record of [active, legacy])
      expect(
        within(rowFor(record.name)).getByRole('button', { name: /删除/ }),
      ).toBeDisabled();
    expect(
      within(rowFor(rotated.name)).getByText('已轮转日志'),
    ).toBeInTheDocument();
  });

  it('confirms the exact filename and permanent deletion without selecting the row or deleting on cancel', async () => {
    showPage();
    await screen.findByText(archived.name);
    await openDelete();
    const title = screen.getByText(
      zhCNMessages['pages.system.logs.delete.title'],
    );
    const popup = title.closest('.ant-popconfirm') as HTMLElement;
    expect(within(popup).getByText(archived.name)).toBeInTheDocument();
    expect(
      within(popup).getByText(
        zhCNMessages['pages.system.logs.delete.description'],
      ),
    ).toBeInTheDocument();
    fireEvent.click(within(popup).getByRole('button', { name: /取\s*消/ }));
    expect(deleteLogFile).not.toHaveBeenCalled();
    expect(queryLogs).toHaveBeenCalledTimes(1);
  });

  it('clears a deleted file filter, preserves the keyword and refreshes all logs', async () => {
    showPage();
    fireEvent.click(await screen.findByText(archived.name));
    await waitFor(() =>
      expect(queryLogs).toHaveBeenLastCalledWith(archived.name, ''),
    );
    fireEvent.change(
      screen.getByPlaceholderText(zhCNMessages['pages.system.logs.keyword']),
      { target: { value: 'failure' } },
    );
    const confirm = await openDelete();
    vi.mocked(queryLogFiles).mockResolvedValue(
      ok(files.filter((file) => file.name !== archived.name)),
    );
    vi.mocked(queryLogs).mockResolvedValue(ok(['new global log line']));
    fireEvent.click(confirm);
    await waitFor(() =>
      expect(deleteLogFile).toHaveBeenCalledWith(archived.name),
    );
    await waitFor(() =>
      expect(queryLogs).toHaveBeenLastCalledWith(undefined, 'failure'),
    );
    expect(await screen.findByText('new global log line')).toBeInTheDocument();
    await waitFor(() =>
      expect(
        screen.queryByRole('row', { name: new RegExp(archived.name) }),
      ).not.toBeInTheDocument(),
    );
    const exportUrl = screen
      .getByRole('link', { name: /导出 NDJSON/ })
      .getAttribute('href');
    expect(exportUrl).toContain('keyword=failure');
    expect(exportUrl).not.toContain('fileName');
    expect(message.success).toHaveBeenCalledWith(
      zhCNMessages['pages.system.logs.delete.success'],
    );
  });

  it('preserves a different selected file when an archive is deleted', async () => {
    showPage();
    fireEvent.click(await screen.findByText(active.name));
    await waitFor(() =>
      expect(queryLogs).toHaveBeenLastCalledWith(active.name, ''),
    );
    const confirm = await openDelete(rotated.name);
    vi.mocked(queryLogFiles).mockResolvedValue(
      ok(files.filter((file) => file.name !== rotated.name)),
    );
    fireEvent.click(confirm);
    await waitFor(() =>
      expect(deleteLogFile).toHaveBeenCalledWith(rotated.name),
    );
    await waitFor(() => expect(queryLogs).toHaveBeenCalledTimes(3));
    expect(queryLogs).toHaveBeenLastCalledWith(active.name, '');
  });

  it('blocks repeated submissions while deletion is pending', async () => {
    let finish: (value: ReturnType<typeof ok<null>>) => void = () => undefined;
    vi.mocked(deleteLogFile).mockImplementation(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    showPage();
    await screen.findByText(archived.name);
    const confirm = await openDelete();
    fireEvent.click(confirm);
    fireEvent.click(confirm);
    expect(deleteLogFile).toHaveBeenCalledTimes(1);
    expect(confirm).toBeDisabled();
    expect(
      within(rowFor(rotated.name)).getByRole('button', { name: /删除/ }),
    ).toBeDisabled();
    await act(async () => {
      finish(ok(null));
    });
    await waitFor(() => expect(queryLogFiles).toHaveBeenCalledTimes(2));
  });

  it.each([
    'zh-CN',
    'zh-TW',
    'en-US',
  ])('localizes deletion failures in %s without showing the server text', async (locale) => {
    localeState.value = locale;
    vi.mocked(deleteLogFile).mockResolvedValue(fail('LOG_FILE_PROTECTED'));
    showPage();
    await screen.findByText(archived.name);
    fireEvent.click(await openDelete());
    expect(
      await screen.findByText(
        locales[locale]['pages.system.logs.delete.notAllowed'],
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByText('Do not display this untranslated server message'),
    ).not.toBeInTheDocument();
    expect(queryLogFiles).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['LOG_FILE_INVALID', 'invalidFile'],
    ['LOG_FILE_NOT_FOUND', 'notFound'],
    ['LOG_FILE_UNSAFE', 'unsafe'],
    ['LOG_FILE_BUSY', 'busy'],
    ['LOG_DELETE_AUDIT_UNAVAILABLE', 'auditUnavailable'],
    ['LOG_DELETE_AUDIT_FAILED', 'auditFailed'],
    ['AUTH_REQUIRED', 'authRequired'],
    ['NETWORK_ERROR', 'networkError'],
    ['UNEXPECTED_CODE', 'failed'],
  ])('handles %s with a specific safe message and no automatic retry', async (code, key) => {
    vi.mocked(deleteLogFile).mockResolvedValue(fail(code));
    showPage();
    await screen.findByText(archived.name);
    fireEvent.click(await openDelete());
    expect(
      await screen.findByText(
        locales['zh-CN'][`pages.system.logs.delete.${key}`],
      ),
    ).toBeInTheDocument();
    expect(deleteLogFile).toHaveBeenCalledTimes(1);
  });
});

describe('overview navigation', () => {
  it('shows one top-level overview page and preserves existing entry URLs', () => {
    const overview = routes.find(
      (route) => route.path === '/dashboard/analysis',
    );
    expect(overview).toMatchObject({
      name: 'dashboard',
      component: './dashboard/analysis',
    });
    expect(overview).not.toHaveProperty('routes');
    expect(routes.find((route) => route.path === '/dashboard')).toMatchObject({
      hideInMenu: true,
      redirect: '/dashboard/analysis',
    });
    expect(routes.find((route) => route.path === '/')).toMatchObject({
      redirect: '/dashboard/analysis',
    });
  });
});
