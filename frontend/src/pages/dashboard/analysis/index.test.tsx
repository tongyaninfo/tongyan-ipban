import { cleanup, render, screen, waitFor } from '@testing-library/react';
import type { ColumnConfig, LineConfig } from '@ant-design/plots';
import { ConfigProvider, theme } from 'antd';
import type { PropsWithChildren } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import messages from '@/locales/zh-CN/pages';
import { emptyOverview, queryOverview } from '@/services/ipban/overview';
import { subscribeManagementRealtime } from '@/services/ipban/realtime';
import { buildSourceChart } from './charts';
import RunOverview from './index';

const plots = vi.hoisted(() => ({ column: vi.fn(), line: vi.fn() }));
vi.mock('@ant-design/plots', () => ({
  // 验证页面交给真实图表库的数据和主题合同；实际画布效果由浏览器验收。
  Column: (props: ColumnConfig) => { plots.column(props); return <div data-testid="source-chart" />; },
  Line: (props: LineConfig) => { plots.line(props); return <div data-testid="trend-chart" />; },
}));
vi.mock('@/services/ipban/ipLocation', async (original) => {
  const service = await original<typeof import('@/services/ipban/ipLocation')>();
  return { ...service, queryIpLocationSettings: vi.fn(async () => ({ success: true, code: 'OK', message: '', data: service.defaultIpLocationSettings })) };
});
vi.mock('@umijs/max', () => ({
  useIntl: () => ({
    formatMessage: ({ id, defaultMessage }: { id: string; defaultMessage: string }) =>
      messages[id as keyof typeof messages] ?? defaultMessage,
  }),
}));
vi.mock('@ant-design/pro-components', () => ({
  PageContainer: ({ children }: PropsWithChildren) => <main>{children}</main>,
}));
vi.mock('@/services/ipban/overview', async (original) => ({
  ...await original<typeof import('@/services/ipban/overview')>(),
  queryOverview: vi.fn(),
}));
vi.mock('@/services/ipban/realtime', () => ({ subscribeManagementRealtime: vi.fn() }));

const labels = { success: '成功', failure: '失败', observeOnly: '观察', total: '总次数' };
const page = (dark = false) => <ConfigProvider theme={{ algorithm: dark ? theme.darkAlgorithm : theme.defaultAlgorithm }}><RunOverview /></ConfigProvider>;
const column = () => plots.column.mock.lastCall?.[0] as ColumnConfig;
const line = () => plots.line.mock.lastCall?.[0] as LineConfig;

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(subscribeManagementRealtime).mockResolvedValue(() => undefined);
  vi.mocked(queryOverview).mockResolvedValue({
    success: true, code: 'OK', message: '',
    data: {
      ...emptyOverview,
      trend: [{ time: '13:00', atUtc: '2026-11-09T13:00:00Z', success: 3, failure: 5, observeOnly: 1 }],
      topSourceIps: [{ ip: '192.0.2.10', count: 9, success: 3, failure: 5, observeOnly: 1 }],
      observeOnlyWithoutIp: 12,
      recentEvents: [{ occurredAtUtc: '2026-11-09T13:00:00Z', protocol: 'Unidentified', success: true }],
    },
  });
});
afterEach(() => cleanup());

describe('overview source chart compatibility', () => {
  it('renders numeric total bars from the deployed count-only API without fabricating success', async () => {
    vi.mocked(queryOverview).mockResolvedValue({
      success: true, code: 'OK', message: '',
      data: {
        ...emptyOverview,
        topSourceIps: [{ ip: '192.0.2.10', count: 100 }, { ip: '(none)', count: 90 }],
      },
    });
    render(page());
    await screen.findByTestId('source-chart');

    expect(column().data).toEqual([
      { ip: '192.0.2.10', type: '总次数', value: 100, series: 'total' },
    ]);
    expect(screen.getByText('暂无统计')).toBeInTheDocument();
    expect(column().stack).toBe(true);
    expect(column().scale).toMatchObject({ color: { domain: ['总次数'], range: ['#8c8c8c'] } });
    expect(queryOverview).toHaveBeenCalledWith('24h');
  });

  it('keeps complete response rows as three true segments with no total legend', async () => {
    render(page());
    await screen.findByTestId('source-chart');

    expect(column().data).toEqual([
      { ip: '192.0.2.10', type: '成功', value: 3, series: 'success' },
      { ip: '192.0.2.10', type: '失败', value: 5, series: 'failure' },
      { ip: '192.0.2.10', type: '观察', value: 1, series: 'observeOnly' },
    ]);
    expect(column().scale).toMatchObject({ color: { domain: ['成功', '失败', '观察'], range: ['#1677ff', '#cf1322', '#fa8c16'] } });
    expect(line().scale).toMatchObject({ color: { domain: ['成功', '失败', '观察'], range: ['#389e0d', '#cf1322', '#faad14'] } });
    expect(screen.getByText('无来源 IP 的观察事件')).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument();
    expect(screen.getByText('未识别协议')).toBeInTheDocument();
  });

  it('shows the explicit observation subtotal from the legacy no-IP row outside the ranking', async () => {
    vi.mocked(queryOverview).mockResolvedValue({
      success: true, code: 'OK', message: '',
      data: {
        ...emptyOverview,
        topSourceIps: [{ ip: '(none)', count: 90, success: 1, failure: 2, observeOnly: 87 }],
      },
    });
    render(page());

    expect(await screen.findByText('87')).toBeInTheDocument();
    expect(screen.getByText('暂无来源数据')).toBeInTheDocument();
    expect(screen.queryByTestId('source-chart')).not.toBeInTheDocument();
  });

  it('supports mixed old/new rows and falls back to totals for an incomplete breakdown', () => {
    const result = buildSourceChart([
      { ip: '192.0.2.10', count: 10 },
      { ip: '192.0.2.11', count: 6, success: 1, failure: 4, observeOnly: 1 },
      { ip: '192.0.2.12', count: 3, success: 1, failure: Number.NaN },
    ], labels);
    expect(result.data.filter((point) => point.series === 'total').map((point) => point.value)).toEqual([10, 3]);
    expect(result.data.filter((point) => point.ip === '192.0.2.11').map((point) => point.value)).toEqual([1, 4, 1]);
    expect(result.data.every((point) => Number.isFinite(point.value))).toBe(true);
    expect(result.color.domain).toEqual(['成功', '失败', '观察', '总次数']);
  });

  it('updates both chart axes and legends when switching light and dark themes', async () => {
    const view = render(page());
    await screen.findByTestId('trend-chart');
    const light = theme.getDesignToken({ algorithm: theme.defaultAlgorithm });
    expect(line().theme).toMatchObject({ axis: { labelFill: light.colorTextSecondary, labelOpacity: 1 } });
    expect(column().theme).toMatchObject({ legendCategory: { itemLabelFill: light.colorText, itemLabelFillOpacity: 1 } });

    view.rerender(page(true));
    const dark = theme.getDesignToken({ algorithm: theme.darkAlgorithm });
    await waitFor(() => expect(column().theme).toMatchObject({
      axis: { labelFill: dark.colorTextSecondary, gridStroke: dark.colorBorderSecondary },
      legendCategory: { itemLabelFill: dark.colorText, itemLabelFillOpacity: 1 },
      tooltip: { css: { '.g2-tooltip': { background: dark.colorBgElevated, color: dark.colorText } } },
    }));
    expect(line().theme).toMatchObject({ axis: { labelFill: dark.colorTextSecondary }, legendCategory: { itemLabelFill: dark.colorText } });
    expect(line().scale).toMatchObject({ color: { range: ['#389e0d', '#cf1322', '#faad14'] } });
  });
});
