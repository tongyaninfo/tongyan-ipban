import type { LineConfig } from '@ant-design/plots';

type SourceSeries = 'success' | 'failure' | 'observeOnly' | 'total';
type SourceLabels = Record<SourceSeries, string>;
type SourceInput = {
  ip: string;
  count: number;
  success?: number;
  failure?: number;
  observeOnly?: number;
};
export type SourceChartPoint = { ip: string; type: string; value: number; series: SourceSeries };

const sourceSeries = ['success', 'failure', 'observeOnly', 'total'] as const;
const sourceColors: Record<SourceSeries, string> = {
  success: '#1677ff',
  failure: '#cf1322',
  observeOnly: '#fa8c16',
  total: '#8c8c8c',
};
const isCount = (value: unknown): value is number =>
  typeof value === 'number' && Number.isFinite(value) && value >= 0;
const isMissingIp = (ip: string) => !ip?.trim() || ip === '(none)';

export function buildSourceChart(sources: readonly SourceInput[], labels: SourceLabels, observeOnlyWithoutIp?: number) {
  // 旧接口可能仍把缺 IP 的事件放进榜单，只能用其明确的观察分项恢复计数。
  const legacyObserveOnly = sources.find(({ ip }) => isMissingIp(ip))?.observeOnly;
  const data = sources.filter(({ ip }) => !isMissingIp(ip)).flatMap<SourceChartPoint>((source) => {
    const { ip } = source;
    if (isCount(source.success) && isCount(source.failure) && isCount(source.observeOnly)) {
      return [
        { ip, type: labels.success, value: source.success, series: 'success' as const },
        { ip, type: labels.failure, value: source.failure, series: 'failure' as const },
        { ip, type: labels.observeOnly, value: source.observeOnly, series: 'observeOnly' as const },
      ];
    }
    // 旧版接口仅提供总数，缺失分段不能传给 stackY，也不能把总数伪装成成功次数。
    return isCount(source.count)
      ? [{ ip, type: labels.total, value: source.count, series: 'total' as const }]
      : [];
  });
  const present = new Set(data.map((point) => point.series));
  const visibleSeries = sourceSeries.filter((series) => present.has(series));
  return {
    data,
    observeOnlyWithoutIp: isCount(observeOnlyWithoutIp) ? observeOnlyWithoutIp
      : isCount(legacyObserveOnly) ? legacyObserveOnly : undefined,
    color: {
      domain: visibleSeries.map((series) => labels[series]),
      range: visibleSeries.map((series) => sourceColors[series]),
    },
  };
}

type ChartThemeTokens = {
  colorText: string;
  colorTextSecondary: string;
  colorBorderSecondary: string;
  colorBgElevated: string;
  fontFamily: string;
  boxShadowSecondary: string;
};

/** G2 画布不继承 antd 的文字颜色，坐标轴、图例和悬浮提示需显式同步当前主题。 */
export function buildChartTheme(token: ChartThemeTokens) {
  return {
    view: { viewFill: 'transparent' },
    axis: {
      labelFill: token.colorTextSecondary,
      labelOpacity: 1,
      labelFontFamily: token.fontFamily,
      titleFill: token.colorText,
      titleOpacity: 1,
      lineStroke: token.colorBorderSecondary,
      tickStroke: token.colorBorderSecondary,
      gridStroke: token.colorBorderSecondary,
      gridStrokeOpacity: 1,
    },
    legendCategory: {
      itemLabelFill: token.colorText,
      itemLabelFillOpacity: 1,
      itemValueFill: token.colorTextSecondary,
      titleFill: token.colorText,
      titleFillOpacity: 1,
      navButtonFill: token.colorText,
      navPageNumFill: token.colorTextSecondary,
    },
    tooltip: {
      css: {
        '.g2-tooltip': {
          background: token.colorBgElevated,
          color: token.colorText,
          boxShadow: token.boxShadowSecondary,
        },
        '.g2-tooltip-title': { color: token.colorText },
        '.g2-tooltip-list-item-name-label': { color: token.colorTextSecondary },
        '.g2-tooltip-list-item-value': { color: token.colorText },
      },
    },
  } satisfies NonNullable<LineConfig['theme']>;
}
