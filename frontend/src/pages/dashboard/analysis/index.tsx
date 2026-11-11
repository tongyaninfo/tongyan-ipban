import IpLocationText from '@/components/IpLocationText';
import {
  ApiOutlined,
  ClockCircleOutlined,
  DesktopOutlined,
  GlobalOutlined,
  LaptopOutlined,
  SafetyCertificateOutlined,
  StopOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { Column, Line } from '@ant-design/plots';
import { Card, Col, Empty, Row, Segmented, Space, Statistic, Tag, theme, Typography } from 'antd';
import { PageContainer } from '@ant-design/pro-components';
import { useEffect, useMemo, useState } from 'react';
import { useIntl } from '@umijs/max';
import { emptyOverview, queryOverview, type OverviewData, type OverviewRange } from '@/services/ipban/overview';
import { subscribeManagementRealtime } from '@/services/ipban/realtime';
import { loginEventProtocolLabel } from '@/utils/loginEventProtocol';
import { buildChartTheme, buildSourceChart, type SourceChartPoint } from './charts';

const bytes = (value: number) => {
  if (!value) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(Math.floor(Math.log(value) / Math.log(1024)), 3);
  return `${(value / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
};

const localDateTime = (value: string) => new Intl.DateTimeFormat(undefined, {
  dateStyle: 'short',
  timeStyle: 'medium',
}).format(new Date(value));

export default function RunOverview() {
  const intl = useIntl();
  const { token } = theme.useToken();
  const [data, setData] = useState<OverviewData>(emptyOverview);
  const [loading, setLoading] = useState(true);
  const [range, setRange] = useState<OverviewRange>('24h');
  const text = (id: string, fallback: string) => intl.formatMessage({ id, defaultMessage: fallback });
  const firewallStatusLabel = (value: string | number) => {
    const labels: Record<string, [string, string]> = {
      '0': ['pages.overview.firewallEnabled', '已启用'],
      '1': ['pages.overview.firewallDisabled', '已停用'],
      '2': ['pages.overview.firewallUnsupported', '不支持'],
      '3': ['pages.overview.firewallPermissionDenied', '权限不足'],
      '4': ['pages.overview.firewallCommandFailed', '执行失败'],
    };
    const [id, fallback] = labels[String(value)] ?? ['', String(value)];
    return id ? text(id, fallback) : fallback;
  };
  useEffect(() => {
    let disposed = false;
    const refresh = async () => {
      const result = await queryOverview(range);
      if (!disposed) {
        setData(result.data);
        setLoading(false);
      }
    };
    setLoading(true);
    void refresh();
    let unsubscribe: (() => void) | undefined;
    void subscribeManagementRealtime('overview', () => void refresh()).then((cleanup) => {
      if (disposed) cleanup();
      else unsubscribe = cleanup;
    });
    return () => {
      disposed = true;
      unsubscribe?.();
    };
  }, [range]);
  const successLabel = text('pages.overview.success', '成功');
  const failureLabel = text('pages.overview.failure', '失败');
  const observeOnlyLabel = text('pages.overview.observeOnly', '观察');
  const totalAttemptsLabel = text('pages.overview.totalAttempts', '总次数');
  const unidentifiedProtocolLabel = text('pages.security.events.unidentifiedProtocol', '未识别协议');
  const trend = useMemo(() => data.trend.flatMap((p) => {
    const date = new Date(p.atUtc);
    const time = range === '24h'
      ? date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      : date.toLocaleDateString([], { month: '2-digit', day: '2-digit' });
    return [
      { time, type: successLabel, value: p.success },
      { time, type: observeOnlyLabel, value: p.observeOnly },
      // 两条线重合时让失败线绘制在最上方。
      { time, type: failureLabel, value: p.failure },
    ];
  }), [data.trend, range, successLabel, failureLabel, observeOnlyLabel]);
  const sourceChart = useMemo(() => buildSourceChart(data.topSourceIps, {
    success: successLabel,
    failure: failureLabel,
    observeOnly: observeOnlyLabel,
    total: totalAttemptsLabel,
  }, data.observeOnlyWithoutIp), [data.topSourceIps, data.observeOnlyWithoutIp, successLabel, failureLabel, observeOnlyLabel, totalAttemptsLabel]);
  const chartTheme = useMemo(() => buildChartTheme(token), [token]);
  const host = data.host;
  const hostFields = [
    { label: text('pages.overview.osVersion', '操作系统版本'), value: host?.osVersion, icon: <LaptopOutlined /> },
    { label: text('pages.overview.computerName', '计算机名称'), value: host?.computerName, icon: <DesktopOutlined /> },
    { label: text('pages.overview.ipAddresses', 'IP 地址'), value: host?.ipAddresses.join(' · '), icon: <GlobalOutlined /> },
    { label: text('pages.overview.systemStartedAt', '系统启动时间'), value: host?.startedAtUtc ? localDateTime(host.startedAtUtc) : null, icon: <ClockCircleOutlined /> },
  ];
  const cardStyles = { body: { padding: token.paddingMD } };
  const hostMissing = text('pages.overview.endpointUnavailable', '未采集');
  return <PageContainer title={text('pages.overview.title', '运行总览')} content={text('pages.overview.subtitle', '登录来源、保护状态和近期风险活动')}>
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <div style={{ overflowX: 'auto' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(200px, 1.25fr) minmax(226px, 1.25fr) repeat(2, minmax(128px, 1fr))', gap: token.marginMD }}>
          <Card loading={loading} styles={cardStyles}>
            <Space size={6} style={{ color: token.colorTextSecondary }}>
              <SafetyCertificateOutlined style={{ color: data.ready ? token.colorSuccess : token.colorWarning }} />
              {text('pages.overview.agentStatus', 'Agent 状态')}
            </Space>
            <div style={{ marginBlock: 4 }}>
              <Typography.Text strong>{data.ready ? text('pages.overview.ready', 'Agent 运行正常') : text('pages.overview.degraded', '部分数据或能力尚未就绪')}</Typography.Text>
            </div>
            <Typography.Text type="secondary">{text('pages.overview.firewall', '防火墙')}：{data.firewallProvider} / {firewallStatusLabel(data.firewallStatus)}</Typography.Text>
          </Card>
          <Card loading={loading} styles={cardStyles}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: token.marginSM }}>
              <Statistic title={<Space size={6}><ApiOutlined style={{ color: token.colorPrimary }} />{text('pages.overview.activeConnections', '活动连接')}</Space>} value={data.activeConnections} />
              <Statistic title={<Space size={6}><DesktopOutlined style={{ color: token.colorPrimary }} />{text('pages.overview.activeSessions', '活动会话')}</Space>} value={data.activeSessions} />
            </div>
          </Card>
          <Card loading={loading} styles={cardStyles}>
            <Statistic title={<Space size={6}><WarningOutlined style={{ color: token.colorError }} />{text('pages.overview.loginFailures', '今日失败')}</Space>} value={data.todayLoginFailures} />
          </Card>
          <Card loading={loading} styles={cardStyles}>
            <Statistic title={<Space size={6}><StopOutlined style={{ color: token.colorWarning }} />{text('pages.overview.activeBans', '当前封禁')}</Space>} value={data.activeBans} />
          </Card>
        </div>
      </div>
      <Card loading={loading} styles={cardStyles}>
        <div style={{ overflowX: 'auto' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(170px, 1fr))', gap: token.marginMD }}>
            {hostFields.map(({ label, value, icon }) => (
              <div key={label} style={{ minWidth: 0 }}>
                <Space size={6} style={{ color: token.colorTextSecondary }}>{icon}{label}</Space>
                <Typography.Text
                  strong
                  ellipsis={{ tooltip: value || hostMissing }}
                  style={{ display: 'block', marginTop: 4 }}
                >
                  {value || hostMissing}
                </Typography.Text>
              </div>
            ))}
          </div>
        </div>
      </Card>
      <Card title={text('pages.overview.trend', '登录趋势')} extra={<Segmented value={range} onChange={(value) => setRange(value as OverviewRange)} options={[{ label: text('pages.overview.range24h', '24 小时'), value: '24h' }, { label: text('pages.overview.range7d', '过去 7 天'), value: '7d' }, { label: text('pages.overview.range1m', '过去 1 月'), value: '1m' }]} />}>
        {trend.length ? (
          <Line
            data={trend}
            theme={chartTheme}
            xField="time"
            yField="value"
            colorField="type"
            scale={{
              color: {
                domain: [successLabel, failureLabel, observeOnlyLabel],
                range: ['#389e0d', '#cf1322', '#faad14'],
              },
            }}
            height={280}
          />
        ) : <Empty description={text('pages.overview.noTrend', '暂无趋势数据')} />}
      </Card>
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={8}>
          <Card title={text('pages.overview.topIps', '来源 IP Top')}>
            {sourceChart.data.length ? (
              <Column
                data={sourceChart.data}
                theme={chartTheme}
                xField="ip"
                yField="value"
                colorField="type"
                stack
                scale={{
                  color: sourceChart.color,
                }}
                axis={{ x: { labelAutoRotate: true, labelAutoHide: true } }}
                tooltip={{ title: 'ip', items: [(point: SourceChartPoint) => ({ name: point.type, value: point.value })] }}
                height={240}
              />
            ) : <Empty description={text('pages.overview.noSource', '暂无来源数据')} />}
            {data.topSourceIps.some(({ ip }) => ip && ip !== '(none)') && <section aria-label={text('pages.ipLocation.sourceLocations', '来源归属地')} style={{ marginTop: 12, maxHeight: 260, overflowY: 'auto' }}>
              {data.topSourceIps.filter(({ ip }) => ip && ip !== '(none)').map(({ ip, count }) => <div key={ip} style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '6px 0' }}><IpLocationText ip={ip} /><span>{count}</span></div>)}
            </section>}
            <Statistic
              title={text('pages.overview.observeOnlyWithoutIp', '无来源 IP 的观察事件')}
              value={sourceChart.observeOnlyWithoutIp ?? text('pages.overview.observationCountUnavailable', '暂无统计')}
              loading={loading}
              style={{ borderTop: `1px solid ${token.colorBorderSecondary}`, marginTop: token.marginMD, paddingTop: token.paddingMD }}
            />
          </Card>
        </Col>
        <Col xs={24} lg={8}><Card title={text('pages.overview.storage', '存储状态')}><Space direction="vertical"><Statistic title={text('pages.overview.database', '数据库')} value={bytes(data.storage.databaseBytes)} /><Statistic title={text('pages.overview.logs', '日志')} value={bytes(data.storage.logBytes)} /><Statistic title={text('pages.overview.archives', '归档')} value={bytes(data.storage.archiveBytes)} /></Space></Card></Col>
        <Col xs={24} lg={8}><Card title={text('pages.overview.recent', '最近事件')}>{data.recentEvents.length ? data.recentEvents.slice(0, 8).map((event) => <div key={`${event.occurredAtUtc}-${event.remoteIp}-${event.remotePort}-${event.username}-${event.success}`} style={{ marginBottom: 10, lineHeight: 1.45 }}><div><Tag color={event.success ? 'green' : 'red'}>{event.success ? text('pages.overview.success', '成功') : text('pages.overview.failure', '失败')}</Tag><strong>{event.username || text('pages.overview.unknownUser', '未识别用户')}</strong><span style={{ marginLeft: 8 }}>{loginEventProtocolLabel(event.protocol, unidentifiedProtocolLabel)}</span><span style={{ marginLeft: 8, color: '#666' }}>{localDateTime(event.occurredAtUtc)}</span></div><div style={{ color: '#666', fontSize: 12, marginLeft: 8 }}><IpLocationText ip={event.remoteIp} port={event.remotePort} endpoint missingLabel="-" /> → {event.localIp || '-'}:{event.localPort ?? '-'} · {event.processName || text('pages.overview.noProcess', '未采集进程')}</div></div>) : <Empty description={text('pages.overview.noEvents', '暂无事件')} />}</Card></Col>
      </Row>
    </Space>
  </PageContainer>;
}
