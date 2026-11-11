import IpLocationText from '@/components/IpLocationText';
import { ReloadOutlined } from '@ant-design/icons';
import { Alert, Button, Card, Table, Tag } from 'antd';
import { PageContainer } from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { useEffect, useMemo, useRef, useState } from 'react';
import { queryLoginEvents, type LoginEvent } from '@/services/ipban/management';
import { subscribeManagementRealtime } from '@/services/ipban/realtime';
import { loginEventProtocolLabel } from '@/utils/loginEventProtocol';

export default function LoginEventsPage() {
  const intl = useIntl();
  const text = (id: string, defaultMessage: string) => intl.formatMessage({ id, defaultMessage });
  const [data, setData] = useState<LoginEvent[]>([]);
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(false);
  const loadingRef = useRef(false);

  const load = async () => {
    if (loadingRef.current) return;
    loadingRef.current = true;
    setLoading(true);
    setError(undefined);
    try {
      const result = await queryLoginEvents();
      if (result.success) setData(result.data ?? []);
      else setError(result.message);
    } finally {
      loadingRef.current = false;
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
    let unsubscribe: (() => void) | undefined;
    let disposed = false;
    void subscribeManagementRealtime('security-events', () => void load()).then((cleanup) => {
      if (disposed) cleanup();
      else unsubscribe = cleanup;
    });
    return () => {
      disposed = true;
      unsubscribe?.();
    };
  }, []);

  const successCount = useMemo(() => data.filter((item) => item.success).length, [data]);
  const localDateTime = (value: string) => new Intl.DateTimeFormat(intl.locale, { dateStyle: 'short', timeStyle: 'medium' }).format(new Date(value));
  const columns = [
    { title: text('pages.security.events.time', '时间'), dataIndex: 'occurredAtUtc', fixed: 'left' as const, render: (value: string) => localDateTime(value) },
    { title: text('pages.security.events.result', '结果'), dataIndex: 'success', render: (value: boolean) => <Tag color={value ? 'green' : 'red'}>{value ? text('pages.security.events.success', '成功') : text('pages.security.events.failure', '失败')}</Tag> },
    { title: text('pages.security.events.protocol', '协议'), dataIndex: 'protocol', render: (value: LoginEvent['protocol']) => loginEventProtocolLabel(value, text('pages.security.events.unidentifiedProtocol', '未识别协议')) },
    { title: text('pages.security.events.username', '用户名'), dataIndex: 'username', render: (value?: string) => value || text('pages.security.events.notProvided', '未提供') },
    { title: text('pages.security.events.remoteEndpoint', '远端端点'), render: (_: unknown, item: LoginEvent) => <IpLocationText ip={item.remoteIp} port={item.remotePort} endpoint missingLabel={text('pages.security.events.notProvided', '未提供')} /> },
    { title: text('pages.security.events.localEndpoint', '本地端点'), render: (_: unknown, item: LoginEvent) => `${item.localIp || text('pages.security.events.notProvided', '未提供')}:${item.localPort ?? text('pages.security.events.notProvided', '未提供')}` },
    { title: text('pages.security.events.process', '本地进程'), dataIndex: 'localProcessName', render: (value?: string) => value || text('pages.security.events.notCollected', '未采集') },
    { title: text('pages.security.events.collector', '采集器'), dataIndex: 'collector' },
    { title: text('pages.security.events.evidence', '证据来源'), dataIndex: 'evidenceSource', ellipsis: true },
  ];

  return <PageContainer title={text('pages.security.events.title', '登录事件')} content={text('pages.security.events.description', '成功/失败登录事件和证据来源')}>
    {error && <Alert showIcon type="warning" message={error} />}
    <Card
      style={{ marginTop: 16 }}
      title={`${text('pages.security.events.recent', '最近')} ${data.length} ${text('pages.security.events.eventsUnit', '条事件')} · ${text('pages.security.events.success', '成功')} ${successCount} / ${text('pages.security.events.failure', '失败')} ${data.length - successCount}`}
      extra={<Button icon={<ReloadOutlined />} onClick={() => void load()} loading={loading}>{text('pages.common.refresh', '刷新')}</Button>}
    >
      <Table rowKey="id" dataSource={data} loading={loading} scroll={{ x: 1100 }} pagination={{ pageSize: 20 }} columns={columns} />
    </Card>
  </PageContainer>;
}
