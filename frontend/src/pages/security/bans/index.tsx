import IpLocationText from '@/components/IpLocationText';
import { ReloadOutlined } from '@ant-design/icons';
import { Alert, Button, Card, Table, Tag } from 'antd';
import { PageContainer } from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { useCallback, useEffect, useRef, useState } from 'react';
import { queryFirewallActions, type FirewallAction } from '@/services/ipban/management';
import { subscribeManagementRealtime } from '@/services/ipban/realtime';
import { firewallActionLabel, firewallProviderLabel, firewallStatusColor, firewallStatusLabel } from '@/utils/firewallLabels';

export default function BansPage() {
  const intl = useIntl();
  const text = (id: string) => intl.formatMessage({ id });
  const [data, setData] = useState<FirewallAction[]>([]);
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(false);
  const requestSequence = useRef(0);
  const load = useCallback(async () => {
    const sequence = ++requestSequence.current;
    setLoading(true);
    setError(undefined);
    const result = await queryFirewallActions();
    if (sequence !== requestSequence.current) return;
    if (result.success) setData(result.data ?? []);
    else setError(result.message);
    setLoading(false);
  }, []);
  useEffect(() => {
    void load();
    let unsubscribe: (() => void) | undefined;
    let disposed = false;
    void subscribeManagementRealtime('security-events', () => void load()).then((cleanup) => {
      if (disposed) cleanup();
      else unsubscribe = cleanup;
    });
    return () => { disposed = true; unsubscribe?.(); };
  }, [load]);
  const localDateTime = (value?: string | null) => value ? new Intl.DateTimeFormat(intl.locale, { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(value)) : '-';
  return <PageContainer title={text('pages.security.bans.title')} content={text('pages.security.bans.description')}>
    {error && <Alert showIcon type="warning" message={error} />}
    <Card style={{ marginTop: 16 }} extra={<Button icon={<ReloadOutlined />} onClick={() => void load()} loading={loading}>{text('pages.common.refresh')}</Button>}>
      <Table rowKey="id" dataSource={data} loading={loading} scroll={{ x: 1000 }} columns={[
        { title: text('pages.security.bans.time'), dataIndex: 'createdAtUtc', render: (value: string) => localDateTime(value) },
        { title: text('pages.security.decisions.sourceIp'), dataIndex: 'sourceIp', render: (value: string) => <IpLocationText ip={value} /> },
        { title: text('pages.security.decisions.action'), dataIndex: 'action', render: (value: string) => firewallActionLabel(value, text) },
        { title: text('pages.security.decisions.provider'), dataIndex: 'provider', render: (value: string) => firewallProviderLabel(value, text) },
        { title: text('pages.security.decisions.status'), dataIndex: 'status', render: (value: string) => <Tag color={firewallStatusColor(value)}>{firewallStatusLabel(value, text)}</Tag> },
        { title: text('pages.security.bans.completedAt'), dataIndex: 'completedAtUtc', render: (value?: string) => localDateTime(value) },
      ]} pagination={{ pageSize: 20 }} />
    </Card>
  </PageContainer>;
}
