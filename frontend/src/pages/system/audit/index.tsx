import IpLocationText from '@/components/IpLocationText';
import { Alert, Card, Table, Tag } from 'antd';
import { PageContainer } from '@ant-design/pro-components';
import { useEffect, useState } from 'react';
import { queryAudit, type AuditRecord } from '@/services/ipban/management';

export default function AuditPage() {
  const [data, setData] = useState<AuditRecord[]>([]);
  const [error, setError] = useState<string>();
  useEffect(() => { queryAudit().then((result) => { if (result.success) setData(result.data ?? []); else setError(result.message); }); }, []);
  return <PageContainer title="操作审计" content="管理员登录、配置、封禁、下线和证书操作">
    {error && <Alert showIcon type="warning" message={error} />}
    <Card style={{ marginTop: 16 }}><Table rowKey="id" dataSource={data} columns={[
      { title: '时间', dataIndex: 'occurredAtUtc', render: (value: string) => new Date(value).toLocaleString() },
      { title: '动作', dataIndex: 'action' }, { title: '分类', dataIndex: 'category' },
      { title: '操作者', dataIndex: 'actorUsername', render: (value?: string) => value || 'local-admin' },
      { title: '目标', dataIndex: 'target', render: (value?: string) => value || '-' },
      { title: '来源 IP', dataIndex: 'remoteIp', render: (value?: string) => <IpLocationText ip={value} missingLabel="本机" /> },
      { title: '结果', dataIndex: 'success', render: (value: boolean) => <Tag color={value ? 'green' : 'red'}>{value ? '成功' : '失败'}</Tag> },
    ]} pagination={{ pageSize: 20 }} /></Card>
  </PageContainer>;
}
