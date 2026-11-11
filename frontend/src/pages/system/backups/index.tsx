import { DatabaseOutlined, ReloadOutlined } from '@ant-design/icons';
import { Alert, Button, Card, Space, Table, Tag, message } from 'antd';
import { PageContainer } from '@ant-design/pro-components';
import { useEffect, useState } from 'react';
import { createBackup, queryBackups, type BackupRecord } from '@/services/ipban/management';

const formatBytes = (value: number) => value ? `${(value / 1024 / 1024).toFixed(2)} MB` : '0 B';

export default function BackupsPage() {
  const [data, setData] = useState<BackupRecord[]>([]);
  const [error, setError] = useState<string>();
  const load = () => queryBackups().then((result) => { if (result.success) setData(result.data ?? []); else setError(result.message); });
  useEffect(() => { void load(); }, []);
  const backup = async () => { const result = await createBackup(); if (!result.success) { message.error(result.message); return; } message.success('数据库备份已完成'); void load(); };
  return <PageContainer title="备份管理" content="数据库、日志归档和备份校验">
    {error && <Alert showIcon type="warning" message={error} />}
    <Card style={{ marginTop: 16 }} extra={<Space><Button icon={<ReloadOutlined />} onClick={() => void load()}>刷新</Button><Button type="primary" icon={<DatabaseOutlined />} onClick={() => void backup()}>立即备份数据库</Button></Space>}>
      <Table rowKey="id" dataSource={data} columns={[
        { title: '类型', dataIndex: 'backupKind' }, { title: '文件', dataIndex: 'backupPath', ellipsis: true },
        { title: '大小', dataIndex: 'sizeBytes', render: formatBytes }, { title: 'SHA-256', dataIndex: 'sha256', ellipsis: true },
        { title: '创建时间', dataIndex: 'createdAtUtc', render: (value: string) => new Date(value).toLocaleString() },
        { title: '状态', dataIndex: 'status', render: (value: string) => <Tag color={value === 'Completed' ? 'green' : 'red'}>{value}</Tag> },
      ]} pagination={{ pageSize: 20 }} />
    </Card>
  </PageContainer>;
}
