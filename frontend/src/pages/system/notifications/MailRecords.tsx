import { ReloadOutlined } from '@ant-design/icons';
import { Alert, Button, Card, Descriptions, Flex, Modal, Select, Skeleton, Table, Tag, Typography, type TableColumnsType } from 'antd';
import { useEffect, useState } from 'react';
import { getNotificationMessage, listNotificationMessages, type NotificationMessage, type NotificationMessageDetail, type NotificationMessageQuery, type NotificationStatus } from '@/services/ipban/notifications';
import MailContent from './MailContent';
import { useNotificationMessages } from './display';

const statuses: NotificationStatus[] = ['sent', 'queued', 'sending', 'retry', 'failed', 'expired', 'cancelled'];
const statusColors: Record<NotificationStatus, string> = { sent: 'green', queued: 'blue', sending: 'processing', retry: 'orange', failed: 'red', expired: 'default', cancelled: 'default' };

export function MailDetail({ id, onClose }: { id?: string; onClose: () => void }) {
  const { text, formatTime } = useNotificationMessages();
  const [detail, setDetail] = useState<NotificationMessageDetail>();
  const [error, setError] = useState<string>();
  useEffect(() => {
    if (!id) return;
    const controller = new AbortController();
    setDetail(undefined);
    setError(undefined);
    void getNotificationMessage(id, controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      if (result.success) setDetail(result.data);
      else setError(result.message);
    });
    return () => controller.abort();
  }, [id]);
  const item = detail?.message;
  return <Modal title={text('detailTitle')} open={Boolean(id)} width={960} footer={null} onCancel={onClose} destroyOnHidden>
    {error ? <Alert type="error" showIcon title={error} /> : detail && item && item.id === id ? <Flex vertical gap={16}>
      <Alert type="info" showIcon title={text('deliveryHint')} />
      <Descriptions size="small" bordered column={{ xs: 1, sm: 2 }} items={[
        { key: 'subject', label: text('subject'), span: 'filled', children: item.subject },
        { key: 'recipient', label: text('recipients'), children: item.recipient },
        { key: 'status', label: text('status'), children: <Tag color={statusColors[item.status]}>{text(`status.${item.status}`)}</Tag> },
        { key: 'type', label: text('eventType'), children: text(`event.${item.eventType}`) },
        { key: 'count', label: text('eventCount'), children: item.eventCount },
        { key: 'ip', label: text('sourceIp'), children: item.sourceIp || '—' },
        { key: 'attempts', label: text('attempts'), children: item.attempts },
        { key: 'created', label: text('createdAt'), children: formatTime(item.createdAtUtc) },
        { key: 'sent', label: text('sentAt'), children: formatTime(item.sentAtUtc) },
        { key: 'next', label: text('nextAttemptAt'), children: formatTime(item.nextAttemptAtUtc) },
        { key: 'version', label: text('templateVersion'), children: detail.templateVersion },
        { key: 'message', label: text('messageId'), span: 'filled', children: <Typography.Text style={{ overflowWrap: 'anywhere' }}>{detail.messageId}</Typography.Text> },
        { key: 'error', label: text('lastError'), span: 'filled', children: item.lastErrorMessage || item.lastErrorCode || '—' },
      ]} />
      <MailContent html={detail.htmlBody} plainText={detail.textBody} title={text('snapshot')} />
      <Typography.Title level={5} style={{ marginBottom: 0 }}>{text('relatedEvents')}</Typography.Title>
      {item.eventCount > detail.events.length && <Alert type="info" showIcon title={text('eventSampleHint', { total: item.eventCount, count: detail.events.length })} />}
      {/* 逐条展示生成时保存的事件样本，不能用摘要的首条来源或状态推断整组事件。 */}
      <Table size="small" rowKey={(event) => `${event.eventType}:${event.sourceId}:${event.occurredAtUtc}`} dataSource={detail.events} scroll={{ x: 880 }}
        pagination={detail.events.length > 10 ? { pageSize: 10, showSizeChanger: false } : false} locale={{ emptyText: text('noRelatedEvents') }} columns={[
          { title: text('eventTime'), dataIndex: 'occurredAtUtc', width: 175, render: (value?: string) => value ? formatTime(value) : text('notProvided') },
          { title: text('sourceIp'), dataIndex: 'sourceIp', width: 150, render: (value?: string) => value || text('notProvided') },
          { title: text('protocol'), dataIndex: 'protocol', width: 110, render: (value?: string) => value || text('notProvided') },
          { title: text('username'), dataIndex: 'username', width: 130, render: (value?: string) => value || text('notProvided') },
          { title: text('eventStatus'), dataIndex: 'status', width: 150, render: (value?: string) => value || text('notProvided') },
          { title: text('reason'), dataIndex: 'reason', width: 200, render: (value?: string) => value || text('notProvided') },
        ]} />
    </Flex> : <Skeleton active />}
  </Modal>;
}

export default function MailRecords({ revision = 0 }: { revision?: number }) {
  const { text, formatTime } = useNotificationMessages();
  const [query, setQuery] = useState<NotificationMessageQuery>({ page: 1, pageSize: 20, status: 'sent' });
  const [refresh, setRefresh] = useState(0);
  const [records, setRecords] = useState<NotificationMessage[]>([]);
  const [total, setTotal] = useState(0);
  const [pendingEvents, setPendingEvents] = useState(0);
  const [suppressedEvents, setSuppressedEvents] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();
  const [selected, setSelected] = useState<string>();
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(undefined);
    void listNotificationMessages(query, controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      setLoading(false);
      if (result.success) {
        setRecords(result.data.items);
        setTotal(result.data.total);
        setPendingEvents(result.data.pendingEvents);
        setSuppressedEvents(result.data.suppressedEvents);
      } else {
        setRecords([]);
        setTotal(0);
        setError(result.message);
      }
    });
    return () => controller.abort();
  }, [query, refresh, revision]);
  const columns: TableColumnsType<NotificationMessage> = [
    { title: text('createdAt'), dataIndex: 'createdAtUtc', width: 175, render: formatTime },
    { title: text('eventType'), dataIndex: 'eventType', width: 110, render: (value: string) => text(`event.${value}`) },
    { title: text('subject'), dataIndex: 'subject', width: 240, ellipsis: true },
    { title: text('recipients'), dataIndex: 'recipient', width: 220, ellipsis: true },
    { title: text('status'), dataIndex: 'status', width: 140, render: (value: NotificationStatus) => <Tag color={statusColors[value]}>{text(`status.${value}`)}</Tag> },
    { title: text('eventCount'), dataIndex: 'eventCount', width: 90 },
    { title: text('sentAt'), dataIndex: 'sentAtUtc', width: 175, render: formatTime },
    { title: text('actions'), width: 100, fixed: 'right', render: (_, row) => <Button type="link" size="small" onClick={() => setSelected(row.id)}>{text('detail')}</Button> },
  ];
  return <Card>
    <Flex vertical gap={16}>
      <Alert type="info" showIcon title={text('deliveryHint')} />
      <Flex wrap gap={12} align="center">
        <Select aria-label={text('status')} value={query.status ?? ''} style={{ minWidth: 170 }} options={[
          { value: '', label: text('allStatuses') }, ...statuses.map((value) => ({ value, label: text(`status.${value}`) })),
        ]} onChange={(status: string) => setQuery((current) => ({ ...current, page: 1, status: status ? status as NotificationStatus : undefined }))} />
        <Select aria-label={text('eventType')} value={query.eventType ?? ''} style={{ minWidth: 160 }} options={[
          { value: '', label: text('allEvents') }, ...['loginSuccess', 'loginFailure', 'ban', 'unban', 'test'].map((value) => ({ value, label: text(`event.${value}`) })),
        ]} onChange={(eventType: string) => setQuery((current) => ({ ...current, page: 1, eventType: eventType ? eventType as NotificationMessageQuery['eventType'] : undefined }))} />
        <Button icon={<ReloadOutlined />} onClick={() => setRefresh((value) => value + 1)}>{text('refresh')}</Button>
        <Typography.Text type="secondary">{text('queueCounts', { pending: pendingEvents, suppressed: suppressedEvents })}</Typography.Text>
      </Flex>
      {error && <Alert type="error" showIcon title={error} />}
      <Table size="small" rowKey="id" columns={columns} dataSource={records} loading={loading} scroll={{ x: 1250 }} locale={{ emptyText: text('emptyRecords') }}
        pagination={{ current: query.page, pageSize: query.pageSize, total, showSizeChanger: true, pageSizeOptions: [20, 50, 100],
          onChange: (page, pageSize) => setQuery((current) => ({ ...current, page: current.pageSize === pageSize ? page : 1, pageSize })),
        }} />
    </Flex>
    <MailDetail id={selected} onClose={() => setSelected(undefined)} />
  </Card>;
}
