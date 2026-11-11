import IpLocationText from '@/components/IpLocationText';
import { ReloadOutlined, SettingOutlined } from '@ant-design/icons';
import {
  Alert, App, Button, Card, DatePicker, Descriptions, Drawer, Flex, Form, Input, InputNumber,
  Modal, Select, Skeleton, Table, Tag, theme, Typography, type TableColumnsType,
} from 'antd';
import type { Dayjs } from 'dayjs';
import { useEffect, useState } from 'react';
import {
  getMcpAudit, listMcpAudits, type McpAuditDetail, type McpAuditQuery, type McpAuditRow,
  type McpSettings, type McpTool, updateMcpSettings,
} from '@/services/ipban/mcp';
import { fromShanghaiTime, useMcpMessages } from './display';

const statuses = ['success', 'denied', 'error', 'pending', 'uncertain'] as const;
const statusColors: Record<string, string> = {
  success: 'green', denied: 'orange', error: 'red', pending: 'blue', uncertain: 'gold',
};

type FilterValues = {
  time?: [Dayjs, Dayjs];
  keyId?: string;
  tool?: string;
  status?: string;
};

function AuditDetail({ id, onClose }: { id?: string; onClose: () => void }) {
  const { text, formatTime } = useMcpMessages();
  const { token } = theme.useToken();
  const [detail, setDetail] = useState<McpAuditDetail>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    if (!id) return;
    const controller = new AbortController();
    setDetail(undefined);
    setError(undefined);
    void getMcpAudit(id, controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      if (result.success) setDetail(result.data);
      else setError(result.message);
    });
    return () => controller.abort();
  }, [id]);

  return (
    <Drawer title={text('detail')} open={Boolean(id)} size="large" onClose={onClose} destroyOnHidden>
      {error ? <Alert type="error" showIcon title={error} /> : detail && detail.id === id ? (
        <Flex vertical gap={16}>
          <Descriptions size="small" column={{ xs: 1, sm: 2 }} bordered items={[
            { key: 'time', label: text('time'), children: formatTime(detail.occurredAtUtc) },
            { key: 'ip', label: text('remoteIp'), children: <IpLocationText ip={detail.remoteIp} /> },
            { key: 'key', label: text('key'), children: detail.keyName ?? detail.keyPrefix ?? '—' },
            { key: 'keyId', label: text('keyId'), children: detail.keyId ?? '—' },
            { key: 'method', label: text('method'), children: detail.method ?? '—' },
            { key: 'path', label: text('path'), children: detail.path },
            { key: 'tool', label: text('tool'), children: detail.tool ?? '—' },
            { key: 'status', label: text('status'), children: text(`outcome.${detail.status}`) },
            { key: 'http', label: text('httpStatus'), children: detail.httpStatus ?? '—' },
            { key: 'duration', label: text('duration'), children: detail.durationMs == null ? '—' : `${detail.durationMs} ms` },
            { key: 'trace', label: text('traceId'), span: 'filled', children: <Typography.Text code style={{ overflowWrap: 'anywhere' }}>{detail.traceId}</Typography.Text> },
          ]} />
          {([
            ['requestHeaders', detail.requestHeaders],
            ['requestBody', detail.requestBody],
            ['responseHeaders', detail.responseHeaders],
            ['responseBody', detail.responseBody],
          ] as const).map(([label, value]) => (
            <section key={label}>
              <Typography.Title level={5} style={{ margin: '0 0 6px' }}>{text(label)}</Typography.Title>
              {/* 保留请求和响应原文，避免 JSON 二次解析时损失长整型或更改业务数据。 */}
              <pre style={{
                whiteSpace: 'pre-wrap',
                overflowWrap: 'anywhere',
                margin: 0,
                padding: 12,
                background: token.colorFillQuaternary,
                color: token.colorText,
                borderRadius: token.borderRadius,
                border: `1px solid ${token.colorBorderSecondary}`,
                maxHeight: 360,
                overflow: 'auto',
              }}>{value || text('noPayload')}</pre>
            </section>
          ))}
        </Flex>
      ) : <Skeleton active />}
    </Drawer>
  );
}

export default function McpAudits({ tools, settings, onSettingsChange }: {
  tools: McpTool[];
  settings?: McpSettings;
  onSettingsChange: (settings: McpSettings) => void;
}) {
  const { text, formatTime } = useMcpMessages();
  const { message, modal } = App.useApp();
  const [form] = Form.useForm<FilterValues>();
  const [query, setQuery] = useState<McpAuditQuery>({ page: 1, pageSize: 20 });
  const [revision, setRevision] = useState(0);
  const [records, setRecords] = useState<McpAuditRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();
  const [selected, setSelected] = useState<string>();
  const [retentionOpen, setRetentionOpen] = useState(false);
  const [days, setDays] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    void listMcpAudits(query, controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      setLoading(false);
      if (result.success) {
        setRecords(result.data.items);
        setTotal(result.data.total);
        setError(undefined);
      } else {
        setRecords([]);
        setTotal(0);
        setError(result.message);
      }
    });
    return () => controller.abort();
  }, [query, revision]);

  function applyFilters(values: FilterValues) {
    setQuery((current) => ({
      page: 1,
      pageSize: current.pageSize,
      fromUtc: values.time?.[0] ? fromShanghaiTime(values.time[0]) : undefined,
      toUtc: values.time?.[1] ? fromShanghaiTime(values.time[1], true) : undefined,
      keyId: values.keyId?.trim(),
      tool: values.tool,
      status: values.status,
    }));
  }

  async function saveRetention(value: number, confirmShorter: boolean) {
    setSaving(true);
    try {
      const result = await updateMcpSettings({ auditRetentionDays: value, confirmShorter });
      if (!result.success) {
        void message.error(result.message);
        return;
      }
      onSettingsChange(result.data);
      setRetentionOpen(false);
      setRevision((current) => current + 1);
      void message.success(text('settingsSaved'));
    } finally {
      setSaving(false);
    }
  }

  const validDays = days !== null && Number.isInteger(days) && days >= 1 && days <= 3650;
  function confirmRetention() {
    if (!settings || !validDays || saving) return;
    if (days >= settings.auditRetentionDays) {
      void saveRetention(days, false);
      return;
    }
    modal.confirm({
      title: text('shortenTitle'),
      content: text('shortenConfirm', { days }),
      okText: text('confirm'),
      cancelText: text('cancel'),
      okButtonProps: { danger: true },
      onOk: () => saveRetention(days, true),
    });
  }

  const columns: TableColumnsType<McpAuditRow> = [
    { title: text('time'), dataIndex: 'occurredAtUtc', width: 170, render: formatTime },
    { title: text('key'), dataIndex: 'keyName', width: 130, ellipsis: true, render: (value: string | null, row) => value ?? row.keyPrefix ?? '—' },
    { title: text('tool'), dataIndex: 'tool', width: 190, ellipsis: true, render: (value: string | null, row) => value ?? row.method ?? '—' },
    { title: text('remoteIp'), dataIndex: 'remoteIp', width: 200, render: (value: string | null) => <IpLocationText ip={value} /> },
    { title: text('status'), dataIndex: 'status', width: 105, render: (value: string) => <Tag color={statusColors[value]}>{text(`outcome.${value}`)}</Tag> },
    { title: text('httpStatus'), dataIndex: 'httpStatus', width: 90, render: (value: number | null) => value ?? '—' },
    { title: text('duration'), dataIndex: 'durationMs', width: 100, align: 'right', render: (value: number | null) => value == null ? '—' : `${value} ms` },
    { title: text('actions'), width: 75, render: (_, row) => <Button type="link" size="small" onClick={() => setSelected(row.id)}>{text('detail')}</Button> },
  ];

  return (
    <Card
      title={text('audits')}
      extra={(
        <Flex wrap gap={8}>
          <Button icon={<ReloadOutlined />} aria-label={text('refresh')} onClick={() => setRevision((value) => value + 1)} />
          <Button
            icon={<SettingOutlined />}
            disabled={!settings}
            onClick={() => {
              setDays(settings?.auditRetentionDays ?? null);
              setRetentionOpen(true);
            }}
          >
            {settings ? text('retentionWithDays', { days: settings.auditRetentionDays }) : text('retention')}
          </Button>
        </Flex>
      )}
    >
      <Form<FilterValues> form={form} layout="vertical" onFinish={applyFilters}>
        <Flex wrap align="end" gap={12} style={{ marginBottom: 12 }}>
          <Form.Item name="time" label={text('timeFilter')} style={{ marginBottom: 0, minWidth: 220 }}>
            <DatePicker.RangePicker showTime format="YYYY-MM-DD HH:mm:ss" style={{ maxWidth: '100%' }} />
          </Form.Item>
          <Form.Item name="keyId" label={text('keyId')} style={{ marginBottom: 0 }}>
            <Input allowClear style={{ width: 140 }} />
          </Form.Item>
          <Form.Item name="tool" label={text('tool')} style={{ marginBottom: 0 }}>
            <Select allowClear showSearch style={{ width: 175 }} options={tools.map((tool) => ({
              value: tool.id, label: text(`tool.${tool.id}`),
            }))} />
          </Form.Item>
          <Form.Item name="status" label={text('status')} style={{ marginBottom: 0 }}>
            <Select allowClear style={{ width: 112 }} options={statuses.map((status) => ({
              value: status, label: text(`outcome.${status}`),
            }))} />
          </Form.Item>
          <Button type="primary" htmlType="submit">{text('filter')}</Button>
          <Button onClick={() => { form.resetFields(); applyFilters({}); }}>{text('reset')}</Button>
        </Flex>
      </Form>
      {error && <Alert type="error" showIcon title={error} style={{ marginBottom: 12 }} />}
      <Table size="small" rowKey="id" loading={loading} dataSource={records} columns={columns}
        scroll={{ x: 990 }} locale={{ emptyText: text('noAudits') }}
        pagination={{
          current: query.page, pageSize: query.pageSize, total, showSizeChanger: true,
          pageSizeOptions: [20, 50, 100],
          onChange: (page, pageSize) => setQuery((current) => ({
            ...current, page: current.pageSize === pageSize ? page : 1, pageSize,
          })),
        }} />
      <AuditDetail id={selected} onClose={() => setSelected(undefined)} />
      <Modal title={text('retention')} open={retentionOpen} onCancel={() => setRetentionOpen(false)}
        onOk={confirmRetention} okButtonProps={{ disabled: !validDays }} confirmLoading={saving}
        cancelButtonProps={{ disabled: saving }} closable={!saving} keyboard={!saving}
        mask={{ closable: !saving }} okText={text('save')} cancelText={text('cancel')}>
        <Flex vertical gap={8}>
          <label htmlFor="mcp-audit-retention-days">{text('retentionDays')}</label>
          <InputNumber id="mcp-audit-retention-days" min={1} max={3650} step={1} value={days} onChange={setDays} style={{ width: '100%' }} />
          <Typography.Text type="secondary">{text('retentionHint')}</Typography.Text>
        </Flex>
      </Modal>
    </Card>
  );
}
