import IpLocationText from '@/components/IpLocationText';
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { Alert, Button, Card, Form, Input, message, Modal, Popconfirm, Radio, Space, Table, Tag } from 'antd';
import { PageContainer } from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { useCallback, useEffect, useRef, useState } from 'react';
import { queryFirewallActions, unbanSource, type FirewallAction } from '@/services/ipban/management';
import { subscribeManagementRealtime } from '@/services/ipban/realtime';
import { banAddress } from '@/services/ipban/system';
import { firewallActionLabel, firewallProviderLabel, firewallStatusColor, firewallStatusLabel, unbanErrorLabel } from '@/utils/firewallLabels';

type BanFormValues = {
  sourceAddress: string;
  durationMode: 'limited' | 'permanent';
  durationSeconds?: string;
  reason: string;
};

const defaultBanValues: Partial<BanFormValues> = { durationMode: 'limited', durationSeconds: '180' };

export default function DecisionsPage() {
  const intl = useIntl();
  const [feedback, contextHolder] = message.useMessage();
  const text = (id: string) => intl.formatMessage({ id });
  const [data, setData] = useState<FirewallAction[]>([]);
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(false);
  const [releasing, setReleasing] = useState<string>();
  const [creating, setCreating] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [createError, setCreateError] = useState<string>();
  const [form] = Form.useForm<BanFormValues>();
  const durationMode = Form.useWatch('durationMode', form);
  const createInFlight = useRef(false);
  const requestSequence = useRef(0);
  const load = useCallback(async (clearError = true) => {
    const sequence = ++requestSequence.current;
    setLoading(true);
    if (clearError) setError(undefined);
    const result = await queryFirewallActions();
    // 解封后的查询优先，较早返回的请求不能覆盖新状态。
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

  const createBan = async (values: BanFormValues) => {
    if (createInFlight.current) return;
    createInFlight.current = true;
    setCreating(true);
    setCreateError(undefined);
    try {
      const duration = values.durationMode === 'permanent' ? -1 : Number(values.durationSeconds);
      const result = await banAddress(values.sourceAddress.trim(), duration, false, values.reason.trim());
      if (result.success) {
        setCreateOpen(false);
        feedback.success(text('pages.security.decisions.createSuccess'));
      } else {
        setCreateError(result.message);
      }
      // 即使执行失败也可能留下记录，重新读取以显示防火墙的实际执行结果。
      await load();
    } finally {
      createInFlight.current = false;
      setCreating(false);
    }
  };

  const release = async (record: FirewallAction) => {
    if (releasing || !record.canUnban) return;
    setReleasing(String(record.id));
    setError(undefined);
    try {
      const result = await unbanSource(record.sourceIp, String(record.id));
      if (result.success) {
        feedback.success(text('pages.security.decisions.unbanSuccess'));
        await load();
      } else {
        const detail = unbanErrorLabel(result.code, result.message, text);
        setError(detail);
        feedback.error(detail);
        // 状态竞争或审计失败时重新读取真实结果，保留错误供用户核对。
        await load(false);
      }
    } finally {
      setReleasing(undefined);
    }
  };
  const localDateTime = (value?: string | null) => value ? new Intl.DateTimeFormat(intl.locale, { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(value)) : '-';
  return <PageContainer title={text('pages.security.decisions.title')} content={text('pages.security.decisions.description')}>
    {contextHolder}
    {error && <Alert showIcon type="warning" message={error} />}
    <Card style={{ marginTop: 16 }} extra={<Space>
      <Button icon={<ReloadOutlined />} loading={loading} onClick={() => void load()}>{text('pages.common.refresh')}</Button>
      <Button type="primary" icon={<PlusOutlined />} disabled={creating} onClick={() => {
        setCreateError(undefined);
        setCreateOpen(true);
      }}>{text('pages.security.decisions.create')}</Button>
    </Space>}>
      <Table rowKey="id" dataSource={data} loading={loading} scroll={{ x: 1100 }} columns={[
        { title: text('pages.security.decisions.time'), dataIndex: 'createdAtUtc', render: (value: string) => localDateTime(value) },
        { title: text('pages.security.decisions.sourceIp'), dataIndex: 'sourceIp', render: (value: string) => <IpLocationText ip={value} /> },
        { title: text('pages.security.decisions.action'), dataIndex: 'action', render: (value: string) => firewallActionLabel(value, text) },
        { title: text('pages.security.decisions.provider'), dataIndex: 'provider', render: (value: string) => firewallProviderLabel(value, text) },
        { title: text('pages.security.decisions.status'), render: (_: unknown, record: FirewallAction) => {
          const status = record.currentStatus ?? record.status;
          return <Tag color={firewallStatusColor(status)}>{firewallStatusLabel(status, text)}</Tag>;
        } },
        { title: text('pages.security.decisions.reason'), render: (_: unknown, record: FirewallAction) => record.errorMessage || record.errorCode || '-' },
        { title: text('pages.security.decisions.actions'), fixed: 'right', render: (_: unknown, record: FirewallAction) => record.canUnban ? (
          <Popconfirm title={text('pages.security.decisions.unbanTitle')} description={<><IpLocationText ip={record.sourceIp} /> · {text('pages.security.decisions.unbanDescription')}</>}
            okText={text('pages.security.decisions.unban')} cancelText={text('pages.security.decisions.cancel')}
            disabled={Boolean(releasing)} onConfirm={() => release(record)}>
            <Button type="link" disabled={Boolean(releasing)} loading={releasing === String(record.id)}>{text('pages.security.decisions.unban')}</Button>
          </Popconfirm>
        ) : '-' },
      ]} pagination={{ pageSize: 20 }} />
    </Card>
    <Modal
      title={text('pages.security.decisions.create')}
      open={createOpen}
      onCancel={() => { if (!createInFlight.current) setCreateOpen(false); }}
      onOk={() => form.submit()}
      okText={text(durationMode === 'permanent' ? 'pages.access.policies.permanent' : 'pages.security.decisions.ban')}
      cancelText={text('pages.security.decisions.cancel')}
      cancelButtonProps={{ disabled: creating }}
      confirmLoading={creating}
      destroyOnHidden
    >
      {createError && <Alert showIcon type="error" title={createError} style={{ marginBottom: 16 }} />}
      <Form form={form} initialValues={defaultBanValues} layout="vertical" clearOnDestroy disabled={creating} onFinish={(values) => void createBan(values)}>
        <Form.Item name="sourceAddress" label={text('pages.security.decisions.createSource')}
          rules={[{ required: true, whitespace: true, max: 64, message: text('pages.security.decisions.createSourceInvalid') }]}>
          <Input placeholder="192.0.2.10 / 2001:db8::/64" autoComplete="off" />
        </Form.Item>
        <Form.Item name="durationMode" label={text('pages.access.policies.durationMode')}>
          <Radio.Group options={[
            { value: 'limited', label: text('pages.access.policies.limited') },
            { value: 'permanent', label: text('pages.access.policies.permanent') },
          ]} />
        </Form.Item>
        {durationMode === 'permanent' ? (
          <Alert showIcon type="info" title={text('pages.security.decisions.createPermanentHelp')} style={{ marginBottom: 24 }} />
        ) : (
          <Form.Item name="durationSeconds" label={text('pages.access.policies.durationSeconds')}
            rules={[{
              validator: (_rule, value: unknown) => typeof value === 'string' && /^[0-9]+$/.test(value)
                && Number(value) >= 1 && Number(value) <= 604800
                ? Promise.resolve() : Promise.reject(new Error(text('pages.security.decisions.createDurationInvalid'))),
            }]}>
            <Input inputMode="numeric" autoComplete="off" />
          </Form.Item>
        )}
        <Form.Item name="reason" label={text('pages.security.decisions.createReason')}
          rules={[{ required: true, whitespace: true, max: 500, message: text('pages.security.decisions.createReasonInvalid') }]}>
          <Input.TextArea rows={3} />
        </Form.Item>
      </Form>
    </Modal>
  </PageContainer>;
}
