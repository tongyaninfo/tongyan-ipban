import IpLocationText from '@/components/IpLocationText';
import {
  DeleteOutlined,
  EditOutlined,
  PlusOutlined,
  ReloadOutlined,
} from '@ant-design/icons';
import {
  Alert,
  Button,
  Card,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  message,
} from 'antd';
import { PageContainer } from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { useEffect, useState } from 'react';
import {
  deleteAccessList,
  queryAccessList,
  upsertAccessList,
  type AccessListEntry,
} from '@/services/ipban/management';

export default function AccessListPage() {
  const intl = useIntl();
  const [data, setData] = useState<AccessListEntry[]>([]);
  const [error, setError] = useState<string>();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<AccessListEntry>();
  const [savingId, setSavingId] = useState<number>();
  const [form] = Form.useForm();
  const text = (id: string, fallback: string) => intl.formatMessage({ id, defaultMessage: fallback });

  const load = () => queryAccessList().then((result) => {
    if (result.success) {
      setData(result.data ?? []);
      setError(undefined);
    } else {
      setError(result.message);
    }
  });

  useEffect(() => { void load(); }, []);

  const openCreate = () => {
    setEditing(undefined);
    form.resetFields();
    form.setFieldsValue({ entryType: 'Deny', source: 'Manual', priority: 100, status: 'Active' });
    setOpen(true);
  };

  const openEdit = (entry: AccessListEntry) => {
    setEditing(entry);
    form.setFieldsValue(entry);
    setOpen(true);
  };

  const save = async () => {
    const values = await form.validateFields();
    const result = await upsertAccessList({
      address: values.address,
      entryType: values.entryType,
      source: values.source || editing?.source || 'Manual',
      reason: values.reason,
      priority: values.priority,
      status: values.status,
      createdBy: editing?.createdBy || 'local-admin',
      effectiveAtUtc: values.effectiveAtUtc,
      expiresAtUtc: values.expiresAtUtc,
    }, editing?.id);
    if (!result.success) {
      message.error(result.message);
      return;
    }
    message.success(text('pages.access.allowlist.saved', '名单条目已保存'));
    setOpen(false);
    setEditing(undefined);
    form.resetFields();
    void load();
  };

  const toggle = async (entry: AccessListEntry, enabled: boolean) => {
    setSavingId(entry.id);
    const result = await upsertAccessList({
      address: entry.address,
      entryType: entry.entryType,
      source: entry.source,
      reason: entry.reason,
      priority: entry.priority,
      status: enabled ? 'Active' : 'Inactive',
      createdBy: entry.createdBy,
      effectiveAtUtc: entry.effectiveAtUtc,
      expiresAtUtc: entry.expiresAtUtc,
    }, entry.id);
    setSavingId(undefined);
    if (!result.success) {
      message.error(result.message);
      return;
    }
    void load();
  };

  const remove = async (entry: AccessListEntry) => {
    const result = await deleteAccessList(entry.id);
    if (!result.success) {
      message.error(result.message);
      return;
    }
    message.success(text('pages.access.allowlist.deleted', '名单条目已删除'));
    void load();
  };

  const statusLabel = (value: string) => {
    const normalized = value.toLowerCase();
    if (normalized === 'active') return text('pages.access.allowlist.active', '启用');
    if (normalized === 'inactive' || normalized === 'disabled') return text('pages.access.allowlist.inactive', '停用');
    if (normalized === 'expired') return text('pages.access.allowlist.expired', '已到期');
    return value;
  };

  const typeLabel = (value: string) => value.toLowerCase() === 'allow'
    ? text('pages.access.allowlist.allow', '允许')
    : text('pages.access.allowlist.deny', '拒绝');

  return (
    <PageContainer
      title={text('pages.access.allowlist.title', '黑白名单')}
      content={text('pages.access.allowlist.subtitle', '管理允许和拒绝的 IP、CIDR 条目')}
    >
      {error && <Alert showIcon type="warning" message={error} />}
      <Card
        style={{ marginTop: 16 }}
        extra={(
          <Space>
            <Button icon={<ReloadOutlined />} onClick={() => void load()}>{text('pages.common.refresh', '刷新')}</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>{text('pages.access.allowlist.create', '新增条目')}</Button>
          </Space>
        )}
      >
        <Table
          rowKey="id"
          dataSource={data}
          columns={[
            { title: text('pages.access.allowlist.address', '地址/CIDR'), dataIndex: 'address', render: (value: string) => <IpLocationText ip={value} /> },
            {
              title: text('pages.access.allowlist.type', '类型'),
              dataIndex: 'entryType',
              render: (value: string) => <Tag color={value.toLowerCase() === 'allow' ? 'green' : 'red'}>{typeLabel(value)}</Tag>,
            },
            { title: text('pages.access.allowlist.reason', '原因'), dataIndex: 'reason', render: (value?: string) => value || '-' },
            { title: text('pages.access.allowlist.priority', '优先级'), dataIndex: 'priority' },
            {
              title: text('pages.access.allowlist.status', '状态'),
              dataIndex: 'status',
              render: (value: string, record: AccessListEntry) => (
                <Space>
                  <Switch
                    checked={value.toLowerCase() === 'active'}
                    loading={savingId === record.id}
                    onChange={(checked) => void toggle(record, checked)}
                  />
                  <Tag color={value.toLowerCase() === 'active' ? 'green' : 'default'}>{statusLabel(value)}</Tag>
                </Space>
              ),
            },
            {
              title: text('pages.access.allowlist.expires', '到期时间'),
              dataIndex: 'expiresAtUtc',
              render: (value?: string) => value ? new Date(value).toLocaleString() : text('pages.access.allowlist.noExpiry', '未设置'),
            },
            {
              title: text('pages.current.actions', '操作'),
              render: (_: unknown, record: AccessListEntry) => (
                <Space>
                  <Button type="link" icon={<EditOutlined />} onClick={() => openEdit(record)}>{text('pages.common.edit', '编辑')}</Button>
                  <Popconfirm title={text('pages.access.allowlist.deleteConfirm', '确认删除此名单条目？')} onConfirm={() => void remove(record)}>
                    <Button type="link" danger icon={<DeleteOutlined />}>{text('pages.common.delete', '删除')}</Button>
                  </Popconfirm>
                </Space>
              ),
            },
          ]}
          pagination={{ pageSize: 20 }}
        />
      </Card>
      <Modal
        title={text(editing ? 'pages.access.allowlist.editTitle' : 'pages.access.allowlist.createTitle', editing ? '编辑名单条目' : '新增名单条目')}
        open={open}
        onCancel={() => setOpen(false)}
        onOk={() => void save()}
        destroyOnClose
      >
        <Form form={form} layout="vertical">
          <Form.Item name="address" label={text('pages.access.allowlist.address', 'IP/CIDR')} rules={[{ required: true }]}><Input placeholder="192.0.2.10 或 192.0.2.0/24" /></Form.Item>
          <Form.Item name="entryType" label={text('pages.access.allowlist.type', '类型')} rules={[{ required: true }]}><Select options={[{ label: text('pages.access.allowlist.allow', '允许'), value: 'Allow' }, { label: text('pages.access.allowlist.deny', '拒绝'), value: 'Deny' }]} /></Form.Item>
          <Form.Item name="reason" label={text('pages.access.allowlist.reason', '原因')}><Input /></Form.Item>
          <Form.Item name="priority" label={text('pages.access.allowlist.priority', '优先级')}><InputNumber min={0} max={10000} style={{ width: '100%' }} /></Form.Item>
          <Form.Item name="status" label={text('pages.access.allowlist.status', '状态')}><Select options={[{ label: text('pages.access.allowlist.active', '启用'), value: 'Active' }, { label: text('pages.access.allowlist.inactive', '停用'), value: 'Inactive' }]} /></Form.Item>
        </Form>
      </Modal>
    </PageContainer>
  );
}
