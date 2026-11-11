import { EditOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { Alert, Button, Card, Form, Input, Modal, Space, Switch, Table, Tag, message } from 'antd';
import { PageContainer } from '@ant-design/pro-components';
import { useEffect, useMemo, useState } from 'react';
import { useIntl } from '@umijs/max';
import { queryUsers, upsertUser, type UserSummary } from '@/services/ipban/management';

export default function UsersPage() {
  const intl = useIntl();
  const text = (id: string, defaultMessage: string) => intl.formatMessage({ id, defaultMessage });
  const [data, setData] = useState<UserSummary[]>([]);
  const [error, setError] = useState<string>();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<UserSummary>();
  const [form] = Form.useForm();
  const load = () => queryUsers().then((result) => {
    if (result.success) setData(result.data ?? []);
    else setError(result.message);
  });
  const edit = (user?: UserSummary) => {
    setEditing(user);
    form.resetFields();
    if (user) form.setFieldsValue({ ...user, password: undefined });
    else form.setFieldsValue({ enabled: true });
    setOpen(true);
  };
  const save = async () => {
    const values = await form.validateFields();
    const result = await upsertUser(values, editing?.id);
    if (!result.success) {
      message.error(result.message);
      return;
    }
    message.success(text('pages.system.users.saved', '用户已保存'));
    setOpen(false);
    setEditing(undefined);
    void load();
  };
  const columns = useMemo(() => [
    { title: text('pages.system.users.username', '用户名'), dataIndex: 'username' },
    { title: text('pages.system.users.displayName', '显示名称'), dataIndex: 'displayName' },
    { title: text('pages.system.users.status', '状态'), dataIndex: 'enabled', render: (value: boolean) => <Tag color={value ? 'green' : 'red'}>{value ? text('pages.system.users.enabled', '启用') : text('pages.system.users.disabled', '停用')}</Tag> },
    { title: text('pages.system.users.createdAt', '创建时间'), dataIndex: 'createdAtUtc', render: (value: string) => new Date(value).toLocaleString() },
    { title: text('pages.system.users.lastLogin', '最后登录'), dataIndex: 'lastLoginAtUtc', render: (value?: string) => value ? new Date(value).toLocaleString() : '-' },
    { title: text('pages.system.users.actions', '操作'), render: (_: unknown, record: UserSummary) => <Button type="link" icon={<EditOutlined />} onClick={() => edit(record)}>{text('pages.common.edit', '编辑')}</Button> },
  ], [intl]);
  useEffect(() => { void load(); }, []);
  return <PageContainer title={text('pages.system.users.title', '用户管理')} content={text('pages.system.users.description', '管理本机账号、状态、密码和最后登录')}>
    {error && <Alert showIcon type="warning" message={error} />}
    <Card style={{ marginTop: 16 }} extra={<Space><Button icon={<ReloadOutlined />} onClick={() => void load()}>{text('pages.common.refresh', '刷新')}</Button><Button type="primary" icon={<PlusOutlined />} onClick={() => edit()}>{text('pages.system.users.add', '新增用户')}</Button></Space>}>
      <Table rowKey="id" dataSource={data} columns={columns} pagination={{ pageSize: 20 }} />
    </Card>
    <Modal title={editing ? text('pages.system.users.edit', '编辑用户') : text('pages.system.users.add', '新增用户')} open={open} onCancel={() => setOpen(false)} onOk={() => void save()} destroyOnClose>
      <Form form={form} layout="vertical">
        <Form.Item name="username" label={text('pages.system.users.username', '用户名')} rules={[{ required: true }]}><Input disabled={Boolean(editing)} /></Form.Item>
        <Form.Item name="displayName" label={text('pages.system.users.displayName', '显示名称')} rules={[{ required: true }]}><Input /></Form.Item>
        <Form.Item name="password" label={editing ? text('pages.system.users.passwordOptional', '新密码（留空不修改）') : text('pages.system.users.password', '密码')} rules={editing ? [] : [{ required: true }]}><Input.Password /></Form.Item>
        <Form.Item name="enabled" label={text('pages.system.users.enabled', '启用')} valuePropName="checked"><Switch /></Form.Item>
      </Form>
    </Modal>
  </PageContainer>;
}
