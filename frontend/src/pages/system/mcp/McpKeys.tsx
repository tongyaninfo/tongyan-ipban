import { CopyOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import {
  Alert, App, Button, Card, DatePicker, Flex, Form, Input, Modal, Radio, Table, Tag, Tree, Typography,
  type TableColumnsType, type TreeDataNode,
} from 'antd';
import type { Dayjs } from 'dayjs';
import { useEffect, useState } from 'react';
import {
  copyMcpKey, createMcpKey, deleteMcpKey, listMcpKeys, type McpKey, type McpKeyMode, type McpTool, revokeMcpKey,
} from '@/services/ipban/mcp';
import { fromShanghaiTime, useMcpMessages } from './display';

type KeyForm = { name: string; mode: McpKeyMode; expiresAt?: Dayjs; scopes: string[] };

function ScopeTree({ tools, mode, value = [], onChange }: {
  tools: McpTool[];
  mode: McpKeyMode;
  value?: string[];
  onChange?: (value: string[]) => void;
}) {
  const { text } = useMcpMessages();
  const groups = Map.groupBy(tools, (tool) => tool.group);
  const treeData: TreeDataNode[] = [...groups].map(([group, children]) => ({
    key: `group:${group}`,
    title: text(`group.${group}`),
    children: children.map((tool) => ({
      key: tool.id,
      title: (
        <Flex wrap align="center" gap={6}>
          <span>{text(`tool.${tool.id}`)}</span>
          {tool.isDangerous && <Tag color="orange">{text('sensitive')}</Tag>}
        </Flex>
      ),
      disabled: mode === 'read' && tool.isWrite,
    })),
  }));
  return (
    <Tree
      checkable
      selectable={false}
      defaultExpandAll
      blockNode
      treeData={treeData}
      checkedKeys={value}
      onCheck={(checked) => {
        // 分组节点只用于批量勾选，服务端授权记录始终使用叶子工具 ID。
        const ids = new Set(Array.isArray(checked) ? checked : checked.checked);
        onChange?.(tools.filter((tool) => ids.has(tool.id) && (mode === 'write' || !tool.isWrite)).map((tool) => tool.id));
      }}
    />
  );
}

export default function McpKeys({ tools, endpoint }: {
  tools: McpTool[];
  endpoint: string;
}) {
  const { text, formatTime } = useMcpMessages();
  const { message, modal } = App.useApp();
  const [form] = Form.useForm<KeyForm>();
  const mode = Form.useWatch('mode', form) ?? 'read';
  const [keys, setKeys] = useState<McpKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();
  const [revision, setRevision] = useState(0);
  const [creating, setCreating] = useState(false);
  const [saving, setSaving] = useState(false);
  const [copyingId, setCopyingId] = useState<string>();
  const [instruction, setInstruction] = useState<string>();

  function refresh() {
    setLoading(true);
    setRevision((value) => value + 1);
  }

  useEffect(() => {
    const controller = new AbortController();
    void listMcpKeys(controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      setLoading(false);
      if (result.success) {
        setKeys(result.data);
        setError(undefined);
      } else setError(result.message);
    });
    return () => controller.abort();
  }, [revision]);

  function buildInstruction(secret: string) {
    return text('instruction', { endpoint, secret });
  }

  async function copyInstruction(value: string) {
    if (navigator.clipboard) {
      try {
        await navigator.clipboard.writeText(value);
        void message.success(text('copied'));
        return true;
      } catch {
        // 浏览器拒绝写入时，继续提供手动复制。
      }
    }
    // HTTP 页面可能没有剪贴板 API，指令仅在当前对话框内保留。
    setInstruction(value);
    void message.warning(text('copyFallback'));
    return false;
  }

  async function copyKey(key: McpKey) {
    setCopyingId(key.id);
    try {
      const result = await copyMcpKey(key.id);
      if (!result.success) {
        void message.error(result.message);
        return;
      }
      await copyInstruction(buildInstruction(result.data.secret));
    } finally {
      setCopyingId(undefined);
    }
  }

  function confirmCopy(key: McpKey) {
    modal.confirm({
      title: text('copy'),
      content: text('copyConfirm', { name: key.name }),
      okText: text('copy'),
      cancelText: text('cancel'),
      onOk: () => copyKey(key),
    });
  }

  async function createKey(values: KeyForm) {
    if (saving) return;
    const expiresAtUtc = values.expiresAt ? fromShanghaiTime(values.expiresAt) : null;
    if (expiresAtUtc && Date.parse(expiresAtUtc) <= Date.now()) {
      form.setFields([{ name: 'expiresAt', errors: [text('futureExpiry')] }]);
      return;
    }
    setSaving(true);
    try {
      const result = await createMcpKey({
        name: values.name.trim(), mode: values.mode, scopes: values.scopes, expiresAtUtc,
      });
      if (!result.success) {
        void message.error(result.message);
        return;
      }
      setCreating(false);
      setInstruction(buildInstruction(result.data.secret));
      refresh();
      void message.success(text('keyCreated'));
    } finally {
      setSaving(false);
    }
  }

  function confirmKeyChange(key: McpKey, action: 'revoke' | 'delete') {
    modal.confirm({
      title: text(action),
      content: text(`${action}Confirm`, { name: key.name }),
      okText: text(action),
      cancelText: text('cancel'),
      okButtonProps: { danger: true },
      onOk: async () => {
        const result = await (action === 'revoke' ? revokeMcpKey(key.id) : deleteMcpKey(key.id));
        if (!result.success) {
          void message.error(result.message);
          throw new Error(result.code);
        }
        refresh();
        void message.success(text(action === 'revoke' ? 'keyRevoked' : 'keyDeleted'));
      },
    });
  }

  const status = (key: McpKey) => key.revokedAtUtc ? 'revoked'
    : key.expiresAtUtc && Date.parse(key.expiresAtUtc) <= Date.now() ? 'expired' : 'active';
  const columns: TableColumnsType<McpKey> = [
    {
      title: text('name'),
      dataIndex: 'name',
      render: (value: string, key) => (
        <Flex vertical>
          <Typography.Text strong>{value}</Typography.Text>
          <Typography.Text type="secondary" code>{key.prefix}…</Typography.Text>
        </Flex>
      ),
    },
    { title: text('mode'), dataIndex: 'mode', render: (value: McpKeyMode) => text(value) },
    { title: text('scopes'), dataIndex: 'scopes', render: (value: string[]) => value.length },
    { title: text('expiresAt'), dataIndex: 'expiresAtUtc', render: (value: string | null) => value ? formatTime(value) : text('neverExpires') },
    { title: text('createdAt'), dataIndex: 'createdAtUtc', render: formatTime },
    { title: text('status'), render: (_, key) => <Tag color={status(key) === 'active' ? 'green' : 'default'}>{text(status(key))}</Tag> },
    {
      title: text('actions'),
      render: (_, key) => (
        <Flex wrap align="center" gap={4}>
          {status(key) === 'active' && (
            <Button type="link" size="small" disabled={Boolean(copyingId && copyingId !== key.id)} loading={copyingId === key.id} onClick={() => confirmCopy(key)}>
              {text('copy')}
            </Button>
          )}
          {key.revokedAtUtc
            ? <Button type="link" size="small" danger onClick={() => confirmKeyChange(key, 'delete')}>{text('delete')}</Button>
            : <Button type="link" size="small" danger onClick={() => confirmKeyChange(key, 'revoke')}>{text('revoke')}</Button>}
        </Flex>
      ),
    },
  ];

  return (
    <Card
      title={text('keys')}
      extra={(
        <Flex wrap gap={8}>
          <Button icon={<ReloadOutlined />} onClick={refresh} aria-label={text('refresh')} />
          <Button type="primary" icon={<PlusOutlined />} disabled={tools.length === 0} onClick={() => setCreating(true)}>
            {text('createKey')}
          </Button>
        </Flex>
      )}
    >
      {error && <Alert type="error" showIcon title={error} style={{ marginBottom: 12 }} />}
      <Table size="small" rowKey="id" loading={loading} dataSource={keys} columns={columns}
        pagination={{ pageSize: 20, hideOnSinglePage: true }} scroll={{ x: 760 }}
        locale={{ emptyText: text('noKeys') }} />
      <Modal
        title={text('createKey')}
        open={creating}
        destroyOnHidden
        onCancel={() => setCreating(false)}
        onOk={() => form.submit()}
        confirmLoading={saving}
        cancelButtonProps={{ disabled: saving }}
        closable={!saving}
        keyboard={!saving}
        mask={{ closable: !saving }}
        okText={text('create')}
        cancelText={text('cancel')}
      >
        <Form<KeyForm> form={form} layout="vertical" preserve={false} initialValues={{ mode: 'read', scopes: [] }} onFinish={(values) => void createKey(values)}>
          <Form.Item name="name" label={text('name')} rules={[{ required: true, whitespace: true, message: text('nameRequired') }]}>
            <Input maxLength={80} />
          </Form.Item>
          <Form.Item name="mode" label={text('mode')}>
            <Radio.Group onChange={(event) => {
              if (event.target.value === 'read') {
                const readIds = new Set(tools.filter((tool) => !tool.isWrite).map((tool) => tool.id));
                form.setFieldValue('scopes', (form.getFieldValue('scopes') ?? []).filter((id: string) => readIds.has(id)));
              }
            }} options={[{ label: text('read'), value: 'read' }, { label: text('write'), value: 'write' }]} />
          </Form.Item>
          <Form.Item name="expiresAt" label={text('expiresAt')} extra={text('expiryHint')}>
            <DatePicker showTime format="YYYY-MM-DD HH:mm:ss" style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="scopes" label={text('scopes')} rules={[{ type: 'array', required: true, min: 1, message: text('scopeRequired') }]}>
            <ScopeTree tools={tools} mode={mode} />
          </Form.Item>
        </Form>
      </Modal>
      <Modal
        title={text('copy')}
        open={Boolean(instruction)}
        onCancel={() => setInstruction(undefined)}
        onOk={async () => {
          if (instruction && await copyInstruction(instruction)) setInstruction(undefined);
        }}
        okText={text('copy')}
        cancelText={text('close')}
        okButtonProps={{ icon: <CopyOutlined /> }}
        destroyOnHidden
      >
        <Input.TextArea readOnly value={instruction} autoSize={{ minRows: 5, maxRows: 12 }} />
      </Modal>
    </Card>
  );
}
