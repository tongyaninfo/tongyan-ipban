import {
  DeleteOutlined,
  EditOutlined,
  InfoCircleOutlined,
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
  Radio,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Popconfirm,
  message,
} from 'antd';
import { PageContainer } from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { useEffect, useState } from 'react';
import {
  deletePolicy,
  queryPolicies,
  upsertPolicy,
  type BanPolicy,
} from '@/services/ipban/management';

const protocolOptions = [
  { label: 'ALL', value: 'ALL' },
  { label: 'SSH', value: 'Ssh' },
  { label: 'OpenSSH', value: 'OpenSsh' },
  { label: 'RDP', value: 'Rdp' },
  { label: 'WinRM', value: 'WinRm' },
  { label: 'VNC', value: 'Vnc' },
];

const maxPolicyInteger = 2_147_483_647;
// 旧版本曾以 0 表示无限期，读取兼容；新请求统一使用 -1 表示永久封禁。
const isPermanentDuration = (seconds: number, action: string) =>
  seconds === -1 || (seconds === 0 && action === 'Ban');
const numericPolicyFields = {
  INVALID_BAN_POLICY_THRESHOLD: 'threshold',
  INVALID_BAN_POLICY_WINDOW: 'windowSeconds',
  INVALID_BAN_POLICY_OBSERVE: 'observeSeconds',
  INVALID_BAN_POLICY_COOLDOWN: 'cooldownSeconds',
  INVALID_BAN_POLICY_DURATION: 'banDurationSeconds',
} as const;

type NumericPolicyField = (typeof numericPolicyFields)[keyof typeof numericPolicyFields];
type PolicyFormValues = Pick<BanPolicy,
  'name' | 'enabled' | Exclude<NumericPolicyField, 'banDurationSeconds'> | 'action' | 'protocol' | 'description'
> & { durationMode: 'limited' | 'permanent'; banDurationSeconds: string };

export default function PoliciesPage() {
  const intl = useIntl();
  const [data, setData] = useState<BanPolicy[]>([]);
  const [error, setError] = useState<string>();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<BanPolicy>();
  const [savingId, setSavingId] = useState<number>();
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm<PolicyFormValues>();
  const durationMode = Form.useWatch('durationMode', form);
  const durationText = Form.useWatch('banDurationSeconds', form);
  const noBan = durationMode !== 'permanent' && typeof durationText === 'string'
    && /^[0-9]+$/.test(durationText) && Number(durationText) === 0;

  const text = (id: string, fallback: string) =>
    intl.formatMessage({ id, defaultMessage: fallback });

  const numericError = (field: NumericPolicyField) => text(
    `pages.access.policies.validation.${field}`,
    field === 'banDurationSeconds'
      ? 'Enter a whole number from 0 to 2147483647 seconds (0 means no ban), or choose Permanent ban.'
      : `Enter a whole number from ${field === 'observeSeconds' || field === 'cooldownSeconds' ? 0 : 1} to 2147483647.`,
  );
  const numericRules = (field: NumericPolicyField, minimum: number) => [{
    // 不用 InputNumber 的 max/precision 静默改写输入；原值留在字段中供用户修正。
    validator: (_rule: unknown, value: unknown) =>
      typeof value === 'number' && Number.isInteger(value) && value >= minimum && value <= maxPolicyInteger
        ? Promise.resolve()
        : Promise.reject(new Error(numericError(field))),
  }];
  const durationRules = [{
    // 时长按原文本保留，验证后才转数值，避免输入组件在粘贴、失焦时自动修整。
    validator: (_rule: unknown, value: unknown) =>
      typeof value === 'string' && /^[0-9]+$/.test(value)
      && Number(value) >= 0 && Number(value) <= maxPolicyInteger
        ? Promise.resolve()
        : Promise.reject(new Error(numericError('banDurationSeconds'))),
  }];

  const policyError = (code: string, fallback: string) => {
    const field = numericPolicyFields[code as keyof typeof numericPolicyFields];
    if (field) return numericError(field);
    if (code === 'INVALID_BAN_POLICY' || code === 'HTTP_400')
      return text('pages.access.policies.validation.invalid', 'Check the policy fields and try again.');
    if (code === 'NETWORK_ERROR')
      return text('pages.access.policies.error.network', 'Cannot connect to the management API. Check your connection and try again.');
    if (code === 'INVALID_RESPONSE' || code.startsWith('HTTP_'))
      return text('pages.access.policies.error.response', 'The server could not process this request. Please try again.');
    return fallback;
  };

  const load = () =>
    queryPolicies().then((result) => {
      if (result.success) {
        setData(result.data ?? []);
        setError(undefined);
      } else {
        setError(policyError(result.code, result.message));
      }
    });

  useEffect(() => {
    void load();
  }, []);

  const openCreate = () => {
    setEditing(undefined);
    form.resetFields();
    form.setFieldsValue({
      enabled: true,
      threshold: 5,
      windowSeconds: 300,
      observeSeconds: 0,
      cooldownSeconds: 900,
      banDurationSeconds: '1800',
      durationMode: 'limited',
      action: 'Ban',
      protocol: 'ALL',
    });
    setOpen(true);
  };

  const openEdit = (policy: BanPolicy) => {
    setEditing(policy);
    form.resetFields();
    form.setFieldsValue({
      ...policy,
      protocol: policy.protocol || 'ALL',
      durationMode: isPermanentDuration(policy.banDurationSeconds, policy.action) ? 'permanent' : 'limited',
      banDurationSeconds: isPermanentDuration(policy.banDurationSeconds, policy.action) ? '1800' : String(policy.banDurationSeconds),
      // 0 时动作由保存逻辑固定为仅观察；再次选择正时长可恢复正常封禁。
      action: policy.banDurationSeconds === 0 && policy.action === 'Observe' ? 'Ban' : policy.action,
    });
    setOpen(true);
  };

  const save = async () => {
    let values: PolicyFormValues;
    try {
      values = await form.validateFields();
    } catch {
      // 字段校验失败已经由 Form 显示，不抛成未处理 Promise 或网络错误。
      return;
    }
    const payload = {
      name: values.name,
      enabled: values.enabled,
      threshold: values.threshold,
      windowSeconds: values.windowSeconds,
      observeSeconds: values.observeSeconds,
      cooldownSeconds: values.cooldownSeconds,
      banDurationSeconds: values.durationMode === 'permanent' ? -1 : Number(values.banDurationSeconds),
      action: values.durationMode !== 'permanent' && Number(values.banDurationSeconds) === 0 ? 'Observe' : values.action,
      protocol: values.protocol === 'ALL' ? undefined : values.protocol,
      description: values.description,
    };
    setSaving(true);
    const result = await upsertPolicy(payload, editing?.id);
    setSaving(false);
    if (!result.success) {
      const errorMessage = policyError(result.code, result.message);
      const field = numericPolicyFields[result.code as keyof typeof numericPolicyFields];
      if (field) form.setFields([{ name: field, errors: [errorMessage] }]);
      message.error(errorMessage);
      return;
    }
    message.success(text('pages.access.policies.saved', 'Policy saved'));
    setOpen(false);
    setEditing(undefined);
    form.resetFields();
    void load();
  };

  const toggle = async (policy: BanPolicy, enabled: boolean) => {
    setSavingId(policy.id);
    const result = await upsertPolicy(
      {
        name: policy.name,
        enabled,
        threshold: policy.threshold,
        windowSeconds: policy.windowSeconds,
        observeSeconds: policy.observeSeconds,
        cooldownSeconds: policy.cooldownSeconds,
        banDurationSeconds: isPermanentDuration(policy.banDurationSeconds, policy.action) ? -1 : policy.banDurationSeconds,
        action: policy.action,
        protocol: policy.protocol || undefined,
        description: policy.description,
      },
      policy.id,
    );
    setSavingId(undefined);
    if (!result.success) {
      message.error(policyError(result.code, result.message));
      return;
    }
    message.success(
      text(
        enabled
          ? 'pages.access.policies.enabled'
          : 'pages.access.policies.disabled',
        enabled ? 'Policy enabled' : 'Policy disabled',
      ),
    );
    void load();
  };

  const remove = async (policy: BanPolicy) => {
    const result = await deletePolicy(policy.id);
    if (!result.success) {
      message.error(policyError(result.code, result.message));
      return;
    }
    message.success(text('pages.access.policies.deleted', 'Policy deleted'));
    void load();
  };

  const infoTitle = (label: string, help: string) => (
    <Space size={4}>
      <span>{label}</span>
      <Tooltip title={help}>
        <InfoCircleOutlined aria-label={help} />
      </Tooltip>
    </Space>
  );

  const protocolLabel = (value?: string | null) => {
    if (!value) return text('pages.access.policies.protocolAll', 'ALL');
    return protocolOptions.find((item) => item.value === value)?.label || value;
  };

  return (
    <PageContainer
      title={text('pages.access.policies.title', 'Automatic Ban Policies')}
      content={text(
        'pages.access.policies.subtitle',
        'Configure thresholds, observation windows, cooldowns and actions',
      )}
    >
      {error && <Alert showIcon type="warning" message={error} />}
      <Card
        style={{ marginTop: 16 }}
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={() => void load()}>
              {text('pages.common.refresh', 'Refresh')}
            </Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
              {text('pages.access.policies.create', 'New policy')}
            </Button>
          </Space>
        }
      >
        <Table
          rowKey="id"
          dataSource={data}
          columns={[
            {
              title: text('pages.access.policies.name', 'Policy name'),
              dataIndex: 'name',
            },
            {
              title: text('pages.access.policies.status', 'Status'),
              dataIndex: 'enabled',
              render: (value: boolean, record: BanPolicy) => (
                <Space>
                  <Switch
                    checked={value}
                    loading={savingId === record.id}
                    onChange={(checked) => void toggle(record, checked)}
                  />
                  <Tag color={value ? 'green' : 'default'}>
                    {value
                      ? text('pages.access.policies.enabled', 'Enabled')
                      : text('pages.access.policies.disabled', 'Disabled')}
                  </Tag>
                </Space>
              ),
            },
            {
              title: infoTitle(
                text('pages.access.policies.thresholdWindow', 'Threshold / window'),
                text(
                  'pages.access.policies.thresholdWindowHelp',
                  'The number of matching failures and the time window used to count them.',
                ),
              ),
              render: (_: unknown, record: BanPolicy) =>
                `${record.threshold} / ${record.windowSeconds}s`,
            },
            {
              title: infoTitle(
                text('pages.access.policies.observe', 'Observation period'),
                text(
                  'pages.access.policies.observeHelp',
                  'The period during which a triggered event is observed before the action is applied.',
                ),
              ),
              dataIndex: 'observeSeconds',
              render: (value: number) => `${value}s`,
            },
            {
              title: infoTitle(
                text('pages.access.policies.cooldown', 'Cooldown period'),
                text(
                  'pages.access.policies.cooldownHelp',
                  'The quiet period after a trigger during which repeated triggers do not create another ban.',
                ),
              ),
              dataIndex: 'cooldownSeconds',
              render: (value: number) => `${value}s`,
            },
            {
              title: text('pages.access.policies.duration', 'Ban duration'),
              dataIndex: 'banDurationSeconds',
              render: (value: number, record: BanPolicy) => isPermanentDuration(value, record.action)
                ? text('pages.access.policies.permanent', 'Permanent ban')
                : value === 0 ? text('pages.access.policies.noBan', 'No ban') : `${value}s`,
            },
            {
              title: text('pages.access.policies.action', 'Action'),
              dataIndex: 'action',
              render: (value: string) =>
                value === 'Observe'
                  ? text('pages.access.policies.observeOnly', 'Observe only')
                  : text('pages.access.policies.ban', 'Ban'),
            },
            {
              title: text('pages.access.policies.protocol', 'Protocol'),
              dataIndex: 'protocol',
              render: (value?: string) => protocolLabel(value),
            },
            {
              title: text('pages.current.actions', 'Actions'),
              render: (_: unknown, record: BanPolicy) => (
                <Space>
                  <Button type="link" icon={<EditOutlined />} onClick={() => openEdit(record)}>
                    {text('pages.common.edit', 'Edit')}
                  </Button>
                  <Popconfirm title={text('pages.access.policies.deleteConfirm', 'Delete this automatic ban policy?')} onConfirm={() => void remove(record)}>
                    <Button type="link" danger icon={<DeleteOutlined />}>
                      {text('pages.common.delete', 'Delete')}
                    </Button>
                  </Popconfirm>
                </Space>
              ),
            },
          ]}
          pagination={{ pageSize: 20 }}
        />
      </Card>
      <Modal
        title={text(
          editing
            ? 'pages.access.policies.editTitle'
            : 'pages.access.policies.createTitle',
          editing ? 'Edit automatic ban policy' : 'New automatic ban policy',
        )}
        open={open}
        onCancel={() => setOpen(false)}
        onOk={() => void save()}
        confirmLoading={saving}
        destroyOnHidden
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="name"
            label={text('pages.access.policies.name', 'Policy name')}
            rules={[{ required: true }]}
          >
            <Input />
          </Form.Item>
          <Form.Item
            name="enabled"
            label={text('pages.access.policies.enabledLabel', 'Enabled')}
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>
          <Form.Item
            name="threshold"
            label={text('pages.access.policies.threshold', 'Failure threshold')}
            rules={numericRules('threshold', 1)}
          >
            <InputNumber changeOnBlur={false} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            name="windowSeconds"
            label={text('pages.access.policies.window', 'Counting window (seconds)')}
            rules={numericRules('windowSeconds', 1)}
          >
            <InputNumber changeOnBlur={false} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            name="observeSeconds"
            label={text('pages.access.policies.observe', 'Observation period (seconds)')}
            rules={numericRules('observeSeconds', 0)}
          >
            <InputNumber changeOnBlur={false} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            name="cooldownSeconds"
            label={text('pages.access.policies.cooldown', 'Cooldown period (seconds)')}
            rules={numericRules('cooldownSeconds', 0)}
          >
            <InputNumber changeOnBlur={false} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            name="durationMode"
            label={text('pages.access.policies.durationMode', 'Ban expiry')}
            rules={[{ required: true }]}
          >
            <Radio.Group options={[
              { value: 'limited', label: text('pages.access.policies.limited', 'Limited duration') },
              { value: 'permanent', label: text('pages.access.policies.permanent', 'Permanent ban') },
            ]} />
          </Form.Item>
          {durationMode === 'permanent' ? (
            <Alert type="info" showIcon style={{ marginBottom: 24 }}
              title={text('pages.access.policies.permanentHelp', 'Permanent bans do not expire automatically. Release them manually in Ban Decisions. Duration changes apply only to newly triggered bans.')} />
          ) : (
            <Form.Item
              name="banDurationSeconds"
              label={text('pages.access.policies.durationSeconds', 'Ban duration (seconds)')}
              rules={durationRules}
            >
              <Input inputMode="numeric" autoComplete="off" />
            </Form.Item>
          )}
          {noBan ? (
            <Alert type="info" showIcon style={{ marginBottom: 24 }}
              title={text('pages.access.policies.durationZeroHelp', 'A duration of 0 means no ban. This policy will be saved as Observe only.')} />
          ) : <Form.Item
            name="action"
            label={text('pages.access.policies.action', 'Action')}
            rules={[{ required: true }]}
          >
            <Select
              options={[
                { label: text('pages.access.policies.ban', 'Ban'), value: 'Ban' },
                {
                  label: text('pages.access.policies.observeOnly', 'Observe only'),
                  value: 'Observe',
                },
              ]}
            />
          </Form.Item>}
          <Form.Item
            name="protocol"
            label={text('pages.access.policies.protocol', 'Protocol')}
            rules={[{ required: true }]}
          >
            <Select options={protocolOptions} />
          </Form.Item>
          <Form.Item
            name="description"
            label={text('pages.access.policies.description', 'Description')}
          >
            <Input.TextArea rows={3} />
          </Form.Item>
        </Form>
      </Modal>
    </PageContainer>
  );
}
