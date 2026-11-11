import {
  PlusOutlined,
  ReloadOutlined,
  SaveOutlined,
  SendOutlined,
} from '@ant-design/icons';
import { PageContainer } from '@ant-design/pro-components';
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Col,
  Flex,
  Form,
  Input,
  InputNumber,
  message,
  Popconfirm,
  Row,
  Select,
  Skeleton,
  Switch,
  Typography,
} from 'antd';
import { useEffect, useRef, useState } from 'react';
import {
  getSyslogSettings,
  saveSyslogSettings,
  testSyslogTarget,
  type SyslogProtocol,
  type SyslogSettings,
  type SyslogTarget,
  type SyslogTestResult,
} from '@/services/ipban/syslog';
import { useSyslogMessages } from '@/utils/syslog';
import SyslogStatusPanel from './SyslogStatusPanel';

const protocols: SyslogProtocol[] = ['udp', 'tcp', 'tls', 'relp'];
const defaultPorts: Record<SyslogProtocol, number> = {
  udp: 514,
  tcp: 514,
  tls: 6514,
  relp: 2514,
};
const maxTargets = 3;

const newTarget = (): SyslogTarget => ({
  id: '',
  deliveryTargetVersion: '',
  name: '',
  enabled: true,
  host: '',
  port: defaultPorts.tls,
  protocol: 'tls',
  maxSeverity: 7,
  ignoreSslErrors: false,
  framing: 'octet',
});

function normalizeHost(value: string) {
  const host = value.trim();
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

/** 服务器和端口分开校验，避免将 URL、凭据或路径作为主机。 */
function isSyslogHost(value: unknown) {
  if (typeof value !== 'string') return false;
  const host = normalizeHost(value);
  if (!host || host.length > 253 || /[\p{Cc}\s/@?#\\%[\]]/u.test(host))
    return false;
  if (host.includes(':')) {
    try {
      return new URL(`https://[${host}]`).hostname.startsWith('[');
    } catch {
      return false;
    }
  }
  if (/^[0-9.]+$/.test(host)) {
    const octets = host.split('.');
    return (
      octets.length === 4 &&
      octets.every(
        (octet) => /^(0|[1-9][0-9]{0,2})$/.test(octet) && Number(octet) <= 255,
      )
    );
  }
  try {
    const dnsName = new URL(`https://${host}`).hostname.replace(/\.$/, '');
    return dnsName
      .split('.')
      .every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
  } catch {
    return false;
  }
}

export default function SettingsPage() {
  const { intl, text, severityOptions } = useSyslogMessages();
  const [form] = Form.useForm<SyslogSettings>();
  const [messageApi, contextHolder] = message.useMessage();
  const [saved, setSaved] = useState<SyslogSettings>();
  const [loadVersion, setLoadVersion] = useState(0);
  const [loading, setLoading] = useState(true);
  const [loadFailed, setLoadFailed] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string>();
  const [error, setError] = useState<string>();
  const [testResult, setTestResult] = useState<SyslogTestResult>();
  const operation = useRef(false);
  const customPortFields = useRef(new Set<number>());
  // 目标 ID 和投递版本由服务端分配，不需要可编辑表单项。
  const targets = Form.useWatch('targets', { form, preserve: true });
  const busy = loading || saving || testing !== undefined;
  const writable = !busy && !loadFailed && saved !== undefined;

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(undefined);
    setTestResult(undefined);
    void getSyslogSettings(controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      setLoading(false);
      if (
        !result.success ||
        !result.data ||
        !Array.isArray(result.data.targets)
      ) {
        setLoadFailed(true);
        setError(result.message || text('loadFailed'));
        return;
      }
      setLoadFailed(false);
      setSaved(result.data);
      form.setFieldsValue(result.data);
      customPortFields.current.clear();
      setDirty(false);
    });
    return () => controller.abort();
  }, [form, loadVersion]);

  const change = () => {
    setDirty(true);
    setTestResult(undefined);
  };

  const changeProtocol = (
    index: number,
    key: number,
    protocol: SyslogProtocol,
    previous: SyslogProtocol,
  ) => {
    const port = form.getFieldValue(['targets', index, 'port']);
    // 只有沿用旧协议建议端口时才给出新建议，保留用户填写的自定义端口。
    if (!customPortFields.current.has(key) && port === defaultPorts[previous]) {
      form.setFieldValue(['targets', index, 'port'], defaultPorts[protocol]);
    }
    if (protocol !== 'tls')
      form.setFieldValue(['targets', index, 'ignoreSslErrors'], false);
    if (protocol !== 'tcp')
      form.setFieldValue(['targets', index, 'framing'], 'octet');
  };

  const save = async () => {
    if (!writable || !saved || operation.current) return;
    operation.current = true;
    setSaving(true);
    setError(undefined);
    try {
      const valid = await form.validateFields().then(
        () => true,
        () => false,
      );
      if (!valid) return;
      const values: SyslogSettings = form.getFieldsValue(true);
      const normalized = values.targets.map(
        (target): SyslogTarget => ({
          id: target.id,
          deliveryTargetVersion: target.deliveryTargetVersion,
          name: target.name.trim(),
          enabled: target.enabled,
          host: normalizeHost(target.host),
          port: target.port,
          protocol: target.protocol,
          maxSeverity: target.maxSeverity,
          ignoreSslErrors: target.protocol === 'tls' && target.ignoreSslErrors,
          framing: target.protocol === 'tcp' ? target.framing : 'octet',
        }),
      );
      if (values.enabled && !normalized.some((target) => target.enabled)) {
        setError(text('enabledTargetRequired'));
        return;
      }
      const endpoints = new Set(
        normalized.map(
          (target) =>
            `${target.protocol}:${target.host.toLowerCase().replace(/\.$/, '')}:${target.port}`,
        ),
      );
      if (endpoints.size !== normalized.length) {
        setError(text('duplicate'));
        return;
      }
      const result = await saveSyslogSettings({
        enabled: values.enabled,
        configRevision: saved.configRevision,
        targets: normalized,
      });
      if (!result.success || !result.data) {
        setError(result.message);
        return;
      }
      setSaved(result.data);
      form.setFieldsValue(result.data);
      setDirty(false);
      setTestResult(undefined);
      void messageApi.success(text('saved'));
    } finally {
      operation.current = false;
      setSaving(false);
    }
  };

  const test = async (id: string) => {
    if (!writable || !saved || dirty || !id || operation.current) return;
    operation.current = true;
    setTesting(id);
    setError(undefined);
    setTestResult(undefined);
    try {
      const result = await testSyslogTarget(id, saved.configRevision);
      if (!result.success || !result.data) setError(result.message);
      else setTestResult(result.data);
    } finally {
      operation.current = false;
      setTesting(undefined);
    }
  };

  const reload = () => setLoadVersion((value) => value + 1);
  const reloadButton = (
    <Button
      icon={<ReloadOutlined />}
      onClick={dirty ? undefined : reload}
      disabled={busy}
    >
      {text('refresh')}
    </Button>
  );

  return (
    <PageContainer title={intl.formatMessage({ id: 'menu.system.settings' })}>
      {contextHolder}
      <Flex vertical gap={16}>
        {error && <Alert showIcon type="error" title={error} />}
        {testResult && (
          <Alert
            showIcon
            type="success"
            title={text(
              `test.${testResult.stage}`,
              undefined,
              testResult.message,
            )}
            description={text('testId', { id: testResult.testId })}
          />
        )}
        <Card
          title={text('title')}
          extra={
            dirty ? (
              <Popconfirm title={text('discard')} onConfirm={reload}>
                {reloadButton}
              </Popconfirm>
            ) : (
              reloadButton
            )
          }
        >
          {loading && !saved && <Skeleton active />}
          <Form<SyslogSettings>
            form={form}
            layout="vertical"
            disabled={!writable}
            onValuesChange={change}
            style={{ display: saved ? undefined : 'none' }}
          >
            <Form.Item
              name="enabled"
              label={text('enabled')}
              valuePropName="checked"
            >
              <Switch />
            </Form.Item>
            <Form.List name="targets">
              {(fields, { add, remove }) => (
                <Flex vertical gap={12}>
                  {!fields.length && (
                    <Typography.Text type="secondary">
                      {text('empty')}
                    </Typography.Text>
                  )}
                  {fields.map(({ key, name }) => {
                    const target = targets?.[name];
                    const protocol = target?.protocol ?? 'tls';
                    const id = target?.id ?? '';
                    return (
                      <Card
                        key={key}
                        size="small"
                        title={text('target', { index: name + 1 })}
                        extra={
                          <Button
                            type="text"
                            danger
                            onClick={() => {
                              customPortFields.current.delete(key);
                              remove(name);
                              change();
                            }}
                          >
                            {text('remove')}
                          </Button>
                        }
                      >
                        <Row gutter={[16, 0]}>
                          <Col xs={24} md={6}>
                            <Form.Item
                              name={[name, 'name']}
                              label={text('name')}
                              rules={[
                                {
                                  required: true,
                                  whitespace: true,
                                  max: 64,
                                  message: text('nameRequired'),
                                },
                              ]}
                            >
                              <Input maxLength={64} />
                            </Form.Item>
                          </Col>
                          <Col xs={24} md={8}>
                            <Form.Item
                              name={[name, 'host']}
                              label={text('host')}
                              rules={[
                                {
                                  validator: (_, value) =>
                                    isSyslogHost(value)
                                      ? Promise.resolve()
                                      : Promise.reject(
                                          new Error(text('hostInvalid')),
                                        ),
                                },
                              ]}
                            >
                              <Input
                                placeholder={text('hostHint')}
                                maxLength={255}
                              />
                            </Form.Item>
                          </Col>
                          <Col xs={12} md={5}>
                            <Form.Item
                              name={[name, 'protocol']}
                              label={text('protocol')}
                            >
                              <Select
                                options={protocols.map((value) => ({
                                  value,
                                  label: value.toUpperCase(),
                                }))}
                                onChange={(value) =>
                                  changeProtocol(name, key, value, protocol)
                                }
                              />
                            </Form.Item>
                          </Col>
                          <Col xs={12} md={5}>
                            <Form.Item
                              name={[name, 'port']}
                              label={text('port')}
                              rules={[
                                {
                                  type: 'integer',
                                  required: true,
                                  min: 1,
                                  max: 65535,
                                  message: text('portInvalid'),
                                },
                              ]}
                            >
                              <InputNumber
                                min={1}
                                max={65535}
                                style={{ width: '100%' }}
                                onChange={() =>
                                  customPortFields.current.add(key)
                                }
                              />
                            </Form.Item>
                          </Col>
                          <Col xs={12} md={8}>
                            <Form.Item
                              name={[name, 'maxSeverity']}
                              label={text('maxSeverity')}
                            >
                              <Select
                                options={severityOptions.map(
                                  ({ value, label }) => ({
                                    value,
                                    label:
                                      value === 7
                                        ? text('allLevels')
                                        : text('levelLimit', { level: label }),
                                  }),
                                )}
                              />
                            </Form.Item>
                          </Col>
                          {protocol === 'tcp' && (
                            <Col xs={24} md={6}>
                              <Form.Item
                                name={[name, 'framing']}
                                label={text('framing')}
                              >
                                <Select
                                  options={[
                                    { value: 'octet', label: text('octet') },
                                    { value: 'lf', label: text('lf') },
                                  ]}
                                />
                              </Form.Item>
                            </Col>
                          )}
                          <Col xs={24} md={5}>
                            <Form.Item
                              name={[name, 'enabled']}
                              label={text('targetEnabled')}
                              valuePropName="checked"
                            >
                              <Switch />
                            </Form.Item>
                          </Col>
                        </Row>
                        {protocol === 'tls' && (
                          <>
                            <Form.Item
                              name={[name, 'ignoreSslErrors']}
                              valuePropName="checked"
                            >
                              <Checkbox>{text('ignoreSsl')}</Checkbox>
                            </Form.Item>
                            {target?.ignoreSslErrors && (
                              <Alert
                                showIcon
                                type="warning"
                                title={text('ignoreSslWarning')}
                                style={{ marginBottom: 12 }}
                              />
                            )}
                          </>
                        )}
                        <Button
                          icon={<SendOutlined />}
                          loading={testing === id}
                          disabled={dirty || !writable || !id}
                          title={dirty ? text('testHint') : undefined}
                          onClick={() => void test(id)}
                        >
                          {text('test')}
                        </Button>
                      </Card>
                    );
                  })}
                  <Button
                    type="dashed"
                    icon={<PlusOutlined />}
                    disabled={fields.length >= maxTargets || !writable}
                    onClick={() => {
                      add(newTarget());
                      change();
                    }}
                  >
                    {text('add')}
                  </Button>
                </Flex>
              )}
            </Form.List>
            {Boolean(targets?.length) && (
              <Typography.Paragraph type="secondary" style={{ marginTop: 12 }}>
                {text('levelHint')}
              </Typography.Paragraph>
            )}
            <Flex gap={12} align="center" wrap style={{ marginTop: 16 }}>
              <Button
                type="primary"
                icon={<SaveOutlined />}
                loading={saving}
                disabled={!dirty || !writable}
                onClick={() => void save()}
              >
                {text('save')}
              </Button>
              {dirty && (
                <Typography.Text type="secondary">
                  {text('dirty')}
                </Typography.Text>
              )}
            </Flex>
          </Form>
        </Card>
        {saved && <SyslogStatusPanel settings={saved} />}
      </Flex>
    </PageContainer>
  );
}
