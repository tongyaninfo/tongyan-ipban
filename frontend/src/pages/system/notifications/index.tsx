import { EyeOutlined, ReloadOutlined, SaveOutlined, SendOutlined } from '@ant-design/icons';
import { PageContainer } from '@ant-design/pro-components';
import { Alert, Button, Card, Checkbox, Flex, Form, Input, InputNumber, Modal, Popconfirm, Select, Skeleton, Switch, Tabs, Typography, message } from 'antd';
import { useEffect, useRef, useState } from 'react';
import { defaultNotificationSettings, getNotificationSettings, previewNotification, sendTestNotification, updateNotificationSettings, type NotificationEventType, type NotificationPreview, type NotificationSettings } from '@/services/ipban/notifications';
import MailContent from './MailContent';
import MailRecords from './MailRecords';
import { useNotificationMessages } from './display';

type SettingsForm = NotificationSettings & { credential?: string; useTls: boolean };
const fullWidth = { width: '100%' };

/** SMTP 主机和端口独立配置，不能把 URL、凭据或路径交给连接层。 */
export function isNotificationHost(value: string) {
  const host = value?.trim();
  if (!host || /[\s/@?#\\%]/.test(host)) return false;
  try {
    const authority = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
    const url = new URL(`https://${authority}`);
    return Boolean(url.hostname) && !url.port && url.pathname === '/' && !url.username && !url.password;
  } catch { return false; }
}

export function isNotificationEmail(value: string) {
  return typeof value === 'string' && value.length <= 254 && /^[^\s<>@]+@[^\s<>@]+$/.test(value);
}

function TemplatePreview({ eventType, onClose }: { eventType?: NotificationEventType; onClose: () => void }) {
  const { text } = useNotificationMessages();
  const [preview, setPreview] = useState<NotificationPreview>();
  const [error, setError] = useState<string>();
  useEffect(() => {
    if (!eventType) return;
    const controller = new AbortController();
    setPreview(undefined);
    setError(undefined);
    void previewNotification(eventType, controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      if (result.success) setPreview(result.data);
      else setError(result.message);
    });
    return () => controller.abort();
  }, [eventType]);
  return <Modal open={Boolean(eventType)} title={text('previewTitle')} width={900} footer={null} onCancel={onClose} destroyOnHidden>
    {error ? <Alert showIcon type="error" title={error} /> : preview ? <Flex vertical gap={12}>
      <Alert showIcon type="info" title={text('previewHint')} />
      <Typography.Text strong>{preview.subject}</Typography.Text>
      <MailContent html={preview.htmlBody} plainText={preview.textBody} title={text('previewTitle')} />
    </Flex> : <Skeleton active />}
  </Modal>;
}

export default function NotificationsPage() {
  const { text } = useNotificationMessages();
  const [form] = Form.useForm<SettingsForm>();
  const [messageApi, contextHolder] = message.useMessage();
  const [settings, setSettings] = useState<NotificationSettings>();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState<string>();
  const [testError, setTestError] = useState<string>();
  const [revision, setRevision] = useState(0);
  const [recordsRevision, setRecordsRevision] = useState(0);
  const [testRecipient, setTestRecipient] = useState('');
  const [dirty, setDirty] = useState(false);
  const [previewType, setPreviewType] = useState<NotificationEventType>();
  const saveLock = useRef(false);
  const testLock = useRef(false);
  const enabled = Form.useWatch('enabled', form);
  const useTls = Form.useWatch('useTls', form);
  const maxPerMinute = Form.useWatch('maxPerMinute', form);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setSettings(undefined);
    setError(undefined);
    void getNotificationSettings(controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      setLoading(false);
      if (result.success) {
        setSettings(result.data);
        form.setFieldsValue({ ...result.data, credential: '', useTls: result.data.security !== 'none' });
        setDirty(false);
      } else setError(result.message);
    });
    return () => controller.abort();
  }, [revision]);

  const save = async () => {
    if (!settings || saveLock.current) return;
    let values: SettingsForm;
    try { values = await form.validateFields(); } catch { return; }
    saveLock.current = true;
    setSaving(true);
    setError(undefined);
    try {
      const { credential, useTls: encrypted, ...updated } = values;
      const result = await updateNotificationSettings({
        ...settings, ...updated,
        security: encrypted ? updated.security === 'none' ? 'ssl' : updated.security : 'none',
        host: updated.host.trim(), fromAddress: updated.fromAddress.trim(),
        username: updated.username.trim() || updated.fromAddress.trim(),
        fromName: updated.fromName.trim(), recipients: updated.recipients.map((value) => value.trim()),
        revision: settings.revision,
      }, credential);
      if (!result.success) { setError(result.message); return; }
      setSettings(result.data);
      form.setFieldsValue({ ...result.data, credential: '', useTls: result.data.security !== 'none' });
      setDirty(false);
      setRecordsRevision((value) => value + 1);
      void messageApi.success(text('saved'));
    } finally {
      saveLock.current = false;
      setSaving(false);
    }
  };

  const sendTest = async () => {
    if (!settings || testLock.current || dirty) return;
    const recipient = testRecipient.trim();
    if (!isNotificationEmail(recipient)) { setTestError(text('invalidEmail')); return; }
    testLock.current = true;
    setTesting(true);
    setTestError(undefined);
    try {
      const result = await sendTestNotification(recipient);
      if (!result.success) { setTestError(result.message); return; }
      setRecordsRevision((value) => value + 1);
      void messageApi.success(text('testQueued'));
    } finally { testLock.current = false; setTesting(false); }
  };
  const clearCredential = async () => {
    // 清除只作用于已保存且停用的配置；待保存草稿不能夹带在凭据操作中提交。
    if (!settings?.hasCredential || settings.enabled || dirty || saveLock.current || testLock.current) return;
    saveLock.current = true;
    setSaving(true);
    setError(undefined);
    try {
      const result = await updateNotificationSettings(settings, undefined, true);
      if (!result.success) { setError(result.message); return; }
      setSettings(result.data);
      form.setFieldsValue({ ...result.data, credential: '', useTls: result.data.security !== 'none' });
      setDirty(false);
      setRecordsRevision((value) => value + 1);
      void messageApi.success(text('credentialCleared'));
    } finally { saveLock.current = false; setSaving(false); }
  };
  const required = { required: Boolean(enabled), message: text('required') };
  const integerRange = (min: number, max: number) => [{ required: true, type: 'integer' as const, min, max, message: text('integerRange', { min, max }) }];
  const saveButton = <Button type="primary" icon={<SaveOutlined />} loading={saving} disabled={!settings || loading || testing} onClick={() => void save()}>{text('save')}</Button>;
  const canTest = Boolean(settings?.host && settings.fromAddress && settings.hasCredential);
  const canClearCredential = Boolean(settings?.hasCredential && !settings.enabled && !dirty && !saving && !testing && !loading);

  return <PageContainer title={text('title')} content={text('description')}>
    {contextHolder}
    <Flex vertical gap={16}>
      {error && <Alert type="error" showIcon title={error} action={<Button size="small" disabled={saving} onClick={() => setRevision((value) => value + 1)}>{text('refresh')}</Button>} />}
      {/* 两个配置页签共用一个表单，切换页签不会丢失未保存的字段或拼出旧版本配置。 */}
      <Form<SettingsForm> form={form} component={false} layout="vertical" initialValues={{ ...defaultNotificationSettings, credential: '', useTls: true }}
        disabled={!settings || saving || loading} onValuesChange={() => setDirty(true)}>
        <Tabs items={[
          { key: 'configuration', label: text('mailService'), forceRender: true, children: <Flex vertical gap={16}>
            <Card loading={loading} extra={<Button icon={<ReloadOutlined />} disabled={saving || testing} onClick={() => setRevision((value) => value + 1)}>{text('refresh')}</Button>}>
              <div style={{ maxWidth: 760 }}>
                <Form.Item name="enabled" label={text('enabled')} valuePropName="checked" extra={text('disableHint')}><Switch /></Form.Item>
                <Flex wrap gap={16}>
                  <Form.Item name="host" label={text('host')} extra={text('hostHint')} style={{ flex: '1 1 320px' }} rules={[required, { validator: (_, value) => !value || isNotificationHost(value) ? Promise.resolve() : Promise.reject(new Error(text('invalidHost'))) }]}><Input autoComplete="off" maxLength={253} placeholder="smtp.example.com" /></Form.Item>
                  <Form.Item name="port" label={text('port')} style={{ flex: '0 1 160px' }} rules={[{ required: true, type: 'integer', min: 1, max: 65535, message: text('invalidPort') }]}><InputNumber min={1} max={65535} precision={0} style={fullWidth} /></Form.Item>
                </Flex>
                <Form.Item name="useTls" valuePropName="checked"><Checkbox onChange={(event) => {
                  if (!event.target.checked) form.setFieldValue('security', 'none');
                  else if (form.getFieldValue('security') === 'none') form.setFieldValue('security', 'ssl');
                }}>{text('ssl')}</Checkbox></Form.Item>
                <Form.Item name="security" label={text('sslMode')}><Select disabled={!settings || saving || !useTls} options={[
                  { value: 'ssl', label: text('sslOnConnect') }, { value: 'starttls', label: text('startTls') },
                  ...(!useTls ? [{ value: 'none', label: text('unencrypted') }] : []),
                ]} /></Form.Item>
                {!useTls && <Alert type="warning" showIcon title={text('noTls')} style={{ marginBottom: 20 }} />}
                <Form.Item name="fromAddress" label={text('fromAddress')} rules={[required, { validator: (_, value) => !value || isNotificationEmail(value.trim()) ? Promise.resolve() : Promise.reject(new Error(text('invalidEmail'))) }]}><Input autoComplete="off" maxLength={254} placeholder="ipban@example.com" onBlur={() => {
                  if (!form.getFieldValue('username')) form.setFieldValue('username', form.getFieldValue('fromAddress')?.trim() ?? '');
                }} /></Form.Item>
                <Form.Item name="fromName" label={text('fromName')} rules={[{ max: 80 }]}><Input maxLength={80} /></Form.Item>
                <Form.Item name="username" label={text('username')} extra={text('usernameHint')}><Input autoComplete="off" maxLength={254} /></Form.Item>
                <Form.Item name="credential" label={text('credential')} extra={text(settings?.hasCredential ? 'credentialSaved' : 'credentialMissing')} rules={[{ required: Boolean(enabled && !settings?.hasCredential), message: text('required') }]}><Input.Password autoComplete="new-password" maxLength={4096} /></Form.Item>
                {settings?.hasCredential && <Flex wrap align="center" gap={12} style={{ marginBottom: 24 }}>
                  <Popconfirm title={text('clearCredentialTitle')} description={text('clearCredentialConfirm')} onConfirm={clearCredential}
                    disabled={!canClearCredential} okText={text('confirmClear')} cancelText={text('cancel')} okButtonProps={{ danger: true }}>
                    <Button danger disabled={!canClearCredential}>{text('clearCredential')}</Button>
                  </Popconfirm>
                  <Typography.Text type="secondary">{text('clearCredentialHint')}</Typography.Text>
                </Flex>}
                <Form.Item name="recipients" label={text('recipients')} extra={text('recipientsHint')} rules={[{ validator: (_, values: string[]) => ((!enabled && !values?.length) || (values?.length > 0 && values.length <= 10 && values.every((value) => isNotificationEmail(value.trim())))) ? Promise.resolve() : Promise.reject(new Error(text('invalidRecipients'))) }]}><Select mode="tags" tokenSeparators={[',', ';']} maxCount={10} open={false} style={fullWidth} /></Form.Item>
                {saveButton}
              </div>
            </Card>
            <Card title={text('testTitle')}>
              <Flex vertical gap={12} style={{ maxWidth: 760 }}>
                <Typography.Paragraph style={{ marginBottom: 0 }} type="secondary">{text('testHint')}</Typography.Paragraph>
                {dirty && <Alert type="info" showIcon title={text('saveBeforeTest')} />}
                {testError && <Alert type="error" showIcon title={testError} />}
                <label htmlFor="notification-test-recipient">{text('testRecipient')}</label>
                <Flex wrap gap={12}>
                  <Input id="notification-test-recipient" value={testRecipient} onChange={(event) => setTestRecipient(event.target.value)} disabled={!settings || testing || saving} placeholder="admin@example.com" maxLength={254} style={{ flex: '1 1 260px' }} />
                  <Button icon={<SendOutlined />} loading={testing} disabled={!canTest || dirty || saving || loading} onClick={() => void sendTest()}>{text('testAction')}</Button>
                </Flex>
              </Flex>
            </Card>
          </Flex> },
          { key: 'rules', label: text('rules'), forceRender: true, children: <Flex vertical gap={16}>
            <Alert type="info" showIcon title={text('ruleHint')} description={text('loginScope')} />
            {(settings?.rules ?? defaultNotificationSettings.rules).map((rule, index) => <Card key={rule.eventType} size="small" title={text(`event.${rule.eventType}`)}
              extra={<Button size="small" icon={<EyeOutlined />} onClick={() => setPreviewType(rule.eventType)}>{text('preview')}</Button>}>
              <Form.Item name={['rules', index, 'eventType']} hidden><Input /></Form.Item>
              <Flex wrap gap={24} align="start">
                <Form.Item name={['rules', index, 'enabled']} valuePropName="checked" label={text('ruleEnabled')}><Switch aria-label={`${text(`event.${rule.eventType}`)} ${text('ruleEnabled')}`} /></Form.Item>
                <Form.Item name={['rules', index, 'intervalSeconds']} label={text('cooldown')} rules={integerRange(10, 86400)} style={{ flex: '0 1 320px' }}><InputNumber min={10} max={86400} precision={0} style={fullWidth} /></Form.Item>
              </Flex>
            </Card>)}
            <Card title={text('globalLimits')}>
              <Flex wrap gap={16}>
                <Form.Item name="maxPerMinute" label={text('maxPerMinute')} rules={integerRange(1, 120)} style={{ flex: '1 1 230px' }}><InputNumber min={1} max={120} precision={0} style={fullWidth} /></Form.Item>
                <Form.Item name="maxPerHour" label={text('maxPerHour')} dependencies={['maxPerMinute']} rules={[...integerRange(1, 10000), { validator: (_, value) => value >= maxPerMinute ? Promise.resolve() : Promise.reject(new Error(text('hourBelowMinute'))) }]} style={{ flex: '1 1 230px' }}><InputNumber min={1} max={10000} precision={0} style={fullWidth} /></Form.Item>
                <Form.Item name="retryCount" label={text('retryCount')} rules={integerRange(0, 5)} style={{ flex: '1 1 230px' }}><InputNumber min={0} max={5} precision={0} style={fullWidth} /></Form.Item>
              </Flex>
              <Flex wrap gap={16}>
                <Form.Item name="queueLifetimeHours" label={text('queueLifetimeHours')} rules={integerRange(1, 168)} style={{ flex: '1 1 230px' }}><InputNumber min={1} max={168} precision={0} style={fullWidth} /></Form.Item>
                <Form.Item name="retentionDays" label={text('retentionDays')} rules={integerRange(1, 365)} style={{ flex: '1 1 230px' }}><InputNumber min={1} max={365} precision={0} style={fullWidth} /></Form.Item>
              </Flex>
              {saveButton}
            </Card>
          </Flex> },
          { key: 'records', label: text('records'), children: <MailRecords revision={recordsRevision} /> },
        ]} />
      </Form>
    </Flex>
    <TemplatePreview eventType={previewType} onClose={() => setPreviewType(undefined)} />
  </PageContainer>;
}
