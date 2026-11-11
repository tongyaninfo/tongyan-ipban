import { ReloadOutlined, SaveOutlined } from '@ant-design/icons';
import { PageContainer } from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { Alert, Button, Card, Form, Input, InputNumber, Select, Space, Switch, Typography, message } from 'antd';
import { useEffect, useState } from 'react';
import { defaultIpLocationSettings, ipLocationDatabases, queryIpLocationSettings, updateIpLocationSettings, type IpLocationSettings } from '@/services/ipban/ipLocation';
import { ipLocationStore } from '@/services/ipban/ipLocationStore';

/** 地址只填主机名或 IP，协议、端口独立配置，拒绝 URL 路径和凭据。 */
export function isIpLocationHost(value: string) {
  const host = value?.trim();
  if (!host || /[\s/@?#\\]/.test(host)) return false;
  try {
    const authority = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
    const url = new URL(`http://${authority}`);
    return Boolean(url.hostname) && !url.port && url.pathname === '/' && !url.username && !url.password;
  } catch { return false; }
}

export default function IpDatabasePage() {
  const intl = useIntl();
  const text = (key: string) => intl.formatMessage({ id: `pages.ipLocation.${key}` });
  const [form] = Form.useForm<IpLocationSettings>();
  const [messageApi, contextHolder] = message.useMessage();
  const [loading, setLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string>();
  const [revision, setRevision] = useState(0);
  const values = Form.useWatch([], form) as IpLocationSettings | undefined;
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(undefined);
    void queryIpLocationSettings(controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      setLoading(false);
      setLoaded(result.success);
      if (result.success) form.setFieldsValue(result.data);
      else setError(result.message);
    });
    return () => controller.abort();
  }, [revision]);

  const save = async (settings: IpLocationSettings) => {
    if (saving || !loaded) return;
    setSaving(true);
    setError(undefined);
    try {
      const result = await updateIpLocationSettings({ ...settings, host: settings.host.trim() });
      if (!result.success) { setError(result.message); return; }
      form.setFieldsValue(result.data);
      ipLocationStore.invalidate(result.data);
      void messageApi.success(text('saved'));
    } finally { setSaving(false); }
  };
  const previewHost = values?.host?.includes(':') && !values.host.startsWith('[') ? `[${values.host}]` : values?.host;
  return <PageContainer title={text('title')} content={text('description')}>
    {contextHolder}
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      <Typography.Paragraph style={{ marginBottom: 0 }}>
        <Typography.Text strong>{text('provider')}</Typography.Text>
        {' · '}{text('source')}：<Typography.Link href="https://ip.tongyaninfo.com/" target="_blank" rel="noopener noreferrer">ip.tongyaninfo.com</Typography.Link>
      </Typography.Paragraph>
      <Alert showIcon type="info" title={text('hint')} description={text('privacy')} />
      {error && <Alert showIcon type="error" title={error} />}
      <Card loading={loading} extra={<Button icon={<ReloadOutlined />} disabled={saving || loading} onClick={() => setRevision((value) => value + 1)}>{text('refresh')}</Button>}>
        <Form<IpLocationSettings> form={form} layout="vertical" initialValues={defaultIpLocationSettings} onFinish={save} disabled={saving || !loaded} style={{ maxWidth: 680 }}>
          <Form.Item name="enabled" label={text('enabled')} valuePropName="checked" extra={text('enabledHint')}><Switch /></Form.Item>
          <Form.Item name="protocol" label={text('protocol')} rules={[{ required: true, message: text('required') }]}><Select options={[{ value: 'https', label: 'HTTPS' }, { value: 'http', label: 'HTTP' }]} /></Form.Item>
          <Form.Item name="host" label={text('host')} extra={text('hostHint')} rules={[{ validator: (_, value) => isIpLocationHost(value) ? Promise.resolve() : Promise.reject(new Error(text('invalidHost'))) }]}><Input autoComplete="off" placeholder="ip.tongyaninfo.com" maxLength={253} /></Form.Item>
          <Form.Item name="port" label={text('port')} rules={[{ required: true, type: 'integer', min: 1, max: 65535, message: text('invalidPort') }]}><InputNumber min={1} max={65535} precision={0} style={{ width: '100%' }} /></Form.Item>
          <Form.Item name="database" label={text('database')} rules={[{ required: true, message: text('required') }]}><Select options={ipLocationDatabases.map((database) => ({ label: database, value: database }))} /></Form.Item>
          <Form.Item name="timeoutSeconds" label={text('timeout')} rules={[{ required: true, type: 'number', min: 0.1, max: 30, message: text('invalidTimeout') }]}><InputNumber min={0.1} max={30} step={0.1} style={{ width: '100%' }} /></Form.Item>
          <Typography.Paragraph type="secondary" style={{ overflowWrap: 'anywhere' }}>{text('endpoint')}: {values?.protocol ?? 'https'}://{previewHost ?? 'ip.tongyaninfo.com'}:{values?.port ?? 443}/</Typography.Paragraph>
          <Button htmlType="submit" type="primary" icon={<SaveOutlined />} loading={saving} disabled={!loaded}>{text('save')}</Button>
        </Form>
      </Card>
    </Space>
  </PageContainer>;
}
