import { UploadOutlined } from '@ant-design/icons';
import { Alert, Button, Card, Descriptions, Space, Upload, message } from 'antd';
import { PageContainer } from '@ant-design/pro-components';
import { useEffect, useState } from 'react';
import { useIntl } from '@umijs/max';
import { queryCertificates, uploadCertificate, type CertificateMetadata } from '@/services/ipban/management';

export default function CertificatesPage() {
  const intl = useIntl();
  const text = (id: string, defaultMessage: string) => intl.formatMessage({ id, defaultMessage });
  const [data, setData] = useState<CertificateMetadata[]>([]);
  const [file, setFile] = useState<File>();
  const [error, setError] = useState<string>();
  const load = () => queryCertificates().then((result) => { if (result.success) setData(result.data ?? []); else setError(result.message); });
  useEffect(() => { void load(); }, []);
  const submit = async () => {
    if (!file) { message.warning(text('pages.system.certificates.selectFile', '请选择 PFX 证书文件')); return; }
    const result = await uploadCertificate(file);
    if (!result.success) { message.error(result.message); return; }
    message.success(text('pages.system.certificates.saved', '证书已保存，重启 API 后生效'));
    setFile(undefined);
    void load();
  };
  const current = data.find((item) => item.active) ?? data[0];
  return <PageContainer title={text('pages.system.certificates.title', '证书管理')} content={text('pages.system.certificates.description', '配置本系统 HTTPS 证书，替换后重启服务生效')}>
    {error && <Alert showIcon type="warning" message={error} />}
    <Card style={{ marginTop: 16 }} title={text('pages.system.certificates.current', '当前证书')}>
      {current ? <Descriptions bordered size="small" column={1}>
        <Descriptions.Item label={text('pages.system.certificates.subject', '主题')}>{current.subject}</Descriptions.Item>
        <Descriptions.Item label={text('pages.system.certificates.thumbprint', '指纹')}>{current.thumbprint}</Descriptions.Item>
        <Descriptions.Item label={text('pages.system.certificates.validity', '有效期')}>{new Date(current.notBeforeUtc).toLocaleDateString()} - {new Date(current.notAfterUtc).toLocaleDateString()}</Descriptions.Item>
        <Descriptions.Item label={text('pages.system.certificates.uploadedAt', '配置时间')}>{new Date(current.uploadedAtUtc).toLocaleString()}</Descriptions.Item>
        <Descriptions.Item label={text('pages.system.certificates.status', '状态')}>{text('pages.system.certificates.active', '当前生效')}</Descriptions.Item>
      </Descriptions> : text('pages.system.certificates.empty', '当前使用自动生成的自签名证书。')}
    </Card>
    <Card style={{ marginTop: 16 }} title={text('pages.system.certificates.replace', '替换 HTTPS 证书')} extra={<Space><Upload beforeUpload={(candidate) => { setFile(candidate); return false; }} showUploadList={false} accept=".pfx,.p12"><Button icon={<UploadOutlined />}>{text('pages.system.certificates.choose', '选择 PFX')}</Button></Upload><Button type="primary" onClick={() => void submit()}>{text('pages.system.certificates.upload', '上传并替换')}</Button></Space>}>
      {file ? `${text('pages.system.certificates.pending', '待替换')}: ${file.name}` : text('pages.system.certificates.hint', '上传包含私钥的 PFX/P12 文件，系统只保留当前生效证书。')}
    </Card>
  </PageContainer>;
}
