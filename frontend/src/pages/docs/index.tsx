import { Card, Col, Row, Typography } from 'antd';
import { PageContainer } from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';

const sections = ['overview', 'current', 'security', 'access', 'system'] as const;

export default function DocsPage() {
  const intl = useIntl();
  const text = (id: string, fallback: string) => intl.formatMessage({ id, defaultMessage: fallback });
  return <PageContainer title={text('pages.docs.title', '使用文档')} content={text('pages.docs.subtitle', '通研 IPBan 本机管理台使用说明')}>
    <Typography.Paragraph>{text('pages.docs.timezone', '页面中的时间使用浏览器或操作系统本地时区显示，服务端数据统一使用 UTC 保存。')}</Typography.Paragraph>
    <Row gutter={[16, 16]}>{sections.map((key) => <Col xs={24} md={12} key={key}><Card title={text(`pages.docs.${key}.title`, key)}><Typography.Paragraph>{text(`pages.docs.${key}.description`, '')}</Typography.Paragraph></Card></Col>)}</Row>
  </PageContainer>;
}
