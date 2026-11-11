import { Tabs, Typography } from 'antd';
import { useNotificationMessages } from './display';

/** 邮件按发送时的快照展示；隔离脚本、表单、弹窗和远程资源，避免查看邮件产生外部请求。 */
export function isolatedMailDocument(html: string) {
  return `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">${html}`;
}

export default function MailContent({ html, plainText, title }: {
  html: string;
  plainText: string;
  title: string;
}) {
  const { text } = useNotificationMessages();
  return <Tabs items={[
    {
      key: 'html', label: text('htmlBody'), children: <iframe
        title={title} sandbox="" referrerPolicy="no-referrer"
        srcDoc={isolatedMailDocument(html)}
        style={{ width: '100%', minHeight: 480, border: '1px solid #d9d9d9', borderRadius: 8, background: '#fff' }}
      />,
    },
    {
      key: 'text', label: text('textBody'), children: <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{plainText || text('emptyBody')}</Typography.Paragraph>,
    },
  ]} />;
}
