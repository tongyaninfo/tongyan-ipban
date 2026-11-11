import { Card, Empty } from 'antd';
import { PageContainer } from '@ant-design/pro-components';
import type { ReactNode } from 'react';

type Props = { title: string; description: string; children?: ReactNode };
export default function BusinessPage({ title, description, children }: Props) {
  return <PageContainer title={title} content={description}><Card>{children ?? <Empty description="暂无数据" />}</Card></PageContainer>;
}
