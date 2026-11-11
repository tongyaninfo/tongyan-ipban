import IpLocationText from '@/components/IpLocationText';
import { PageContainer, ProTable } from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { ReloadOutlined } from '@ant-design/icons';
import { Alert, Button, message, Popconfirm, Space, Tag } from 'antd';
import type { ActionType } from '@ant-design/pro-components';
import type { FC } from 'react';
import { useEffect, useRef } from 'react';
import {
  banAddress,
  disconnectConnection,
  queryConnections,
  type ConnectionSnapshot,
} from '@/services/ipban/system';
import { subscribeManagementRealtime } from '@/services/ipban/realtime';
import {
  displayEndpoint,
  protocolLabel,
  resolveConnectionProtocol,
  tcpStateLabel,
} from '@/utils/currentConnections';

const ConnectionsPage: FC = () => {
  const intl = useIntl();
  const actionRef = useRef<ActionType | undefined>(undefined);
  const text = (id: string, defaultMessage: string) =>
    intl.formatMessage({ id, defaultMessage });

  useEffect(() => {
    let unsubscribe: (() => void) | undefined;
    let disposed = false;
    void subscribeManagementRealtime('connections', () => {
      void actionRef.current?.reload();
    }).then((cleanup) => {
      if (disposed) cleanup();
      else unsubscribe = cleanup;
    });
    return () => {
      disposed = true;
      unsubscribe?.();
    };
  }, []);

  return (
    <PageContainer
      title={text('pages.current.connections.title', '当前网络连接')}
      content={
        <Alert
          type="info"
          showIcon
          message={text(
            'pages.current.connections.description',
            '显示当前 TCP 连接、端点、进程和连接状态。业务协议按端口和进程识别。',
          )}
        />
      }
    >
      <ProTable<ConnectionSnapshot>
        actionRef={actionRef}
        rowKey={(record) =>
          `${record.protocol}-${record.remoteIp}-${record.remotePort ?? 'missing'}-${record.observedAtUtc}`
        }
        search={false}
        options={false}
        scroll={{ x: 1100 }}
        toolBarRender={() => [
          <Button
            key="refresh"
            icon={<ReloadOutlined />}
            onClick={() => actionRef.current?.reload()}
          >
            {text('pages.common.refresh', '刷新')}
          </Button>,
        ]}
        pagination={{ pageSize: 20, showSizeChanger: true }}
        locale={{
          emptyText: text(
            'pages.current.connections.empty',
            '当前没有可显示的连接，或连接采集器尚未接入。',
          ),
        }}
        request={async () => {
          const response = await queryConnections();
          const data = response.data ?? [];
          return {
            data,
            success: response.success,
            total: data.length,
          };
        }}
        columns={[
          {
            title: text('pages.current.protocol', '协议'),
            render: (_, record) =>
              protocolLabel(resolveConnectionProtocol(record), text),
          },
          {
            title: text('pages.current.state', '状态'),
            dataIndex: 'state',
            render: (_, record) => (
              <Tag color="blue" title={record.state}>
                {tcpStateLabel(record.state, text)}
              </Tag>
            ),
          },
          {
            title: text('pages.current.remoteEndpoint', '远端端点'),
            render: (_, record) => <IpLocationText ip={record.remoteIp} port={record.remotePort} endpoint missingLabel={text('pages.current.notProvided', '未提供')} />,
          },
          {
            title: text('pages.current.localEndpoint', '本地端点'),
            render: (_, record) =>
              displayEndpoint(
                record.localIp,
                record.localPort,
                text('pages.current.notCollected', '未采集'),
              ),
          },
          {
            title: text('pages.current.process', '本地进程'),
            render: (_, record) =>
              record.processName ||
              text('pages.current.processNotCollected', '进程信息未采集'),
          },
          {
            title: text('pages.current.observedAt', '观测时间'),
            dataIndex: 'observedAtUtc',
            valueType: 'dateTime',
          },
          {
            title: text('pages.current.actions', '操作'),
            valueType: 'option',
            fixed: 'right',
            width: 130,
            render: (_, record) => (
              <Space size="small">
                <Popconfirm
                  title={text('pages.current.ban.title', '封禁此远端 IP？')}
                  description={text(
                    'pages.current.ban.description',
                    '将写入防火墙并处理匹配的已有连接。',
                  )}
                  okText={text('pages.current.ban.confirm', '封禁')}
                  cancelText={text('pages.current.ban.cancel', '取消')}
                  onConfirm={async () => {
                    const response = await banAddress(record.remoteIp);
                    if (response.success) {
                      message.success(
                        text(
                          'pages.current.ban.success',
                          '封禁已生效，匹配连接已处理。',
                        ),
                      );
                      actionRef.current?.reload();
                    } else {
                      message.error(response.message);
                    }
                  }}
                >
                  <Button danger type="link">
                    {text('pages.current.ban.action', '封禁')}
                  </Button>
                </Popconfirm>
                <Popconfirm
                  title={text('pages.current.disconnect.title', '下线此连接？')}
                  description={text(
                    'pages.current.disconnect.description',
                    '只断开当前连接，不修改防火墙规则。',
                  )}
                  okText={text('pages.current.disconnect.confirm', '下线')}
                  cancelText={text('pages.current.ban.cancel', '取消')}
                  onConfirm={async () => {
                    const response = await disconnectConnection(record);
                    if (response.success) {
                      message.success(
                        text(
                          'pages.current.disconnect.success',
                          '连接已下线。',
                        ),
                      );
                      actionRef.current?.reload();
                    } else {
                      message.error(response.message);
                    }
                  }}
                >
                  <Button type="link">
                    {text('pages.current.disconnect.action', '下线')}
                  </Button>
                </Popconfirm>
              </Space>
            ),
          },
        ]}
      />
    </PageContainer>
  );
};

export default ConnectionsPage;
