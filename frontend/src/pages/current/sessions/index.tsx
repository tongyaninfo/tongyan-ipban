import IpLocationText from '@/components/IpLocationText';
import {
  PageContainer,
  ProTable,
  type ActionType,
} from '@ant-design/pro-components';
import { ReloadOutlined } from '@ant-design/icons';
import { useIntl } from '@umijs/max';
import { Alert, Button, message, Popconfirm } from 'antd';
import type { FC } from 'react';
import { useEffect, useRef } from 'react';
import {
  disconnectSession,
  querySessions,
  type LoginSession,
} from '@/services/ipban/system';
import { subscribeManagementRealtime } from '@/services/ipban/realtime';
import { displayEndpoint, protocolLabel } from '@/utils/currentConnections';

const availabilityMessage = (
  value:
    | LoginSession['usernameAvailability']
    | LoginSession['processAvailability'],
  text: (id: string, defaultMessage: string) => string,
) => {
  const labels: Record<string, string> = {
    '0': text('pages.current.available', '已采集'),
    '1': text('pages.current.notProvided', '未提供'),
    '2': text('pages.current.notCollected', '未采集'),
    '3': text('pages.current.correlationFailed', '关联失败'),
    '4': text('pages.current.notApplicable', '不适用'),
    available: text('pages.current.available', '已采集'),
    notprovided: text('pages.current.notProvided', '未提供'),
    notcollected: text('pages.current.notCollected', '未采集'),
    correlationfailed: text('pages.current.correlationFailed', '关联失败'),
    notapplicable: text('pages.current.notApplicable', '不适用'),
  };
  return (
    labels[String(value).toLowerCase()] ||
    text('pages.current.notCollected', '未采集')
  );
};

const SessionsPage: FC = () => {
  const intl = useIntl();
  const actionRef = useRef<ActionType | undefined>(undefined);
  const text = (id: string, defaultMessage: string) =>
    intl.formatMessage({ id, defaultMessage });

  useEffect(() => {
    const cleanups: Array<() => void> = [];
    let disposed = false;
    // 新登录记录可能稍后补齐用户名，连接变化和安全事件都需要重新查询会话。
    for (const channel of ['connections', 'security-events'] as const) {
      void subscribeManagementRealtime(channel, () => {
        void actionRef.current?.reload();
      }).then((cleanup) => {
        if (disposed) cleanup();
        else cleanups.push(cleanup);
      });
    }
    return () => {
      disposed = true;
      for (const cleanup of cleanups) cleanup();
    };
  }, []);

  return (
    <PageContainer
      title={text('pages.current.sessions.title', '当前会话')}
      content={
        <Alert
          type="info"
          showIcon
          message={text(
            'pages.current.sessions.description',
            '根据活动连接识别 SSH、RDP、WinRM 和 VNC 会话，匹配成功登录记录后显示用户名。本页可下线。',
          )}
        />
      }
    >
      <ProTable<LoginSession>
        actionRef={actionRef}
        rowKey={(record) => record.sessionId}
        search={false}
        options={false}
        scroll={{ x: 1250 }}
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
            'pages.current.sessions.empty',
            '当前没有可识别的活动会话。',
          ),
        }}
        request={async () => {
          const response = await querySessions();
          return {
            data: response.data ?? [],
            success: response.success,
            total: response.data?.length ?? 0,
          };
        }}
        columns={[
          {
            title: text('pages.current.protocol', '协议'),
            dataIndex: 'protocol',
            render: (value: unknown) =>
              protocolLabel(String(value ?? ''), text),
          },
          {
            title: text('pages.current.sessionId', '会话 ID'),
            dataIndex: 'sessionId',
            ellipsis: true,
            width: 220,
          },
          {
            title: text('pages.current.username', '用户名'),
            render: (_, record) =>
              record.username ||
              availabilityMessage(record.usernameAvailability, text),
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
              availabilityMessage(record.processAvailability, text),
          },
          {
            title: text('pages.current.observedAt', '观测时间'),
            dataIndex: 'lastObservedAtUtc',
            valueType: 'dateTime',
          },
          {
            title: text('pages.current.actions', '操作'),
            valueType: 'option',
            fixed: 'right',
            width: 90,
            render: (_, record) => (
              <Popconfirm
                title={text('pages.current.disconnect.title', '下线此连接？')}
                description={text(
                  'pages.current.disconnect.description',
                  '只断开当前连接，不修改防火墙规则。',
                )}
                okText={text('pages.current.disconnect.confirm', '下线')}
                cancelText={text('pages.current.ban.cancel', '取消')}
                onConfirm={async () => {
                  const response = await disconnectSession(record.sessionId);
                  if (response.success) {
                    message.success(
                      text('pages.current.disconnect.success', '连接已下线。'),
                    );
                    void actionRef.current?.reload();
                  } else {
                    message.error(response.message);
                  }
                }}
              >
                <Button type="link" disabled={!record.canDisconnect}>
                  {text('pages.current.disconnect.action', '下线')}
                </Button>
              </Popconfirm>
            ),
          },
        ]}
      />
    </PageContainer>
  );
};

export default SessionsPage;
