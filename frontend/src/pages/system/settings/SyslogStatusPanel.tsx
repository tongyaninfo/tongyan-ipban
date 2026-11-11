import {
  Alert,
  Card,
  Flex,
  Table,
  Tag,
  Typography,
  type TableProps,
} from 'antd';
import { useEffect, useState } from 'react';
import {
  getSyslogStatus,
  type SyslogProcessStatus,
  type SyslogSettings,
  type SyslogStatus,
  type SyslogTargetStatus,
} from '@/services/ipban/syslog';
import { useSyslogMessages } from '@/utils/syslog';

const number = new Intl.NumberFormat();
const date = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'short',
  timeStyle: 'medium',
  timeZone: 'Asia/Shanghai',
});
const formatDate = (value?: string | null) => {
  const time = value ? Date.parse(value) : Number.NaN;
  return Number.isNaN(time) ? '—' : date.format(time);
};

function ProcessStatus({
  status,
  settings,
  name,
}: {
  status: SyslogProcessStatus;
  settings: SyslogSettings;
  name: string;
}) {
  const { text } = useSyslogMessages();
  const columns: TableProps<SyslogTargetStatus>['columns'] = [
    {
      title: text('name'),
      key: 'name',
      render: (_, row) => {
        const target = settings.targets.find(
          (candidate) =>
            candidate.id === row.targetId &&
            candidate.deliveryTargetVersion === row.deliveryTargetVersion,
        );
        return target?.name || row.targetId;
      },
    },
    {
      title: text('status'),
      key: 'state',
      render: (_, row) => (
        <Tag color={row.state === 'retrying' ? 'orange' : 'default'}>
          {row.state === 'unknown'
            ? text('configuration.unknown')
            : text(`state.${row.state}`, undefined, row.state)}
        </Tag>
      ),
    },
    {
      title: text('queue'),
      key: 'queue',
      render: (_, row) =>
        text('queueValue', {
          count: number.format(row.queuedCount),
          bytes: number.format(row.queuedBytes),
        }),
    },
    {
      title: text('oldest'),
      dataIndex: 'oldestQueuedAtUtc',
      render: formatDate,
    },
    { title: text('sent'), dataIndex: 'lastSentAtUtc', render: formatDate },
    {
      title: text('ack'),
      dataIndex: 'lastAcknowledgedAtUtc',
      render: formatDate,
    },
    {
      title: text('failures'),
      key: 'failures',
      render: (_, row) =>
        `${number.format(row.failedCount)} / ${number.format(row.retryCount)}`,
    },
    {
      title: text('dropped'),
      key: 'dropped',
      render: (_, row) => (
        <Flex vertical>
          <Typography.Text
            type={row.priorityDroppedCount > 0 ? 'danger' : undefined}
          >
            {number.format(row.droppedCount)} /{' '}
            {number.format(row.priorityDroppedCount)}
          </Typography.Text>
          {row.firstPriorityDroppedAtUtc && (
            <Typography.Text type="secondary">
              {formatDate(row.firstPriorityDroppedAtUtc)} –{' '}
              {formatDate(row.lastPriorityDroppedAtUtc)}
            </Typography.Text>
          )}
        </Flex>
      ),
    },
    {
      title: text('truncated'),
      dataIndex: 'truncatedCount',
      render: (value?: number) => number.format(value ?? 0),
    },
    {
      title: text('lastError'),
      dataIndex: 'lastError',
      render: (value) => value || '—',
    },
  ];

  return (
    <section aria-label={name}>
      <Flex gap={8} align="center" wrap style={{ marginBottom: 8 }}>
        <Typography.Text strong>{name}</Typography.Text>
        <Tag
          color={status.configurationState === 'unknown' ? 'orange' : 'default'}
        >
          {text(`configuration.${status.configurationState}`)}
        </Tag>
        <Typography.Text type="secondary">
          {text('appliedRevision')}
        </Typography.Text>
        <Typography.Text code>{status.appliedRevision ?? '—'}</Typography.Text>
        {status.lastError && (
          <Typography.Text type="warning">{status.lastError}</Typography.Text>
        )}
        <Typography.Text
          type={status.priorityDroppedCount > 0 ? 'danger' : 'secondary'}
        >
          {text('processDropped', {
            total: number.format(status.droppedCount),
            priority: number.format(status.priorityDroppedCount),
          })}
        </Typography.Text>
      </Flex>
      <Table
        rowKey={(row) => `${row.targetId}:${row.deliveryTargetVersion}`}
        size="small"
        columns={columns}
        dataSource={status.targets}
        scroll={{ x: 1040 }}
        pagination={false}
        locale={{ emptyText: text('noTargets') }}
      />
    </section>
  );
}

export default function SyslogStatusPanel({
  settings,
}: {
  settings: SyslogSettings;
}) {
  const { text } = useSyslogMessages();
  const [status, setStatus] = useState<SyslogStatus>();
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const load = async () => {
      const result = await getSyslogStatus(controller.signal);
      if (controller.signal.aborted) return;
      setFailed(!result.success || !result.data);
      setStatus(result.success ? result.data : undefined);
      timer = setTimeout(load, 5000);
    };
    void load();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [settings.configRevision]);

  return (
    <Card title={text('status')} loading={!status && !failed}>
      {failed && (
        <Alert showIcon type="warning" title={text('statusUnavailable')} />
      )}
      {status && (
        <Flex vertical gap={16}>
          <Flex gap={8} align="center" wrap>
            <Typography.Text>{text('desiredRevision')}</Typography.Text>
            <Typography.Text code>{status.desiredRevision}</Typography.Text>
          </Flex>
          <ProcessStatus name="API" status={status.api} settings={settings} />
          {status.agent ? (
            <ProcessStatus
              name="Agent"
              status={status.agent}
              settings={settings}
            />
          ) : (
            <Alert
              showIcon
              type="warning"
              title={text('agentUnavailable')}
              description={status.agentErrorCode}
            />
          )}
        </Flex>
      )}
    </Card>
  );
}
