import {
  DeleteOutlined,
  DownloadOutlined,
  ReloadOutlined,
  SearchOutlined,
} from '@ant-design/icons';
import {
  Alert,
  Button,
  Card,
  Col,
  Flex,
  Input,
  message,
  Popconfirm,
  Row,
  Segmented,
  Select,
  Space,
  Statistic,
  Table,
  Tag,
  Typography,
  type TableProps,
} from 'antd';
import { PageContainer } from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import { useEffect, useMemo, useRef, useState } from 'react';
import {
  deleteLogFile,
  queryLogFiles,
  queryLogs,
  type LogFileInfo,
} from '@/services/ipban/management';
import type { SyslogSeverity } from '@/services/ipban/syslog';
import { useSyslogMessages } from '@/utils/syslog';

const formatBytes = (value: number) => {
  if (!value) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const index = Math.min(
    Math.floor(Math.log(value) / Math.log(1024)),
    units.length - 1,
  );
  return `${(value / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`;
};
const formatDate = (value?: string) =>
  value ? new Date(value).toLocaleString() : '-';

type LogRow = {
  index: number;
  message: string;
  appName?: string;
  severity?: SyslogSeverity;
  timestampUtc?: string;
};
type LogFilters = { severity?: SyslogSeverity; appName?: string };

const syslogApplications = [
  'login',
  'collector',
  'ban',
  'unban',
  'firewall',
  'policy',
  'session',
  'admin',
  'audit',
  'http',
  'ipc',
  'mcp',
  'mail',
  'geoip',
  'storage',
  'backup',
  'cert',
  'runtime',
  'logging',
  'syslog',
  'other',
].map((name) => `ipban-${name}`);

function parseLogLine(raw: string, index: number): LogRow {
  try {
    const entry: unknown = JSON.parse(raw);
    if (!entry || typeof entry !== 'object') return { index, message: raw };
    const fields = entry as Record<string, unknown>;
    const severity = fields.syslogSeverity;
    return {
      index,
      message: typeof fields.message === 'string' ? fields.message : raw,
      appName: typeof fields.appName === 'string' ? fields.appName : undefined,
      timestampUtc:
        typeof fields.timestampUtc === 'string'
          ? fields.timestampUtc
          : undefined,
      severity:
        typeof severity === 'number' &&
        Number.isInteger(severity) &&
        severity >= 0 &&
        severity <= 7
          ? (severity as SyslogSeverity)
          : undefined,
    };
  } catch {
    // 旧归档或未完整写入的行仍可原样显示。
    return { index, message: raw };
  }
}

export default function SystemLogsPage() {
  const intl = useIntl();
  const {
    text: syslogText,
    severityLabel,
    severityOptions,
  } = useSyslogMessages();
  const text = (id: string, defaultMessage: string) =>
    intl.formatMessage({ id, defaultMessage });
  const [files, setFiles] = useState<LogFileInfo[]>([]);
  const [selectedFile, setSelectedFile] = useState<string>();
  const [keyword, setKeyword] = useState('');
  const [lines, setLines] = useState<string[]>([]);
  const [view, setView] = useState<'raw' | 'structured'>('raw');
  const [filters, setFilters] = useState<LogFilters>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>();
  const [deletingFile, setDeletingFile] = useState<string>();
  const deletingRef = useRef(false);
  const loadVersion = useRef(0);
  // 显式传入 undefined 代表查询全部，删除当前文件后不能回退到旧筛选。
  const load = async (
    fileName: string | undefined,
    search: string,
    currentFilters = filters,
  ) => {
    const version = ++loadVersion.current;
    setLoading(true);
    setError(undefined);
    const [fileResult, logResult] = await Promise.all([
      queryLogFiles(),
      currentFilters.severity !== undefined || currentFilters.appName
        ? queryLogs(fileName, search, undefined, currentFilters)
        : queryLogs(fileName, search),
    ]);
    if (version !== loadVersion.current) return;
    if (fileResult.success) setFiles(fileResult.data ?? []);
    else setError(fileResult.message);
    if (logResult.success) setLines(logResult.data ?? []);
    else setError(logResult.message);
    setLoading(false);
  };
  useEffect(() => {
    void load(undefined, '');
  }, []);
  const deleteError = (code: string) => {
    const codes: Record<string, string> = {
      NETWORK_ERROR: 'networkError',
      AUTH_REQUIRED: 'authRequired',
      HTTP_401: 'authRequired',
      LOG_FILE_NOT_FOUND: 'notFound',
      HTTP_404: 'notFound',
      LOG_FILE_PROTECTED: 'notAllowed',
      LOG_FILE_INVALID: 'invalidFile',
      LOG_FILE_UNSAFE: 'unsafe',
      LOG_FILE_BUSY: 'busy',
      LOG_DELETE_AUDIT_UNAVAILABLE: 'auditUnavailable',
      LOG_DELETE_AUDIT_FAILED: 'auditFailed',
    };
    return text(
      `pages.system.logs.delete.${codes[code] ?? 'failed'}`,
      '日志文件删除失败，请刷新后重试。',
    );
  };
  const removeFile = async (record: LogFileInfo) => {
    // 以服务端许可为准，并同步锁住重复点击，避免 React 更新前重复提交。
    if (record.canDelete !== true || deletingRef.current) return;
    deletingRef.current = true;
    setDeletingFile(record.name);
    setError(undefined);
    try {
      const result = await deleteLogFile(record.name);
      if (!result.success) {
        setError(deleteError(result.code));
        return;
      }
      const nextSelected =
        selectedFile === record.name ? undefined : selectedFile;
      setSelectedFile(nextSelected);
      setFiles((current) =>
        current.filter((file) => file.name !== record.name),
      );
      if (selectedFile === record.name) setLines([]);
      message.success(
        text('pages.system.logs.delete.success', '日志文件已删除。'),
      );
      await load(nextSelected, keyword);
    } catch {
      setError(deleteError('DELETE_FAILED'));
    } finally {
      deletingRef.current = false;
      setDeletingFile(undefined);
    }
  };
  const totalBytes = useMemo(
    () => files.reduce((sum, item) => sum + item.sizeBytes, 0),
    [files],
  );
  const logRows = useMemo(() => lines.map(parseLogLine), [lines]);
  const applications = useMemo(
    () =>
      Array.from(
        new Set([
          ...syslogApplications,
          ...logRows.flatMap((row) => (row.appName ? [row.appName] : [])),
        ]),
      ).sort(),
    [logRows],
  );
  const changeFilters = (next: LogFilters) => {
    setFilters(next);
    void load(selectedFile, keyword, next);
  };
  const logColumns: TableProps<LogRow>['columns'] = [
    {
      title: syslogText('view.time', undefined, '时间'),
      dataIndex: 'timestampUtc',
      width: 165,
      render: formatDate,
    },
    {
      title: syslogText('severity', undefined, 'Syslog 级别'),
      dataIndex: 'severity',
      width: 120,
      render: (value?: SyslogSeverity) =>
        value === undefined ? (
          '—'
        ) : (
          <Tag color={value <= 3 ? 'red' : value === 4 ? 'orange' : 'default'}>
            {severityLabel(value)}
          </Tag>
        ),
    },
    {
      title: syslogText('appName', undefined, '应用名'),
      dataIndex: 'appName',
      width: 160,
      render: (value?: string) => value || '—',
    },
    {
      title: syslogText('view.message', undefined, '日志'),
      dataIndex: 'message',
      render: (value: string) => (
        <Typography.Text style={{ overflowWrap: 'anywhere' }}>
          {value}
        </Typography.Text>
      ),
    },
  ];
  const columns: TableProps<LogFileInfo>['columns'] = [
    {
      title: text('pages.system.logs.file', '文件'),
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: text('pages.system.logs.size', '大小'),
      dataIndex: 'sizeBytes',
      key: 'sizeBytes',
      render: (value: number) => formatBytes(value),
    },
    {
      title: text('pages.system.logs.lastWrite', '最后写入'),
      dataIndex: 'lastWriteTimeUtc',
      key: 'lastWriteTimeUtc',
      render: formatDate,
    },
    {
      title: text('pages.system.logs.type', '类型'),
      key: 'type',
      render: (_, record) => (
        <Tag
          color={
            record.compressed
              ? 'blue'
              : record.canDelete === true
                ? 'default'
                : 'green'
          }
        >
          {record.compressed
            ? text('pages.system.logs.archive', 'gzip 归档')
            : record.canDelete === true
              ? text('pages.system.logs.rotated', '已轮转日志')
              : text('pages.system.logs.active', '活动日志')}
        </Tag>
      ),
    },
    {
      title: text('pages.system.logs.actions', '操作'),
      key: 'actions',
      width: 100,
      onCell: () => ({ onClick: (event) => event.stopPropagation() }),
      render: (_, record) =>
        record.canDelete === true ? (
          <Popconfirm
            title={text(
              'pages.system.logs.delete.title',
              '永久删除此日志文件？',
            )}
            description={
              <>
                <Typography.Text code style={{ overflowWrap: 'anywhere' }}>
                  {record.name}
                </Typography.Text>
                <p>
                  {text(
                    'pages.system.logs.delete.description',
                    '此操作将永久删除该日志文件，无法撤销。',
                  )}
                </p>
              </>
            }
            okText={text('pages.system.logs.delete.confirm', '永久删除')}
            cancelText={text('pages.system.logs.delete.cancel', '取消')}
            okButtonProps={{
              danger: true,
              loading: deletingFile === record.name,
              disabled: deletingFile !== undefined,
            }}
            cancelButtonProps={{ disabled: deletingFile !== undefined }}
            onPopupClick={(event) => event.stopPropagation()}
            onConfirm={(event) => {
              event?.stopPropagation();
              return removeFile(record);
            }}
          >
            <Button
              danger
              type="link"
              icon={<DeleteOutlined />}
              disabled={deletingFile !== undefined || loading}
              loading={deletingFile === record.name}
              onClick={(event) => event.stopPropagation()}
            >
              {text('pages.common.delete', '删除')}
            </Button>
          </Popconfirm>
        ) : (
          <Button
            danger
            type="link"
            icon={<DeleteOutlined />}
            disabled
            title={text(
              'pages.system.logs.delete.unavailable',
              '活动日志或未获服务端删除许可的文件不可删除。',
            )}
          >
            {text('pages.common.delete', '删除')}
          </Button>
        ),
    },
  ];
  return (
    <PageContainer
      title={text('pages.system.logs.title', '系统日志')}
      content={text(
        'pages.system.logs.description',
        '查询、筛选、轮转、压缩和导出系统日志',
      )}
    >
      <Space direction="vertical" size={16} style={{ display: 'flex' }}>
        {error && <Alert showIcon type="warning" message={error} />}
        <Row gutter={16}>
          <Col xs={24} sm={8}>
            <Card>
              <Statistic
                title={text('pages.system.logs.fileCount', '日志文件数')}
                value={files.length}
              />
            </Card>
          </Col>
          <Col xs={24} sm={8}>
            <Card>
              <Statistic
                title={text('pages.system.logs.totalSize', '日志总大小')}
                value={formatBytes(totalBytes)}
              />
            </Card>
          </Col>
          <Col xs={24} sm={8}>
            <Card>
              <Statistic
                title={text('pages.system.logs.lineCount', '当前显示行数')}
                value={lines.length}
              />
            </Card>
          </Col>
        </Row>
        <Card title={text('pages.system.logs.files', '日志文件')}>
          <Table
            rowKey="name"
            size="small"
            loading={loading}
            columns={columns}
            dataSource={files}
            pagination={{ pageSize: 8 }}
            scroll={{ x: 700 }}
            onRow={(record) => ({
              onClick: () => {
                if (deletingRef.current) return;
                setSelectedFile(record.name);
                void load(record.name, keyword);
              },
            })}
          />
        </Card>
        <Card
          title={text('pages.system.logs.search', '日志检索')}
          extra={
            <Space>
              <Button
                icon={<ReloadOutlined />}
                onClick={() => void load(selectedFile, keyword)}
                loading={loading}
                disabled={deletingFile !== undefined}
              >
                {text('pages.common.refresh', '刷新')}
              </Button>
              <Button
                icon={<DownloadOutlined />}
                href={`/api/admin/v1/logs/export?${new URLSearchParams({
                  ...(selectedFile ? { fileName: selectedFile } : {}),
                  ...(keyword ? { keyword } : {}),
                  ...(filters.severity !== undefined
                    ? { severity: String(filters.severity) }
                    : {}),
                  ...(filters.appName ? { appName: filters.appName } : {}),
                }).toString()}`}
                target="_blank"
              >
                {text('pages.system.logs.export', '导出 NDJSON')}
              </Button>
            </Space>
          }
        >
          <Space.Compact style={{ display: 'flex', marginBottom: 12 }}>
            <Select
              allowClear
              placeholder={text('pages.system.logs.chooseFile', '选择日志文件')}
              style={{ minWidth: 240 }}
              value={selectedFile}
              disabled={deletingFile !== undefined}
              onChange={(value) => setSelectedFile(value)}
              options={files.map((file) => ({
                label: file.name,
                value: file.name,
              }))}
            />
            <Input
              placeholder={text(
                'pages.system.logs.keyword',
                '关键词（级别、事件、IP、异常）',
              )}
              value={keyword}
              disabled={deletingFile !== undefined}
              onChange={(event) => setKeyword(event.target.value)}
              onPressEnter={() => void load(selectedFile, keyword)}
            />
            <Button
              type="primary"
              icon={<SearchOutlined />}
              disabled={deletingFile !== undefined}
              onClick={() => void load(selectedFile, keyword)}
            >
              {text('pages.system.logs.searchAction', '查询')}
            </Button>
          </Space.Compact>
          <Typography.Paragraph type="secondary">
            {text(
              'pages.system.logs.hint',
              '日志按 NDJSON 保存，后台按日期和大小轮转，归档文件使用 gzip 压缩并按保留策略清理。',
            )}
          </Typography.Paragraph>
          <Flex gap={8} align="center" wrap style={{ marginBottom: 12 }}>
            <Segmented
              value={view}
              onChange={setView}
              options={[
                {
                  value: 'raw',
                  label: syslogText('view.raw', undefined, '原始日志'),
                },
                {
                  value: 'structured',
                  label: syslogText('view.structured', undefined, '列表'),
                },
              ]}
            />
            <Select
              allowClear
              aria-label={syslogText('severity', undefined, 'Syslog 级别')}
              placeholder={syslogText('severity', undefined, 'Syslog 级别')}
              style={{ minWidth: 130 }}
              options={severityOptions}
              value={filters.severity}
              disabled={deletingFile !== undefined}
              onChange={(value) =>
                changeFilters({ ...filters, severity: value })
              }
            />
            <Select
              allowClear
              aria-label={syslogText('appName', undefined, '应用名')}
              placeholder={syslogText('appName', undefined, '应用名')}
              style={{ minWidth: 130 }}
              options={applications.map((name) => ({
                label: name,
                value: name,
              }))}
              value={filters.appName}
              disabled={deletingFile !== undefined}
              onChange={(value) =>
                changeFilters({ ...filters, appName: value })
              }
            />
          </Flex>
          {view === 'structured' ? (
            <Table
              rowKey="index"
              columns={logColumns}
              dataSource={logRows}
              loading={loading}
              size="small"
              scroll={{ x: 680 }}
              pagination={{ pageSize: 20 }}
              locale={{
                emptyText: text('pages.system.logs.empty', '暂无匹配日志'),
              }}
            />
          ) : (
            <div
              style={{
                maxHeight: 520,
                overflow: 'auto',
                background: '#111827',
                borderRadius: 6,
                padding: 12,
              }}
            >
              {lines.length ? (
                <pre
                  style={{
                    color: '#d1fae5',
                    whiteSpace: 'pre-wrap',
                    margin: 0,
                    lineHeight: 1.6,
                  }}
                >
                  {lines.join('\n')}
                </pre>
              ) : (
                <Typography.Text type="secondary">
                  {text('pages.system.logs.empty', '暂无匹配日志')}
                </Typography.Text>
              )}
            </div>
          )}
        </Card>
      </Space>
    </PageContainer>
  );
}
