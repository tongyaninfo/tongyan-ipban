import { ApiOutlined, PauseCircleOutlined, PlayCircleOutlined, ReloadOutlined } from '@ant-design/icons';
import { PageContainer } from '@ant-design/pro-components';
import { Alert, App, Button, Card, Flex, Skeleton, Tabs, Tag, Typography } from 'antd';
import { useEffect, useState } from 'react';
import {
  getMcpSettings,
  listMcpTools,
  type McpSettings,
  type McpTool,
  updateMcpSettings,
} from '@/services/ipban/mcp';
import McpAudits from './McpAudits';
import { useMcpMessages } from './display';
import McpKeys from './McpKeys';

export default function McpPage() {
  const { text } = useMcpMessages();
  const { message, modal } = App.useApp();
  const [settings, setSettings] = useState<McpSettings>();
  const [tools, setTools] = useState<McpTool[]>([]);
  const [error, setError] = useState<string>();
  const [revision, setRevision] = useState(0);
  const endpoint = typeof window === 'undefined' ? '' : new URL('/mcp', window.location.origin).href;

  useEffect(() => {
    const controller = new AbortController();
    void Promise.all([getMcpSettings(controller.signal), listMcpTools(controller.signal)]).then(
      ([settingsResult, toolsResult]) => {
        if (controller.signal.aborted) return;
        if (settingsResult.success) setSettings(settingsResult.data);
        if (toolsResult.success) setTools(toolsResult.data);
        setError(
          !settingsResult.success
            ? settingsResult.message
            : !toolsResult.success
              ? toolsResult.message
              : undefined,
        );
      },
    );
    return () => controller.abort();
  }, [revision]);

  function toggleService() {
    if (!settings) return;
    const enabled = !settings.enabled;
    modal.confirm({
      title: text(enabled ? 'start' : 'stop'),
      content: text(enabled ? 'startConfirm' : 'stopConfirm'),
      okText: text(enabled ? 'start' : 'stop'),
      cancelText: text('cancel'),
      onOk: async () => {
        const result = await updateMcpSettings({ enabled });
        if (!result.success) {
          void message.error(result.message);
          throw new Error(result.code);
        }
        setSettings(result.data);
        void message.success(text('settingsSaved'));
      },
    });
  }

  return (
    <PageContainer title={text('title')} content={text('description')}>
      {error && (
        <Alert
          type="error"
          showIcon
          title={error}
          action={
            <Button size="small" icon={<ReloadOutlined />} onClick={() => setRevision((value) => value + 1)}>
              {text('refresh')}
            </Button>
          }
        />
      )}
      <Tabs
        style={{ marginTop: 12 }}
        items={[
          {
            key: 'service',
            label: text('title'),
            children: (
              <Flex vertical gap={16}>
                <Card
                  title={<Flex gap={8} align="center"><ApiOutlined />{text('endpoint')}</Flex>}
                  extra={settings && (
                    <Tag color={settings.enabled ? 'green' : 'default'}>
                      {text(settings.enabled ? 'running' : 'stopped')}
                    </Tag>
                  )}
                >
                  {settings ? (
                    <Flex wrap gap={16} align="center" justify="space-between">
                      <Flex vertical gap={4} style={{ minWidth: 0 }}>
                        <Typography.Text code style={{ overflowWrap: 'anywhere' }}>{endpoint}</Typography.Text>
                        <Typography.Text type="secondary">Streamable HTTP</Typography.Text>
                      </Flex>
                      <Button
                        type={settings.enabled ? 'default' : 'primary'}
                        icon={settings.enabled ? <PauseCircleOutlined /> : <PlayCircleOutlined />}
                        onClick={toggleService}
                      >
                        {text(settings.enabled ? 'stop' : 'start')}
                      </Button>
                    </Flex>
                  ) : <Skeleton paragraph={{ rows: 1 }} active={!error} />}
                </Card>
                <McpKeys tools={tools} endpoint={endpoint} />
              </Flex>
            ),
          },
          {
            key: 'audits',
            label: text('audits'),
            children: <McpAudits tools={tools} settings={settings} onSettingsChange={setSettings} />,
          },
        ]}
      />
    </PageContainer>
  );
}
