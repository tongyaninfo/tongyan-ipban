import {
  HubConnection,
  HubConnectionBuilder,
  HubConnectionState,
  LogLevel,
} from '@microsoft/signalr';

export type ManagementRealtimeChannel = 'overview' | 'connections' | 'security-events';

type ManagementRealtimeMessage = {
  channel?: string;
  atUtc?: string;
};

type Listener = (message: ManagementRealtimeMessage) => void;

let connection: HubConnection | undefined;
let startPromise: Promise<HubConnection> | undefined;
const listeners = new Map<ManagementRealtimeChannel, Set<Listener>>();
const joinedChannels = new Set<ManagementRealtimeChannel>();

const dispatch = (message: ManagementRealtimeMessage) => {
  if (!message.channel || !listeners.has(message.channel as ManagementRealtimeChannel)) return;
  listeners.get(message.channel as ManagementRealtimeChannel)?.forEach((listener) => listener(message));
};

const joinChannelsAfterReconnect = async () => {
  if (!connection || connection.state !== HubConnectionState.Connected) return;
  for (const channel of joinedChannels) {
    try {
      await connection.invoke('Subscribe', channel);
    } catch {
      // 重连期间服务端可能尚未恢复，后续连接事件会再次尝试订阅。
    }
  }
};

const ensureConnection = async () => {
  if (!connection) {
    connection = new HubConnectionBuilder()
      .withUrl('/hubs/management', { withCredentials: true })
      .withAutomaticReconnect([0, 2000, 5000, 10000])
      .configureLogging(LogLevel.Warning)
      .build();
    connection.on('dataChanged', dispatch);
    connection.on('managementDataChanged', dispatch);
    connection.onreconnected(() => void joinChannelsAfterReconnect());
  }

  if (connection.state === HubConnectionState.Connected) return connection;
  if (startPromise) return startPromise;

  startPromise = connection.start()
    .then(() => connection as HubConnection)
    .finally(() => {
      startPromise = undefined;
    });
  return startPromise;
};

export async function subscribeManagementRealtime(
  channel: ManagementRealtimeChannel,
  listener: Listener,
): Promise<() => void> {
  const channelListeners = listeners.get(channel) ?? new Set<Listener>();
  channelListeners.add(listener);
  listeners.set(channel, channelListeners);
  joinedChannels.add(channel);

  try {
    const activeConnection = await ensureConnection();
    await activeConnection.invoke('Subscribe', channel);
  } catch {
    // API 未初始化或当前会话失效时，页面仍保留手动刷新和首次查询能力。
  }

  return () => {
    const currentListeners = listeners.get(channel);
    currentListeners?.delete(listener);
    if (currentListeners?.size === 0) {
      listeners.delete(channel);
      joinedChannels.delete(channel);
    }
  };
}
