import type { ConnectionSnapshot } from '@/services/ipban/system';

type Translate = (id: string, defaultMessage: string) => string;

/** 端点仅用于显示；操作接口仍接收原始 DTO，IPv6 地址保留方括号。 */
export function displayEndpoint(
  ip: string | null | undefined,
  port: number | null | undefined,
  missingLabel: string,
) {
  const address = ip?.includes(':') && !ip.startsWith('[') ? `[${ip}]` : ip;
  return `${address || missingLabel}:${port ?? missingLabel}`;
}

export function protocolLabel(value: string, text: Translate) {
  const labels: Record<string, string> = {
    tcp: 'TCP',
    ssh: text('pages.current.protocolSsh', 'SSH'),
    openssh: text('pages.current.protocolSsh', 'SSH'),
    rdp: text('pages.current.protocolRdp', 'RDP'),
    vnc: text('pages.current.protocolVnc', 'VNC'),
    winrm: text('pages.current.protocolWinRm', 'WinRM'),
  };
  return labels[value.toLowerCase()] || value;
}

/** 网络页不关联登录记录；业务协议按端口和进程推断，不等同于认证成功。 */
export function resolveConnectionProtocol(record: ConnectionSnapshot) {
  if (
    record.localPort === 22 ||
    record.processName?.toLowerCase().includes('ssh')
  )
    return 'ssh';
  if (record.localPort === 3389) return 'rdp';
  // WinRM 的标准端口也在 VNC 常用端口区间内，必须优先识别。
  if (record.localPort === 5985 || record.localPort === 5986) return 'winrm';
  if (
    record.localPort != null &&
    record.localPort >= 5900 &&
    record.localPort <= 5999
  )
    return 'vnc';
  return record.protocol;
}

const tcpStates: Record<string, { key: string; fallback: string }> = {
  established: { key: 'established', fallback: '已建立' },
  estab: { key: 'established', fallback: '已建立' },
  synsent: { key: 'synSent', fallback: '等待连接响应' },
  synrecv: { key: 'synReceived', fallback: '等待连接确认' },
  synreceived: { key: 'synReceived', fallback: '等待连接确认' },
  newsynrecv: { key: 'newSynReceived', fallback: '新连接待确认' },
  finwait1: { key: 'finWait1', fallback: '等待断开确认' },
  finwait2: { key: 'finWait2', fallback: '等待对端关闭' },
  timewait: { key: 'timeWait', fallback: '等待连接释放' },
  closewait: { key: 'closeWait', fallback: '等待本地关闭' },
  lastack: { key: 'lastAck', fallback: '等待最终确认' },
  listen: { key: 'listen', fallback: '监听中' },
  listening: { key: 'listen', fallback: '监听中' },
  close: { key: 'closed', fallback: '已关闭' },
  closed: { key: 'closed', fallback: '已关闭' },
  closing: { key: 'closing', fallback: '正在关闭' },
  deletetcb: { key: 'deleteTcb', fallback: '正在删除连接' },
  unconn: { key: 'unconnected', fallback: '未连接' },
  bound: { key: 'bound', fallback: '已绑定，未连接' },
  boundinactive: { key: 'bound', fallback: '已绑定，未连接' },
};

/** 兼容 Linux ss 的 ESTAB/SYN-RECV 与 Windows netstat 的 ESTABLISHED/SYN_RECEIVED。 */
export function tcpStateLabel(
  value: string | null | undefined,
  text: Translate,
) {
  const raw = value?.trim();
  if (!raw) return text('pages.current.notCollected', '未采集');
  const state = tcpStates[raw.toLowerCase().replace(/[-_\s]/g, '')];
  if (state) return text(`pages.current.tcpState.${state.key}`, state.fallback);
  return `${text('pages.current.tcpState.unrecognized', '未识别状态')} (${raw})`;
}
