const protocolLabels: Record<string, string> = {
  '0': 'SSH',
  '1': 'VNC',
  '2': 'RDP',
  '3': 'OpenSSH',
  '4': 'WinRM',
  ssh: 'SSH',
  vnc: 'VNC',
  rdp: 'RDP',
  openssh: 'OpenSSH',
  winrm: 'WinRM',
};

export function loginEventProtocolLabel(protocol: string | number, unidentifiedLabel: string): string {
  const value = String(protocol);
  const key = value.toLowerCase();
  // 兼容数字枚举和字符串协议，未识别协议统一使用本地化标签。
  if (key === '5' || key === 'unidentified') return unidentifiedLabel;
  return protocolLabels[key] ?? value;
}
