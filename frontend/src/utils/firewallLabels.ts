type Translate = (id: string) => string;

const providerKeys: Record<string, string> = {
  'windows-defender-firewall-wfp': 'pages.security.providers.windows',
  firewalld: 'pages.security.providers.firewalld',
  ufw: 'pages.security.providers.ufw',
  nftables: 'pages.security.providers.nftables',
  iptables: 'pages.security.providers.iptables',
  'not-probed': 'pages.security.providers.notProbed',
  none: 'pages.security.providers.none',
};

const statusKeys: Record<string, string> = {
  applied: 'pages.security.decisions.applied',
  removed: 'pages.security.decisions.removed',
  pending: 'pages.security.decisions.pending',
  failed: 'pages.security.decisions.failed',
  disabled: 'pages.security.decisions.disabled',
  superseded: 'pages.security.decisions.superseded',
};

const actionKeys: Record<string, string> = {
  ban: 'pages.security.decisions.ban',
  'auto-ban': 'pages.security.decisions.autoBan',
  unban: 'pages.security.decisions.unban',
  'manual-unban': 'pages.security.decisions.manualUnban',
  'auto-unban': 'pages.security.decisions.autoUnban',
};

// 机器标识保留在合同中，页面按当前语言翻译，未来未知值仍显示原始内容便于识别。
export const firewallProviderLabel = (value: string, translate: Translate) => {
  const key = providerKeys[value.toLowerCase()];
  return key ? translate(key) : value;
};

export const firewallStatusLabel = (value: string, translate: Translate) => {
  const key = statusKeys[value.toLowerCase()];
  return key ? translate(key) : value;
};

export const firewallActionLabel = (value: string, translate: Translate) => {
  const key = actionKeys[value.toLowerCase()];
  return key ? translate(key) : value;
};

export const firewallStatusColor = (value: string) => {
  const colors: Record<string, string> = {
    applied: 'red', removed: 'green', pending: 'gold', failed: 'red', disabled: 'orange',
  };
  return colors[value.toLowerCase()] ?? 'default';
};

export const unbanErrorLabel = (code: string, fallback: string, translate: Translate) => {
  const keys: Record<string, string> = {
    INVALID_REQUEST: 'invalid', INVALID_BAN_ACTION: 'invalid', BAN_NOT_FOUND: 'notFound',
    BAN_NOT_CURRENT: 'notCurrent', FIREWALL_PROVIDER_UNAVAILABLE: 'unavailable',
    FIREWALL_UNBAN_FAILED: 'failed', UNBAN_AUDIT_FAILED: 'auditFailed',
    AGENT_IPC_ERROR: 'apiError', AGENT_IPC_TIMEOUT: 'apiError', AGENT_IPC_UNAVAILABLE: 'apiError', NETWORK_ERROR: 'apiError',
  };
  return keys[code] ? translate(`pages.security.unbanErrors.${keys[code]}`) : fallback;
};
