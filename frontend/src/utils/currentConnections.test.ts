import { describe, expect, it } from 'vitest';
import zhCN from '@/locales/zh-CN/pages';
import zhTW from '@/locales/zh-TW/pages';
import enUS from '@/locales/en-US/pages';
import type { ConnectionSnapshot } from '@/services/ipban/system';
import {
  displayEndpoint,
  protocolLabel,
  resolveConnectionProtocol,
  tcpStateLabel,
} from './currentConnections';

const translate =
  (messages: Record<string, string>) => (id: string, fallback: string) =>
    messages[id] || fallback;

describe('connection display helpers', () => {
  it.each([
    ['192.0.2.4', 22, '192.0.2.4:22'],
    ['2001:db8::1', 5985, '[2001:db8::1]:5985'],
    ['[2001:db8::1]', 3389, '[2001:db8::1]:3389'],
    ['::1', null, '[::1]:未采集'],
    [null, null, '未采集:未采集'],
  ])('formats endpoint %s without losing IPv6 boundaries', (ip, port, expected) => {
    expect(displayEndpoint(ip, port, '未采集')).toBe(expected);
  });

  it.each([
    [22, 'sshd', 'SSH'],
    [2222, 'sshd.exe', 'SSH'],
    [3389, 'svchost', 'RDP'],
    [5985, 'svchost', 'WinRM'],
    [5986, 'svchost', 'WinRM'],
    [5900, 'Xtigervnc', 'VNC'],
    [5999, 'Xtigervnc', 'VNC'],
    [443, 'browser', 'TCP'],
  ])('infers port %s as %s without mutating the connection', (localPort, processName, expected) => {
    const record: ConnectionSnapshot = {
      protocol: 'tcp',
      state: 'ESTAB',
      remoteIp: '192.0.2.4',
      localPort,
      processName,
      observedAtUtc: '2026-01-01T00:00:00Z',
    };
    expect(
      protocolLabel(resolveConnectionProtocol(record), translate(zhCN)),
    ).toBe(expected);
    expect(record.protocol).toBe('tcp');
    expect(record.state).toBe('ESTAB');
  });

  it('labels Windows OpenSSH sessions as SSH', () => {
    expect(protocolLabel('OpenSsh', translate(enUS))).toBe('SSH');
  });

  it.each([
    ['ESTAB', 'ESTABLISHED', 'established'],
    ['SYN-SENT', 'SYN_SENT', 'synSent'],
    ['SYN-RECV', 'SYN_RECEIVED', 'synReceived'],
    ['FIN-WAIT-1', 'FIN_WAIT_1', 'finWait1'],
    ['FIN-WAIT-2', 'FIN_WAIT_2', 'finWait2'],
    ['TIME-WAIT', 'TIME_WAIT', 'timeWait'],
    ['CLOSE-WAIT', 'CLOSE_WAIT', 'closeWait'],
    ['LAST-ACK', 'LAST_ACK', 'lastAck'],
    ['LISTEN', 'LISTENING', 'listen'],
    ['CLOSE', 'CLOSED', 'closed'],
    ['CLOSING', 'closing', 'closing'],
    ['NEW-SYN-RECV', 'new_syn_recv', 'newSynReceived'],
    ['DELETE_TCB', 'DeleteTcb', 'deleteTcb'],
    ['UNCONN', 'unconn', 'unconnected'],
    ['BOUND', 'BOUND_INACTIVE', 'bound'],
  ])('localizes Linux %s and Windows %s states in all three languages', (linux, windows, key) => {
    for (const messages of [zhCN, zhTW, enUS]) {
      const text = translate(messages);
      const expected = (messages as Record<string, string>)[
        `pages.current.tcpState.${key}`
      ];
      expect(expected).toBeTruthy();
      expect(tcpStateLabel(linux, text)).toBe(expected);
      expect(tcpStateLabel(windows, text)).toBe(expected);
    }
  });

  it('uses localized fallbacks and preserves an unrecognized raw state', () => {
    for (const messages of [zhCN, zhTW, enUS]) {
      expect(tcpStateLabel('FUTURE_STATE', translate(messages))).toBe(
        `${messages['pages.current.tcpState.unrecognized']} (FUTURE_STATE)`,
      );
      expect(tcpStateLabel('', translate(messages))).toBe(
        messages['pages.current.notCollected'],
      );
    }
    expect(tcpStateLabel('ESTAB', translate(zhCN))).toBe('已建立');
  });
});
