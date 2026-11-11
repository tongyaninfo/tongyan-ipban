import { describe, expect, it } from 'vitest';
import simplified from '../locales/zh-CN/pages';
import traditional from '../locales/zh-TW/pages';
import english from '../locales/en-US/pages';
import { firewallActionLabel, firewallProviderLabel, firewallStatusLabel, unbanErrorLabel } from './firewallLabels';

const dictionaries = [simplified, traditional, english];

describe('firewall history internationalization', () => {
  it.each(dictionaries)('provides translated values for every supported provider and action status', (dictionary) => {
    const text = (id: string) => (dictionary as Record<string, string>)[id] ?? id;
    for (const provider of ['windows-defender-firewall-wfp', 'firewalld', 'ufw', 'nftables', 'iptables', 'not-probed', 'none']) {
      expect(firewallProviderLabel(provider, text)).not.toMatch(/^pages\./);
      expect(firewallProviderLabel(provider, text)).not.toBe(provider);
    }
    for (const status of ['Applied', 'Removed', 'Pending', 'Failed', 'Disabled', 'Superseded']) {
      expect(firewallStatusLabel(status, text)).not.toMatch(/^pages\./);
    }
    for (const action of ['ban', 'auto-ban', 'unban', 'manual-unban', 'auto-unban']) {
      expect(firewallActionLabel(action, text)).not.toMatch(/^pages\./);
    }
    for (const code of ['BAN_NOT_CURRENT', 'FIREWALL_UNBAN_FAILED', 'UNBAN_AUDIT_FAILED']) {
      expect(unbanErrorLabel(code, 'raw server message', text)).not.toMatch(/^pages\./);
      expect(unbanErrorLabel(code, 'raw server message', text)).not.toBe('raw server message');
    }
  });

  it('renders Chinese provider and state values instead of machine identifiers', () => {
    const text = (id: string) => (simplified as Record<string, string>)[id];
    expect(firewallProviderLabel('windows-defender-firewall-wfp', text)).toContain('防火墙');
    expect(firewallProviderLabel('nftables', text)).toBe('nftables 防火墙');
    expect(firewallStatusLabel('Applied', text)).toBe('已生效');
    expect(firewallStatusLabel('Removed', text)).toBe('已解封');
  });

  it('keeps unknown values readable for newer servers', () => {
    const text = (id: string) => id;
    expect(firewallProviderLabel('future-provider', text)).toBe('future-provider');
    expect(firewallStatusLabel('FutureState', text)).toBe('FutureState');
    expect(firewallActionLabel('future-action', text)).toBe('future-action');
  });
});
