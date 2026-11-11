import { useIntl } from '@umijs/max';
import { Typography } from 'antd';
import { useCallback, useSyncExternalStore, type ReactNode } from 'react';
import { ipLocationStore } from '@/services/ipban/ipLocationStore';
import type { IpLocationResult } from '@/services/ipban/ipLocation';
import { displayEndpoint } from '@/utils/currentConnections';

/** 只拼接真实返回的字段，去除同名省市与重复运营商；仅有网络归属也保留展示。 */
export function locationDescription(value: IpLocationResult) {
  const geography = [value.country, value.province, value.city, value.district]
    .map((part) => part?.trim()).filter(Boolean);
  const region = value.region?.trim();
  // 通研接口的 region 也映射为 province；重复时按国家、省、市顺序展示。
  return [...new Set([...(region && !geography.includes(region) ? [region] : []), ...geography, value.isp, value.asName, value.asn]
    .map((part) => part?.trim()).filter(Boolean))].join(' · ');
}

type Props = { ip?: string | null; port?: number | null; endpoint?: boolean; missingLabel?: string; children?: ReactNode };

export default function IpLocationText({ ip, port, endpoint = false, missingLabel = '—', children }: Props) {
  const intl = useIntl();
  const address = ip?.trim() ?? '';
  const subscribe = useCallback((listener: () => void) => ipLocationStore.subscribe(address, listener), [address]);
  const snapshot = useCallback(() => ipLocationStore.getSnapshot(address), [address]);
  const location = useSyncExternalStore(subscribe, snapshot, () => undefined);
  const text = (key: string) => intl.formatMessage({ id: `pages.ipLocation.${key}` });
  const description = location?.status === 'resolved' ? locationDescription(location) || text('status.notFound')
    : location && location.status !== 'disabled' ? text(`status.${location.status}`) : undefined;
  const attribution = location ? [location.database, location.version, location.isp, location.asName, location.attribution].filter(Boolean).join(' · ') : undefined;
  return <span style={{ display: 'inline-block', maxWidth: '100%', overflowWrap: 'anywhere', verticalAlign: 'top' }}>
    <span style={{ display: 'block' }}>{children ?? (endpoint ? displayEndpoint(ip, port, missingLabel) : ip || missingLabel)}</span>
    {description && <Typography.Text type="secondary" title={attribution} style={{ display: 'block', fontSize: 12, whiteSpace: 'normal', lineHeight: 1.5 }}>{description}</Typography.Text>}
  </span>;
}
