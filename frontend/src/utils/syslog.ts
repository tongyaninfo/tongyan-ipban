import { useIntl } from '@umijs/max';
import type { SyslogSeverity } from '@/services/ipban/syslog';

const severities: SyslogSeverity[] = [0, 1, 2, 3, 4, 5, 6, 7];

export function useSyslogMessages() {
  const intl = useIntl();
  const text = (
    id: string,
    values?: Record<string, string | number>,
    defaultMessage?: string,
  ) => intl.formatMessage({ id: `pages.syslog.${id}`, defaultMessage }, values);
  const severityLabel = (level: SyslogSeverity) =>
    `${level} · ${text(`severity.${level}`)}`;
  return {
    intl,
    text,
    severityLabel,
    severityOptions: severities.map((value) => ({
      value,
      label: severityLabel(value),
    })),
  };
}
