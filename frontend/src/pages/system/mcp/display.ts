import { useIntl } from '@umijs/max';
import dayjs, { type Dayjs } from 'dayjs';
import timezone from 'dayjs/plugin/timezone';
import utc from 'dayjs/plugin/utc';

dayjs.extend(utc);
dayjs.extend(timezone);

const timeZone = 'Asia/Shanghai';

export function useMcpMessages() {
  const intl = useIntl();
  const text = (key: string, values?: Record<string, string | number>) =>
    intl.formatMessage({ id: `pages.system.mcp.${key}` }, values);
  const formatter = new Intl.DateTimeFormat(intl.locale, {
    timeZone,
    dateStyle: 'short',
    timeStyle: 'medium',
  });
  const formatTime = (value?: string | null) => (value ? formatter.format(new Date(value)) : '—');
  return { text, formatTime };
}

export function fromShanghaiTime(value: Dayjs, endOfSecond = false) {
  // DatePicker 选择的是北京时间墙钟，提交时转换为带时区的 UTC。
  const timestamp = dayjs.tz(value.format('YYYY-MM-DD HH:mm:ss'), timeZone).toISOString();
  // 审计筛选截止含当前秒，保留 SQLite 中 .NET 时间戳的 100 纳秒精度。
  return endOfSecond ? timestamp.replace('.000Z', '.9999999Z') : timestamp;
}
