import { queryIpLocations, queryIpLocationSettings, type IpLocationResult, type IpLocationSettings } from './ipLocation';

type Listener = () => void;
type Entry = { result?: IpLocationResult; listeners: Set<Listener>; due: number; attempts: number };
const SETTINGS_INTERVAL = 30_000;
const CACHE_LIMIT = 2_000;

/** 单页所有 IP 共用批量队列；卸载最后一个单元格后取消请求与计时器。 */
export function createIpLocationStore(dependencies = {
  settings: queryIpLocationSettings,
  lookup: queryIpLocations,
}) {
  const entries = new Map<string, Entry>();
  let settings: IpLocationSettings | undefined;
  let settingsDue = 0;
  let revision: string | undefined;
  let generation = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let controller: AbortController | undefined;
  let running = false;
  const active = () => Array.from(entries.entries()).filter(([, entry]) => entry.listeners.size > 0);
  const notify = (entry: Entry) => entry.listeners.forEach((listener) => listener());
  const stopTimer = () => { if (timer !== undefined) clearTimeout(timer); timer = undefined; };
  const prune = () => {
    for (const [ip, entry] of entries) {
      if (entries.size <= CACHE_LIMIT) break;
      if (!entry.listeners.size) entries.delete(ip);
    }
  };
  const resetEntries = () => {
    for (const [ip, entry] of entries) {
      entry.result = settings?.enabled ? undefined : { ip, status: 'disabled' };
      entry.due = 0;
      entry.attempts = 0;
      notify(entry);
    }
  };
  const markUnavailable = () => {
    settingsDue = Date.now() + SETTINGS_INTERVAL;
    for (const [ip, entry] of active()) {
      // 已有成功缓存可继续展示；首次失败与待解析失败明确降级，不影响业务内容。
      if (entry.result?.status !== 'resolved') entry.result = { ip, status: 'failed' };
      entry.due = settingsDue;
      notify(entry);
    }
  };
  const schedule = (delay = 25) => {
    if (!active().length || running) return;
    stopTimer();
    timer = setTimeout(() => { timer = undefined; void run(); }, delay);
  };
  const configure = (value: IpLocationSettings) => {
    const changed = JSON.stringify(settings) !== JSON.stringify(value);
    settings = { ...value };
    settingsDue = Date.now() + SETTINGS_INTERVAL;
    if (changed) {
      generation += 1;
      revision = undefined;
      resetEntries();
    }
  };
  async function run() {
    if (running || !active().length) return;
    running = true;
    controller = new AbortController();
    const signal = controller.signal;
    try {
      if (settingsDue <= Date.now()) {
        const settingsGeneration = generation;
        const response = await dependencies.settings(signal);
        if (signal.aborted || settingsGeneration !== generation) return;
        settingsDue = Date.now() + SETTINGS_INTERVAL;
        if (!response.success) { markUnavailable(); return; }
        configure(response.data);
      }
      if (!settings?.enabled || signal.aborted) return;
      const batch = active().filter(([, entry]) => entry.due <= Date.now()).slice(0, 100);
      if (!batch.length) return;
      const requestGeneration = generation;
      const response = await dependencies.lookup(batch.map(([ip]) => ip), signal);
      // 保存配置、切换数据库或卸载会使旧请求失效，不能把旧归属地回填。
      if (signal.aborted || requestGeneration !== generation) return;
      if (response.success) {
        if (revision !== undefined && revision !== response.data.revision) resetEntries();
        revision = response.data.revision;
        if (!response.data.enabled) {
          settings = { ...settings, enabled: false };
          resetEntries();
          return;
        }
      }
      const byIp = new Map(response.success ? response.data.items.map((item) => [item.ip, item]) : []);
      for (const [ip, entry] of batch) {
        const result = byIp.get(ip) ?? { ip, status: 'failed' as const };
        entry.attempts += 1;
        entry.result = result;
        const pending = result.status === 'queued' || result.status === 'busy';
        // 每轮最多追踪 10 次；拥塞或失败时退避，避免慢服务产生高频轮询。
        entry.due = Date.now() + (pending && entry.attempts < 10 ? 1_000
          : result.status === 'resolved' || ['private', 'reserved', 'network', 'invalid'].includes(result.status) ? 600_000 : 30_000);
        if (!pending || entry.attempts >= 10) entry.attempts = 0;
        notify(entry);
      }
    } catch {
      // 网络封装之外的异常同样受退避约束，避免未处理 Promise 与紧密重试。
      if (!signal.aborted) markUnavailable();
    } finally {
      running = false;
      controller = undefined;
      prune();
      const mounted = active();
      if (mounted.length) {
        const next = settings?.enabled ? Math.min(settingsDue, ...mounted.map(([, entry]) => entry.due)) : settingsDue;
        schedule(Math.max(25, next - Date.now()));
      }
    }
  }
  const refresh = () => { settingsDue = 0; schedule(); };
  const onVisible = () => { if (document.visibilityState === 'visible') refresh(); };
  return {
    getSnapshot: (ip: string) => entries.get(ip)?.result,
    subscribe(ip: string, listener: Listener) {
      if (!ip) return () => undefined;
      const first = !active().length;
      const entry = entries.get(ip) ?? { listeners: new Set<Listener>(), due: 0, attempts: 0 };
      entry.listeners.add(listener);
      entries.set(ip, entry);
      if (first && typeof window !== 'undefined') {
        window.addEventListener('focus', refresh);
        document.addEventListener('visibilitychange', onVisible);
      }
      schedule();
      return () => {
        entry.listeners.delete(listener);
        if (!active().length) {
          stopTimer();
          controller?.abort();
          if (typeof window !== 'undefined') {
            window.removeEventListener('focus', refresh);
            document.removeEventListener('visibilitychange', onVisible);
          }
        }
        prune();
      };
    },
    invalidate(value?: IpLocationSettings) {
      generation += 1;
      controller?.abort();
      revision = undefined;
      if (value) configure(value);
      else settingsDue = 0;
      resetEntries();
      schedule();
    },
  };
}

export const ipLocationStore = createIpLocationStore();
