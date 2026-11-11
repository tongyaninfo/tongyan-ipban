import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import type { SettingDrawerProps } from '@ant-design/pro-components';
import { ConfigProvider, Drawer } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { useState } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import messages from '@/locales/zh-CN/settingDrawer';
import AppearanceSettings from './index';

vi.mock('@umijs/max', () => ({
  useIntl: () => ({
    formatMessage: ({
      id,
      defaultMessage,
    }: {
      id: string;
      defaultMessage: string;
    }) => messages[id as keyof typeof messages] ?? defaultMessage,
  }),
  useModel: () => {
    const [initialState, setInitialState] = useState({
      themeMode: 'light',
      settingDrawerOpen: true,
      settings: { navTheme: 'light', layout: 'side', colorPrimary: '#1677ff' },
    });
    return { initialState, setInitialState };
  },
}));
vi.mock('@ant-design/pro-components', () => ({
  // 使用真实 Drawer 验证公开插槽和关闭按钮，仅隔离 ProLayout 的运行环境。
  SettingDrawer: ({
    drawerProps,
    collapse,
    onCollapseChange,
    settings,
    onSettingChange,
  }: SettingDrawerProps) => (
    <Drawer
      {...drawerProps}
      open={collapse}
      onClose={() => onCollapseChange?.(false)}
    >
      <output aria-label="当前设置">{JSON.stringify(settings)}</output>
      <button
        type="button"
        onClick={() =>
          onSettingChange?.({
            layout: 'mix',
            navTheme: 'light',
            colorPrimary: '#13c2c2',
          })
        }
      >
        切换布局和主题色
      </button>
    </Drawer>
  ),
}));

const listeners = new Set<(event: MediaQueryListEvent) => void>();
let systemDark = false;
beforeEach(() => {
  vi.clearAllMocks();
  listeners.clear();
  systemDark = false;
  vi.spyOn(window, 'matchMedia').mockImplementation(
    (query) =>
      ({
        get matches() { return query === '(prefers-color-scheme: dark)' && systemDark; },
        media: query,
        onchange: null,
        addEventListener: (
          _type: string,
          listener: (event: MediaQueryListEvent) => void,
        ) => {
          if (query === '(prefers-color-scheme: dark)') listeners.add(listener);
        },
        removeEventListener: (
          _type: string,
          listener: (event: MediaQueryListEvent) => void,
        ) => {
          listeners.delete(listener);
        },
        addListener: vi.fn(),
        removeListener: vi.fn(),
        dispatchEvent: vi.fn(),
      }) as unknown as MediaQueryList,
  );
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const showSettings = () =>
  render(
    <ConfigProvider locale={zhCN} theme={{ token: { motion: false } }}>
      <AppearanceSettings />
    </ConfigProvider>,
  );
const currentSettings = () =>
  JSON.parse(screen.getByLabelText('当前设置').textContent || '{}');

describe('appearance settings previews', () => {
  it('shows three accessible 44 by 36 previews and keeps the auto description visible', async () => {
    showSettings();
    expect(
      await screen.findByRole('dialog', { name: '主题设置' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: '整体风格设置' }),
    ).toBeInTheDocument();
    for (const label of ['自动', '浅色', '深色']) {
      const button = screen.getByRole('button', { name: label });
      expect(button).toHaveAttribute('type', 'button');
      expect(button).toHaveAttribute('aria-pressed', String(label === '浅色'));
      expect(button.querySelector('svg')).toHaveAttribute('width', '44');
      expect(button.querySelector('svg')).toHaveAttribute('height', '36');
      button.focus();
      expect(button).toHaveFocus();
    }
    expect(
      screen.getByText(messages['app.setting.pagestyle.auto.description']),
    ).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: '深色' }));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '深色' })).toHaveAttribute(
        'aria-pressed',
        'true',
      ),
    );
    expect(currentSettings()).toMatchObject({
      navTheme: 'realDark',
      layout: 'side',
      colorPrimary: '#1677ff',
    });
    expect(localStorage.setItem).toHaveBeenLastCalledWith(
      'ipban:theme-mode',
      'realDark',
    );
    expect(
      screen.getByText(messages['app.setting.pagestyle.auto.description']),
    ).toBeVisible();
  });

  it('preserves automatic system following when changing other settings', async () => {
    showSettings();
    fireEvent.click(await screen.findByRole('button', { name: '自动' }));
    expect(localStorage.setItem).toHaveBeenLastCalledWith(
      'ipban:theme-mode',
      'auto',
    );
    act(() => {
      systemDark = true;
      for (const listener of listeners)
        listener({ matches: true } as MediaQueryListEvent);
    });
    await waitFor(() => expect(currentSettings().navTheme).toBe('realDark'));
    fireEvent.click(screen.getByRole('button', { name: '切换布局和主题色' }));
    // 布局组件传入浅色时，自动模式仍按系统深色求值，不覆盖用户选择。
    expect(screen.getByRole('button', { name: '自动' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    expect(currentSettings()).toMatchObject({
      layout: 'mix',
      colorPrimary: '#13c2c2',
      navTheme: 'realDark',
    });
    fireEvent.click(screen.getByRole('button', { name: '浅色' }));
    expect(listeners.size).toBe(0);
  });

  it('closes through the native left close button', async () => {
    showSettings();
    const close = await screen.findByRole('button', { name: '关闭' });
    expect(close.closest('.ant-drawer-header-title')).not.toBeNull();
    fireEvent.click(close);
    await waitFor(() =>
      expect(
        screen.queryByRole('dialog', { name: '主题设置' }),
      ).not.toBeInTheDocument(),
    );
  });
});
