import { CheckOutlined } from '@ant-design/icons';
import type { SettingDrawerProps } from '@ant-design/pro-components';
import { SettingDrawer } from '@ant-design/pro-components';
import { useIntl, useModel } from '@umijs/max';
import { Tooltip } from 'antd';
import { createStyles } from 'antd-style';
import React, { useEffect } from 'react';
import {
  resolveTheme,
  saveThemeMode,
  subscribeSystemTheme,
  type ThemeMode,
} from '@/utils/theme';

const useStyles = createStyles(({ token }) => ({
  drawerHeader: {
    // 使用 Drawer 的公开 extra 插槽；标题和风格区分成两行，中间保留标题分隔线。
    '& > .ant-drawer-header-title': {
      padding: '12px 24px',
      borderBottom: `1px solid ${token.colorSplit}`,
    },
  },
  drawerBody: {
    // SettingDrawer 没有主题选项插槽，只隐藏它内置的深浅色选项，保留其余设置。
    '& .ant-pro-setting-drawer-drawer-content > div:has(> .ant-pro-setting-drawer-block-checkbox > .ant-pro-setting-drawer-block-checkbox-theme-item)':
      {
        display: 'none',
      },
  },
  styleTitle: {
    margin: '0 0 16px',
    color: token.colorTextHeading,
    fontSize: 14,
    fontWeight: 600,
    lineHeight: '22px',
  },
  previews: {
    display: 'flex',
    gap: 12,
  },
  preview: {
    position: 'relative',
    display: 'block',
    flex: '0 0 44px',
    width: 44,
    height: 36,
    padding: 0,
    border: 0,
    borderRadius: 4,
    overflow: 'hidden',
    background: 'transparent',
    boxShadow: token.boxShadow,
    cursor: 'pointer',
    '&:focus-visible': {
      outline: '2px solid #1677ff',
      outlineOffset: 4,
    },
  },
  selected: {
    position: 'absolute',
    right: 6,
    bottom: 4,
    color: '#1677ff',
    fontSize: 14,
    pointerEvents: 'none',
  },
  autoDescription: {
    margin: '16px 0 0',
    color: token.colorTextSecondary,
    fontSize: 14,
    fontWeight: 400,
    lineHeight: '22px',
  },
}));

/** 用矢量色块呈现浅色、深色和左右明暗的自动模式，不受当前页面主题影响。 */
function ThemePreview({ mode }: { mode: ThemeMode }) {
  if (mode === 'auto') {
    return (
      <svg
        width="44"
        height="36"
        viewBox="0 0 44 36"
        aria-hidden="true"
        focusable="false"
      >
        <path fill="#fff" d="M0 0h22v36H0z" />
        <path fill="#000" d="M22 0h22v36H22z" />
        <path fill="#f0f2f5" d="M6 9h16v27H6z" />
        <path fill="#141414" d="M22 9h22v27H22z" />
        <path fill="#001529" d="M22 9h6v27h-6z" />
        <path fill="none" stroke="#e3e5e8" d="M6 36V9h16" />
        <path fill="none" stroke="#303030" d="M28 36V9h16" />
        <rect x="10" y="14" width="7" height="17" rx="2" fill="#fff" />
        <rect x="32" y="14" width="7" height="17" rx="2" fill="#262626" />
      </svg>
    );
  }
  const dark = mode === 'realDark';
  return (
    <svg
      width="44"
      height="36"
      viewBox="0 0 44 36"
      aria-hidden="true"
      focusable="false"
    >
      <path fill={dark ? '#000' : '#fff'} d="M0 0h44v36H0z" />
      <path fill={dark ? '#001529' : '#fff'} d="M0 9h12v27H0z" />
      <path fill={dark ? '#141414' : '#f0f2f5'} d="M12 9h32v27H12z" />
      <path fill="none" stroke={dark ? '#303030' : '#e3e5e8'} d="M12 36V9h32" />
      <rect
        x="16"
        y="14"
        width="22"
        height="17"
        rx="2"
        fill={dark ? '#262626' : '#fff'}
      />
    </svg>
  );
}

export default function AppearanceSettings() {
  const { initialState, setInitialState } = useModel('@@initialState');
  const intl = useIntl();
  const { styles } = useStyles();
  const mode = initialState?.themeMode ?? 'light';
  const automatic = mode === 'auto';
  const title = intl.formatMessage({
    id: 'globalHeader.themeSettings',
    defaultMessage: '主题设置',
  });
  const styleTitle = intl.formatMessage({
    id: 'app.setting.pagestyle',
    defaultMessage: '整体风格设置',
  });
  const modes: Array<{ value: ThemeMode; label: string }> = [
    {
      value: 'auto',
      label: intl.formatMessage({
        id: 'app.setting.pagestyle.auto',
        defaultMessage: '自动',
      }),
    },
    {
      value: 'light',
      label: intl.formatMessage({
        id: 'app.setting.themeMode.light',
        defaultMessage: '浅色',
      }),
    },
    {
      value: 'realDark',
      label: intl.formatMessage({
        id: 'app.setting.themeMode.dark',
        defaultMessage: '深色',
      }),
    },
  ];

  useEffect(() => saveThemeMode(mode), [mode]);
  useEffect(() => {
    if (!automatic) return;
    return subscribeSystemTheme((navTheme) => {
      void setInitialState((state) =>
        state?.themeMode === 'auto' && state.settings?.navTheme !== navTheme
          ? { ...state, settings: { ...state.settings, navTheme } }
          : state,
      );
    });
  }, [automatic, setInitialState]);

  const changeMode = (themeMode: ThemeMode) => {
    void setInitialState((state) => ({
      ...state,
      themeMode,
      settings: { ...state?.settings, navTheme: resolveTheme(themeMode) },
    }));
  };

  const changeSettings: SettingDrawerProps['onSettingChange'] = (settings) => {
    // 模板切换混合布局时会传入浅色，由主题选择单独决定实际颜色。
    void setInitialState((state) => ({
      ...state,
      settings: {
        ...state?.settings,
        ...settings,
        navTheme: resolveTheme(state?.themeMode ?? 'light'),
      },
    }));
  };

  return (
    <SettingDrawer
      disableUrlParams
      collapse={initialState?.settingDrawerOpen}
      onCollapseChange={(settingDrawerOpen) =>
        setInitialState((state) => ({ ...state, settingDrawerOpen }))
      }
      settings={initialState?.settings}
      onSettingChange={changeSettings}
      drawerProps={{
        title,
        size: 'min(340px, 100vw)',
        closable: { placement: 'start' },
        classNames: { header: styles.drawerHeader, body: styles.drawerBody },
        styles: {
          header: {
            display: 'grid',
            gridTemplateColumns: 'minmax(0, 1fr)',
            padding: 0,
            borderBottom: 0,
          },
          extra: { minWidth: 0, padding: '24px 14px 0' },
          body: { padding: '16px 14px 24px' },
        },
        extra: (
          <section aria-label={styleTitle}>
            <h3 className={styles.styleTitle}>{styleTitle}</h3>
            <div className={styles.previews}>
              {modes.map(({ value, label }) => (
                <Tooltip key={value} title={label}>
                  <button
                    type="button"
                    className={styles.preview}
                    aria-label={label}
                    aria-pressed={mode === value}
                    onClick={() => changeMode(value)}
                  >
                    <ThemePreview mode={value} />
                    {mode === value && (
                      <CheckOutlined
                        className={styles.selected}
                        aria-hidden="true"
                      />
                    )}
                  </button>
                </Tooltip>
              ))}
            </div>
            <p className={styles.autoDescription}>
              {intl.formatMessage({
                id: 'app.setting.pagestyle.auto.description',
                defaultMessage: '自动模式会跟随操作系统的浅色或深色设置。',
              })}
            </p>
          </section>
        ),
      }}
    />
  );
}
