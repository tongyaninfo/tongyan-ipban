import { createStyles } from 'antd-style';
import React from 'react';

const useStyles = createStyles(({ token, css }, dark: boolean) => ({
  footer: css`
    padding: 12px 24px;
    text-align: center;
  `,
  link: css`
    display: inline-flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    color: ${token.colorTextSecondary};
    font-size: ${token.fontSizeSM}px;
    line-height: ${token.lineHeight};
    text-decoration: none;

    &:hover {
      color: ${token.colorLinkHover};
      text-decoration: underline;
    }

    &:focus-visible {
      outline: 2px solid ${token.colorPrimary};
      outline-offset: 3px;
    }
  `,
  logo: css`
    display: block;
    border-radius: ${token.borderRadiusSM}px;
    background-color: ${dark ? '#fff' : 'transparent'};
  `,
}));

const Footer: React.FC<{ className?: string; dark?: boolean }> = ({ className, dark = false }) => {
  const { styles, cx } = useStyles(dark);

  return (
    <footer className={cx(styles.footer, className)}>
      <a className={styles.link} href="https://www.tongyaninfo.com" target="_blank" rel="noopener noreferrer">
        <img className={styles.logo} src="/assets/brand/tyinfo-logo-horizontal_mini.png" width={90} height={30} alt="" />
        <span>TongYanInfo Site</span>
      </a>
    </footer>
  );
};

export default Footer;
