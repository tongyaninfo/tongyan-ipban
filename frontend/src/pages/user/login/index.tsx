import {
  ApiOutlined,
  LockOutlined,
  RadarChartOutlined,
  SafetyCertificateOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { Alert, App, Button, Card, Checkbox, Form, Input, Typography } from 'antd';
import { Helmet, SelectLang, useIntl, useModel } from '@umijs/max';
import { createStyles } from 'antd-style';
import React, { startTransition, useEffect, useState } from 'react';
import Footer from '@/components/Footer';
import { initializeAdmin, login, setupStatus } from '@/services/ant-design-pro/api';
import Settings from '../../../../config/defaultSettings';

const getSafeRedirectUrl = (redirect: string | null): string => {
  if (!redirect?.startsWith('/') || redirect.startsWith('//')) return '/';
  try {
    const parsed = new URL(redirect, window.location.origin);
    if (parsed.origin !== window.location.origin) return '/';
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return '/';
  }
};

const useStyles = createStyles(({ css }) => ({
  container: css`
    position: relative;
    min-height: 100vh;
    overflow: hidden;
    background:
      radial-gradient(circle at 10% 18%, rgba(50, 105, 210, 0.16), transparent 32%),
      radial-gradient(circle at 90% 84%, rgba(39, 166, 175, 0.13), transparent 30%),
      linear-gradient(135deg, #edf3ff 0%, #f8fbff 48%, #f3f6fa 100%);
  `,
  glow: css`
    position: absolute;
    border-radius: 50%;
    filter: blur(2px);
    pointer-events: none;
  `,
  glowOne: css`
    top: -180px;
    right: -100px;
    width: 420px;
    height: 420px;
    background: rgba(48, 101, 191, 0.08);
  `,
  glowTwo: css`
    bottom: -220px;
    left: 18%;
    width: 500px;
    height: 500px;
    background: rgba(32, 151, 164, 0.07);
  `,
  topBar: css`
    position: relative;
    z-index: 1;
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: min(1180px, calc(100% - 64px));
    margin: 0 auto;
    padding-top: 28px;
    @media (max-width: 860px) {
      width: min(100% - 40px, 600px);
      padding-top: 20px;
    }
    @media (max-width: 480px) {
      width: calc(100% - 32px);
    }
  `,
  brand: css`
    display: inline-flex;
    align-items: center;
    gap: 12px;
    color: #172b4d;
    font-size: 18px;
    font-weight: 700;
    letter-spacing: 0.02em;
  `,
  brandLogo: css`
    width: 150px;
    height: 50px;
    object-fit: contain;
    object-position: left center;
  `,
  brandProduct: css`
    padding-left: 12px;
    border-left: 1px solid rgba(43, 74, 120, 0.16);
    color: #315ca8;
    font-size: 16px;
    letter-spacing: 0.08em;
  `,
  language: css`
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 42px;
    height: 42px;
    border: 1px solid rgba(43, 74, 120, 0.12);
    border-radius: 12px;
    background: rgba(255, 255, 255, 0.7);
    box-shadow: 0 8px 20px rgba(33, 74, 140, 0.06);
  `,
  content: css`
    position: relative;
    z-index: 1;
    display: grid;
    grid-template-columns: minmax(0, 1.05fr) minmax(360px, 0.95fr);
    align-items: center;
    gap: 88px;
    width: min(1180px, calc(100% - 64px));
    min-height: calc(100vh - 106px);
    margin: 0 auto;
    padding: 54px 0 88px;
    @media (max-width: 860px) {
      display: block;
      width: min(100% - 40px, 600px);
      min-height: auto;
      padding: 58px 0 92px;
    }
    @media (max-width: 480px) {
      width: calc(100% - 32px);
      padding-top: 40px;
    }
  `,
  intro: css`
    max-width: 570px;
    @media (max-width: 860px) {
      max-width: none;
      margin-bottom: 36px;
    }
  `,
  eyebrow: css`
    margin-bottom: 18px;
    color: #315ca8;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.26em;
  `,
  heading: css`
    margin: 0 0 18px !important;
    color: #142849 !important;
    font-size: clamp(42px, 5vw, 68px) !important;
    line-height: 1.05 !important;
    letter-spacing: -0.04em;
    @media (max-width: 860px) {
      font-size: clamp(40px, 12vw, 58px) !important;
    }
  `,
  subtitle: css`
    max-width: 500px;
    margin-bottom: 42px !important;
    color: #526681 !important;
    font-size: 18px;
    line-height: 1.8;
    @media (max-width: 860px) {
      margin-bottom: 26px !important;
      font-size: 16px;
    }
  `,
  featureList: css`
    display: grid;
    gap: 16px;
  `,
  feature: css`
    display: flex;
    align-items: center;
    gap: 16px;
    max-width: 500px;
    padding: 14px 18px;
    border: 1px solid rgba(62, 101, 163, 0.1);
    border-radius: 16px;
    background: rgba(255, 255, 255, 0.48);
    backdrop-filter: blur(12px);
    @media (max-width: 480px) {
      padding: 12px;
    }
  `,
  featureIcon: css`
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: 0 0 42px;
    width: 42px;
    height: 42px;
    border-radius: 13px;
    color: #2f5cab;
    background: #e9f0ff;
    font-size: 20px;
  `,
  featureTitle: css`
    margin-bottom: 3px;
    color: #203a62;
    font-size: 15px;
    font-weight: 700;
  `,
  featureDescription: css`
    color: #70829a;
    font-size: 13px;
    line-height: 1.55;
  `,
  card: css`
    width: 100%;
    max-width: 450px;
    justify-self: end;
    border: 1px solid rgba(42, 78, 128, 0.09) !important;
    border-radius: 24px !important;
    background: rgba(255, 255, 255, 0.92) !important;
    box-shadow: 0 26px 70px rgba(27, 63, 116, 0.15) !important;
    @media (max-width: 860px) {
      max-width: none;
    }
  `,
  cardBody: css`
    padding: 38px 38px 30px !important;
    @media (max-width: 480px) {
      padding: 28px 22px 24px !important;
    }
  `,
  accent: css`
    width: 34px;
    height: 4px;
    margin-bottom: 22px;
    border-radius: 999px;
    background: #d49447;
  `,
  cardTitle: css`
    margin: 0 0 8px !important;
    color: #172b4d !important;
    font-size: 30px !important;
    letter-spacing: -0.03em;
  `,
  cardDescription: css`
    margin-bottom: 24px !important;
    color: #74839a !important;
    line-height: 1.65;
  `,
  setupHint: css`
    margin-bottom: 18px;
    border-radius: 12px;
  `,
  field: css`
    height: 52px;
    border-radius: 12px !important;
    background: #f7f9fc !important;
  `,
  submit: css`
    height: 52px;
    margin-top: 10px;
    border: 0;
    border-radius: 12px;
    background: #2f56ad;
    box-shadow: 0 10px 22px rgba(47, 86, 173, 0.2);
    font-size: 16px;
    font-weight: 700;
  `,
  securityHint: css`
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 24px;
    color: #8996a8;
    font-size: 12px;
    line-height: 1.6;
  `,
  footer: css`
    position: absolute;
    right: 0;
    bottom: 10px;
    left: 0;
    z-index: 1;
  `,
}));

const LoginMessage: React.FC<{ content: string }> = ({ content }) => (
  <Alert style={{ marginBottom: 18 }} title={content} type="error" showIcon />
);

const Login: React.FC = () => {
  const [userLoginState, setUserLoginState] = useState<API.LoginResult>({});
  const [setupRequired, setSetupRequired] = useState(false);
  const { initialState, setInitialState } = useModel('@@initialState');
  const { styles } = useStyles();
  const { message } = App.useApp();
  const intl = useIntl();
  const [form] = Form.useForm();
  const text = (id: string, defaultMessage: string) => intl.formatMessage({ id, defaultMessage });

  useEffect(() => {
    void setupStatus().then((result) => {
      setSetupRequired(result?.data?.initialized === false);
    }).catch(() => setSetupRequired(false));
  }, []);

  const fetchUserInfo = async () => {
    const userInfo = await initialState?.fetchUserInfo?.();
    if (userInfo) {
      startTransition(() => {
        setInitialState((state) => ({ ...state, currentUser: userInfo }));
      });
    }
  };

  const handleSubmit = async (values: API.LoginParams & { displayName?: string }) => {
    try {
      if (setupRequired) {
        const setup = await initializeAdmin({
          username: values.username || '',
          displayName: values.displayName || values.username || '',
          password: values.password || '',
        });
        if (!setup.success) {
          message.error(setup.message || text('pages.login.setupFailure', '初始化失败'));
          return;
        }
      } else {
        const result = await login({ ...values, type: 'account' });
        if (result.status !== 'ok') {
          setUserLoginState(result);
          return;
        }
      }

      message.success(text('pages.login.success', '登录成功！'));
      await fetchUserInfo();
      const redirectUrl = getSafeRedirectUrl(new URL(window.location.href).searchParams.get('redirect'));
      window.location.href = redirectUrl;
    } catch {
      message.error(text('pages.login.failure', '登录失败，请重试！'));
    }
  };

  const { status, type: loginType } = userLoginState;
  const title = setupRequired ? text('pages.login.setupTitle', '初始化管理员') : text('pages.login.welcome', '欢迎回来');
  const description = setupRequired
    ? text('pages.login.setupDescription', '首次启动，请创建本机管理台的第一个管理员账号。')
    : text('pages.login.welcomeDescription', '登录你的账号，进入 IPBan 防护工作台。');

  return (
    <div className={styles.container}>
      <div className={`${styles.glow} ${styles.glowOne}`} />
      <div className={`${styles.glow} ${styles.glowTwo}`} />
      <Helmet>
        <title>{title}{Settings.title && ` - ${Settings.title}`}</title>
      </Helmet>
      <header className={styles.topBar}>
        <div className={styles.brand}>
          <img className={styles.brandLogo} src="/assets/brand/tyinfo-logo-horizontal.png" alt={text('pages.login.brand', '通研技术')} />
          <span className={styles.brandProduct}>IPBan</span>
        </div>
        <div className={styles.language} title={text('pages.login.language', '语言切换')}>
          <SelectLang />
        </div>
      </header>
      <main className={styles.content}>
        <section className={styles.intro} aria-labelledby="ipban-login-title">
          <div className={styles.eyebrow}>IPBAN / LOCAL SECURITY</div>
          <Typography.Title id="ipban-login-title" className={styles.heading}>{text('pages.login.productTitle', '通研 IPBan')}</Typography.Title>
          <Typography.Paragraph className={styles.subtitle}>{text('pages.login.productSubtitle', '本机登录防护与 IP 封禁管理台')}</Typography.Paragraph>
          <div className={styles.featureList}>
            <div className={styles.feature}><span className={styles.featureIcon}><SafetyCertificateOutlined /></span><div><div className={styles.featureTitle}>{text('pages.login.featureProtectionTitle', '让登录防护更可靠')}</div><div className={styles.featureDescription}>{text('pages.login.featureProtectionDescription', '集中查看 SSH、RDP、WinRM 等登录事件与封禁状态')}</div></div></div>
            <div className={styles.feature}><span className={styles.featureIcon}><RadarChartOutlined /></span><div><div className={styles.featureTitle}>{text('pages.login.featureInsightTitle', '让风险判断更清晰')}</div><div className={styles.featureDescription}>{text('pages.login.featureInsightDescription', '从来源 IP、连接、会话和进程关联风险活动')}</div></div></div>
            <div className={styles.feature}><span className={styles.featureIcon}><ApiOutlined /></span><div><div className={styles.featureTitle}>{text('pages.login.featureControlTitle', '让处置动作更有序')}</div><div className={styles.featureDescription}>{text('pages.login.featureControlDescription', '联动本机防火墙，支持人工下线与 IP 封禁')}</div></div></div>
          </div>
        </section>
        <Card className={styles.card} styles={{ body: { padding: 0 } }}>
          <div className={styles.cardBody}>
            <div className={styles.accent} />
            <Typography.Title level={2} className={styles.cardTitle}>{title}</Typography.Title>
            <Typography.Paragraph className={styles.cardDescription}>{description}</Typography.Paragraph>
            {setupRequired && <Alert className={styles.setupHint} type="info" showIcon message={text('pages.login.setupHint', '管理员账号只保存在本机，不预置默认密码。')} />}
            {status === 'error' && loginType === 'account' && <LoginMessage content={text('pages.login.accountLogin.errorMessage', '账户或密码错误')} />}
            <Form form={form} layout="vertical" requiredMark onFinish={handleSubmit} initialValues={{ autoLogin: true }}>
              <Form.Item name="username" label={text('pages.login.username.label', '用户名')} rules={[{ required: true, message: text('pages.login.username.required', '请输入用户名') }]}>
                <Input className={styles.field} size="large" prefix={<UserOutlined />} placeholder={text('pages.login.username.placeholder', '请输入用户名')} />
              </Form.Item>
              {setupRequired && <Form.Item name="displayName" label={text('pages.login.displayName.label', '显示名称')} rules={[{ required: true, message: text('pages.login.displayName.required', '请输入显示名称') }]}>
                <Input className={styles.field} size="large" prefix={<UserOutlined />} placeholder={text('pages.login.displayName.placeholder', '请输入显示名称')} />
              </Form.Item>}
              <Form.Item name="password" label={text('pages.login.password.label', '密码')} rules={[{ required: true, message: text('pages.login.password.required', '请输入密码') }]}>
                <Input.Password className={styles.field} size="large" prefix={<LockOutlined />} placeholder={text('pages.login.password.placeholder', '请输入密码')} />
              </Form.Item>
              <Form.Item name="autoLogin" valuePropName="checked" style={{ marginBottom: 8 }}>
                <Checkbox>{text('pages.login.rememberMe', '自动登录')}</Checkbox>
              </Form.Item>
              <Button className={styles.submit} type="primary" htmlType="submit" block size="large">{setupRequired ? text('pages.login.initializeButton', '创建管理员') : text('pages.login.loginButton', '登录管理平台')}</Button>
            </Form>
            <div className={styles.securityHint}><LockOutlined />{text('pages.login.securityHint', '管理台账号仅用于本机访问，登录凭据通过安全会话保护。')}</div>
          </div>
        </Card>
      </main>
      <Footer className={styles.footer} />
    </div>
  );
};

export default Login;
