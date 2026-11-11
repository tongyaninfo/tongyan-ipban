/**
 * 通研 IPBan 业务路由。模板示例页面已从产品导航移除。
 */
export default [
  {
    path: '/user',
    layout: false,
    routes: [
      {
        path: '/user/login',
        name: 'login',
        component: './user/login',
      },
      {
        name: '404',
        component: './exception/404',
        path: '/user/*',
      },
    ],
  },
  {
    path: '/docs',
    name: 'docs',
    hideInMenu: true,
    component: './docs',
  },
  {
    path: '/dashboard/analysis',
    name: 'dashboard',
    icon: 'dashboard',
    component: './dashboard/analysis',
  },
  {
    path: '/dashboard',
    hideInMenu: true,
    redirect: '/dashboard/analysis',
  },
  {
    path: '/current',
    name: 'current',
    icon: 'monitor',
    routes: [
      {
        path: '/current',
        redirect: '/current/sessions',
      },
      {
        path: '/current/sessions',
        name: 'sessions',
        icon: 'team',
        component: './current/sessions',
      },
      {
        path: '/current/connections',
        name: 'connections',
        icon: 'link',
        component: './current/connections',
      },
    ],
  },
  {
    path: '/security',
    name: 'security',
    icon: 'safetyCertificate',
    routes: [
      { path: '/security', redirect: '/security/events' },
      { path: '/security/events', name: 'events', icon: 'fileSearch', component: './security/events' },
      { path: '/security/decisions', name: 'decisions', icon: 'audit', component: './security/decisions' },
      { path: '/security/bans', name: 'bans', icon: 'stop', component: './security/bans' },
    ],
  },
  {
    path: '/access',
    name: 'access',
    icon: 'lock',
    routes: [
      { path: '/access', redirect: '/access/allowlist' },
      { path: '/access/allowlist', name: 'allowlist', icon: 'checkCircle', component: './access/allowlist' },
      { path: '/access/policies', name: 'policies', icon: 'branches', component: './access/policies' },
    ],
  },
  {
    path: '/system',
    name: 'system',
    icon: 'setting',
    routes: [
      { path: '/system', redirect: '/system/users' },
      { path: '/system/ip-database', name: 'ip-database', icon: 'global', component: './system/ip-database' },
      { path: '/system/settings', name: 'settings', icon: 'setting', component: './system/settings' },
      { path: '/system/notifications', name: 'notifications', icon: 'mail', component: './system/notifications' },
      { path: '/system/users', name: 'users', icon: 'team', component: './system/users' },
      { path: '/system/certificates', name: 'certificates', icon: 'safety', component: './system/certificates' },
      { path: '/system/logs', name: 'logs', icon: 'fileText', component: './system/logs' },
      { path: '/system/audit', name: 'audit', icon: 'audit', component: './system/audit' },
      { path: '/system/mcp', name: 'mcp', icon: 'api', component: './system/mcp' },
      { path: '/system/backups', name: 'backups', icon: 'database', component: './system/backups' },
    ],
  },
  {
    path: '/',
    redirect: '/dashboard/analysis',
  },
  {
    component: './exception/404',
    path: '/*',
  },
];
