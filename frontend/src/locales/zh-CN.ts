import ipLocation from './zh-CN/ipLocation';
import component from './zh-CN/component';
import globalHeader from './zh-CN/globalHeader';
import menu from './zh-CN/menu';
import mcp from './zh-CN/mcp';
import notifications from './zh-CN/notifications';
import network from './zh-CN/network';
import pages from './zh-CN/pages';
import settingDrawer from './zh-CN/settingDrawer';
import settings from './zh-CN/settings';

import syslog from './zh-CN/syslog';

export default {
  ...syslog,
  ...ipLocation,
  'navBar.lang': '语言',
  'layout.user.link.help': '帮助',
  'layout.user.link.privacy': '隐私',
  'layout.user.link.terms': '条款',
  'app.preview.down.block': '下载此页面到本地项目',
  ...pages,
  ...mcp,
  ...notifications,
  ...globalHeader,
  ...menu,
  ...settingDrawer,
  ...settings,
  ...network,
  ...component,
};
