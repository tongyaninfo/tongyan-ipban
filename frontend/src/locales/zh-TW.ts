import ipLocation from './zh-TW/ipLocation';
import component from './zh-TW/component';
import globalHeader from './zh-TW/globalHeader';
import menu from './zh-TW/menu';
import mcp from './zh-TW/mcp';
import network from './zh-TW/network';
import pages from './zh-TW/pages';
import settingDrawer from './zh-TW/settingDrawer';
import settings from './zh-TW/settings';

import syslog from './zh-TW/syslog';

export default {
  ...syslog,
  ...ipLocation,
  'navBar.lang': '語言',
  'layout.user.link.help': '幫助',
  'layout.user.link.privacy': '隱私',
  'layout.user.link.terms': '條款',
  'app.preview.down.block': '下載此頁面到本地項目',
  ...pages,
  ...mcp,
  ...globalHeader,
  ...menu,
  ...settingDrawer,
  ...settings,
  ...network,
  ...component,
};
