import ipLocation from './en-US/ipLocation';
import component from './en-US/component';
import globalHeader from './en-US/globalHeader';
import menu from './en-US/menu';
import mcp from './en-US/mcp';
import notifications from './en-US/notifications';
import network from './en-US/network';
import pages from './en-US/pages';
import settingDrawer from './en-US/settingDrawer';
import settings from './en-US/settings';

import syslog from './en-US/syslog';

export default {
  ...syslog,
  ...ipLocation,
  'navBar.lang': 'Languages',
  'layout.user.link.help': 'Help',
  'layout.user.link.privacy': 'Privacy',
  'layout.user.link.terms': 'Terms',
  'app.preview.down.block': 'Download this page to your local project',
  ...globalHeader,
  ...menu,
  ...settingDrawer,
  ...settings,
  ...network,
  ...component,
  ...pages,
  ...mcp,
  ...notifications,
};
