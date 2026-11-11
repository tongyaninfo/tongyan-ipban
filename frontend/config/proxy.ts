/**
 * @name 代理的配置
 * @see 在生产环境 代理是无法生效的，所以这里没有生产环境的配置
 * -------------------------------
 * The agent cannot take effect in the production environment
 * so there is no configuration of the production environment
 * For details, please see
 * https://pro.ant.design/docs/deploy
 *
 * @doc https://umijs.org/docs/guides/proxy
 */
export default {
  // 开发时把同源 API 转发到本机管理 API，生产构建不依赖代理。
  dev: {
    '/api/': {
      target: 'http://localhost:5180',
      changeOrigin: true,
    },
  },
  /**
   * @name 详细的代理配置
   * @doc https://github.com/chimurai/http-proxy-middleware
   */
  test: {
    // 测试环境示例：localhost:8000/api/** -> https://api.example.com/api/**
    // 实际联调地址按部署环境填写，勿指向第三方演示服务。
    '/api/': {
      target: 'https://api.example.com',
      changeOrigin: true,
    },
  },
  pre: {
    // 预发布环境示例，实际域名按部署环境填写。
    '/api/': {
      target: 'https://api.example.com',
      changeOrigin: true,
    },
  },
};
