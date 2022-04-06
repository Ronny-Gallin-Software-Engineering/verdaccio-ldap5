import AuthCustomPlugin from '../src/index';
import * as bunyan from 'bunyan';
import { Options } from 'ldapauth-fork';
import { Config, PackageAccess, PluginOptions, Security } from '@verdaccio/types';

export const logger = bunyan.createLogger({ name: `${AuthCustomPlugin.LOGGING_PREFIX}`, level: 'info' });

export const userName = 'testee';
export const group = 'testeegroup';

export function createTestee(doCache?: boolean): AuthCustomPlugin {
    return new AuthCustomPlugin({
        ...config,
        cache: doCache ? doCache : false,
      }, options);
}

const client_options: Options = {
    url: 'ldap://127.0.0.1:4389',
    searchBase: 'o=rgse',
    searchFilter: '(cn={{username}})',
    groupDnProperty: 'cn',
    groupSearchBase: 'o=rgse',
    // If you have memberOf:
    searchAttributes: ['*', 'memberOf'],
    // Else, if you don't:
    // groupSearchFilter: '(memberUid={{dn}})',
  };
  
  const security: Security = {
    web: {
      sign: {},
      verify: {},
    },
    api: {
      jwt: {
        sign: {},
        verify: {},
      },
      legacy: false,
    },
  };
  
  const config: Config = {
    client_options,
    user_agent: '',
    server_id: '',
    secret: '',
    userRateLimit: {},
    uplinks: {},
    self_path: '',
    packages: {},
    security,
    checkSecretKey(token: string): string {
      return token;
    },
    getMatchedPackagesSpec(storage: string): PackageAccess | void {},
  };
  
  export const options: PluginOptions<Config> = {
    config,
    logger,
  };