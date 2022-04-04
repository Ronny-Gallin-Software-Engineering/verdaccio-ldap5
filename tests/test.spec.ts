import { PackageAccess, PluginOptions, Security, RemoteUser } from '@verdaccio/types';
import { Config } from '@verdaccio/types';
import { Options } from 'ldapauth-fork';
import * as bunyan from 'bunyan';

import AuthCustomPlugin from '../src/index';

import 'ts-jest';
import { spawn } from 'child_process';

const userName = 'testee';

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

const logger = bunyan.createLogger({ name: `${AuthCustomPlugin.LOGGING_PREFIX}`, level: 'info' });

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
  uplinks: {},
  self_path: '',
  packages: {},
  security,
  checkSecretKey(token: string): string {
    return token;
  },
  getMatchedPackagesSpec(storage: string): PackageAccess | void {},
};

const options: PluginOptions<Config> = {
  config,
  logger,
};

let auth: AuthCustomPlugin;
let server;

describe('ldap auth', () => {
  beforeAll(done => {
    server = spawn(
      'node',
      [
        'node_modules/ldap-server-mock/server.js',
        '--conf=./tests/ldap-server-mock-conf.json',
        '--database=./tests/users.json',
      ],
      {
        stdio: ['ipc'],
      }
    );

    server.stdout.on('data', d => logger.info(`${d}`));
    server.stderr.on('error', d => logger.error(`${d}`));

    server.on('message', message => {
      if (message.status === 'started') {
        logger.info('ldap-server up');
        done();
      }
    });
  });

  afterAll(done => {
    server.kill('SIGTERM');
    done();
  });

  beforeEach(() => {
    jest.setTimeout(5000);
  });

  describe('tests without cache', () => {
    const user: RemoteUser = {
      real_groups: [],
      groups: [],
      name: 'Testuser'
    };

    const pgk: PackageAccess = {};

    beforeEach(() => {
      auth = new AuthCustomPlugin(config, options);
    });

    it('should match user', done => {
      auth.authenticate(userName, 'password', (err, results) => {
        expect(err).toBeNull();
        expect(results[0]).toEqual(userName);
        done();
      });
    });

    test('is allowed to publish', done => {
      auth.allow_publish(user, pgk, (error, result) => {
        expect(error).toBeNull();
        expect(result).toBe(true);
        done();
      });
    });

    test('is allowed to unpublish', done => {
      auth.allow_unpublish(user, pgk, (error, result) => {
        expect(error).toBeNull();
        expect(result).toBe(true);
        done();
      });
    });

    test('is allowed to access', done => {
      auth.allow_access(user, pgk, (error, result) => {
        expect(error).toBeNull();
        expect(result).toBe(true);
        done();
      });
    });
  });

  describe('tests with cache', () => {
    beforeEach(() => {
      auth = new AuthCustomPlugin(
        {
          ...config,
          cache: true,
        },
        options
      );
    });

    jest.setTimeout(15000);

    it('should use cache', done => {
      auth.authenticate(userName, 'password', (err, results) => {
        expect(err).toBeNull();
        expect(results.cacheHit).toBeFalsy();
        expect(results[0]).toEqual(userName);

        auth.authenticate(userName, 'password', (err, results) => {
          expect(err).toBeNull();
          expect(results).toBeTruthy();
          logger.info(results);
          expect(results.cacheHit).toBeTruthy();
          expect(results[0]).toEqual(userName);

          done();
        });
      });
    });

    it('should return false and set cache', done => {
      const user = 'wronguser';
      const password = 'password';
      const hash = auth.getHashByPasswordOrLogError(user, password);
      const key = user + hash;

      expect(auth.userCache.getItem(key)).toBeTruthy();
      auth.authenticate(user, password, (err, results) => {
        expect(err).toBeTruthy();
        expect(results).toBeFalsy();
        expect(auth.userCache.getItem(key)).toBeDefined();
        done();
      });
    });
  });

  describe('test admin password', () => {
    let config;
    const password = '1234';
    beforeEach(() => {
      config = {
        cache: true,
        client_options: {
          url: 'ldap://localhost:4389',
          searchBase: 'o=rgse',
          searchFilter: '(cn={{username}})',
          groupDnProperty: 'cn',
          groupSearchBase: 'o=rgse',
          // If you have memberOf:
          searchAttributes: ['*', 'memberOf'],
          // Else, if you don't:
          // groupSearchFilter: '(memberUid={{dn}})',
        },
      };
    });

    it('should read password from config', done => {
      config.client_options.adminPassword = password;
      auth = new AuthCustomPlugin(config, options);
      expect(auth.config.client_options.adminPassword).toEqual(password);
      done();
    });

    it('should read password from env if exist', function(done) {
      process.env.LDAP_ADMIN_PASS = password;
      auth = new AuthCustomPlugin(config, options);
      expect(auth.config.client_options.adminPassword).toEqual(password);
      done();
    });

    it('should override password from env if exist', function(done) {
      config.client_options.adminPassword = 'asdf';
      process.env.LDAP_ADMIN_PASS = password;
      auth = new AuthCustomPlugin(config, options);
      expect(auth.config.client_options.adminPassword).toEqual(password);
      done();
    });
  });
});
