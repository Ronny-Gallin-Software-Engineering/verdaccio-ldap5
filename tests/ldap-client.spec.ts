import { Config, PackageAccess, PluginOptions, Security } from '@verdaccio/types';
import { spawn } from 'child_process';
import { Options } from 'ldapauth-fork';
import AuthCustomPlugin, { CachableUserGroups } from '../src';
import { logger, userName, group, createTestee, options } from './test-commons';

let server;
let auth: AuthCustomPlugin;

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
        auth = createTestee();
      });

      describe('tests without cache', () => {
    
        beforeEach(() => {
            auth = createTestee();
        });

        it('should match user', done => {
          auth.authenticate(userName, 'password', (err, results) => {
            expect(err).toBeNull();
            logger.info(results);
            expect(results[0]).toEqual(userName);
            expect(results[1]).toEqual(group);
            done();
          });
        });
      });
    
      describe('tests with cache', () => {
        beforeEach(() => {
          auth = createTestee(true);
        });
    
        it('should use cache', done => {
          auth.authenticate(userName, 'password', (err, results) => {
            expect(err).toBeNull();
            expect((results as CachableUserGroups).cacheHit).toBeFalsy();
            expect(results[0]).toEqual(userName);
    
            auth.authenticate(userName, 'password', (err, results) => {
              expect(err).toBeNull();
              expect(results).toBeTruthy();
              expect((results as CachableUserGroups).cacheHit).toBeTruthy();
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