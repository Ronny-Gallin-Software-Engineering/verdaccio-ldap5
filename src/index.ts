import {
  AuthAccessCallback,
  AuthCallback,
  Config,
  IPluginAuth,
  Logger,
  PackageAccess,
  PluginOptions,
  RemoteUser,
} from '@verdaccio/types';
import LdapAuth from 'ldapauth-fork';
import bcrypt from 'bcryptjs';
import rfc2253 from 'rfc2253';
import { CacheContainer } from 'node-ts-cache';
import { MemoryStorage } from 'node-ts-cache-storage-memory';
import { getInternalError } from '@verdaccio/commons-api';

const LDAP_ADMIN_PASS_ENV = 'LDAP_ADMIN_PASS';

/**
 * Custom Verdaccio Authenticate Plugin.
 */
export default class AuthCustomPlugin implements IPluginAuth<Config> {

  public static readonly LOGGING_PREFIX = 'verdaccio-ldap5';

  public logger: Logger;
  public userCache?: CacheContainer;
  public users = {};
  private salt = 10;
  private expire = 0;

  public constructor(public config: Config, options: PluginOptions<Config>) {
    this.logger = options.logger;

    // pass verdaccio logger to ldapauth
    this.config.client_options.log = this.logger;

    // always set ldapauth cache false
    this.config.client_options.cache = false;

    // TODO: Set more defaults
    this.config.groupNameAttribute = this.config.groupNameAttribute || 'cn';

    if (config.cache) {
      this.expire = typeof config.cache.expire === 'number' ? config.cache.expire : 300;
      this.userCache = new CacheContainer(new MemoryStorage());
    }

    if (LDAP_ADMIN_PASS_ENV in process.env) {
      this.config.client_options.adminPassword = process.env[LDAP_ADMIN_PASS_ENV];
    }

    return this;
  }

  /**
   * Authenticate an user.
   * @param username user to log
   * @param password provided password
   * @param callback callback function
   */
  public authenticate(username: string, password: string, callback: AuthCallback): void {
    const hash = this.getHashByPasswordOrLogError(username, password);

    if (this.config.cache) {
      this.readFromCache(username, password, hash, callback);
    } else {
      this.loadUser(username, password, hash, callback);
    }
  }

  /**
   * Triggered on each access request
   * @param user
   * @param pkg
   * @param cb
   */
  public allow_access(user: RemoteUser, pkg: PackageAccess, cb: AuthAccessCallback): void {
    cb(null, this.allow(user, pkg.access));
  }

  /**
   * Triggered on each publish request
   * @param user
   * @param pkg
   * @param cb
   */
  public allow_publish(user: RemoteUser, pkg: PackageAccess, cb: AuthAccessCallback): void {
    cb(null, this.allow(user, pkg.publish));
  }

  public allow_unpublish(user: RemoteUser, pkg: PackageAccess, cb: AuthAccessCallback): void {
    cb(null, this.allow(user, pkg['unpublish']));
  }

  public getHashByPasswordOrLogError(username: string, password: string): string {
    try {
      return bcrypt.hashSync(password, this.salt);
    } catch (err) {
      this.logger.warn({ username, err }, `${AuthCustomPlugin.LOGGING_PREFIX} bcrypt hash error ${err}`);
      return '';
    }
  }

  private allow(user: RemoteUser, required: string[] | undefined): boolean {
    return required ? required.some(accessValue => user.groups.indexOf(accessValue) >= 0) : true;
  }

  private authenticatedUserGroups(user: any, groupNameAttribute: string): CachableUserGroups {
    return [
      user.cn,
      // _groups or memberOf could be single els or arrays.
      ...(user._groups ? [].concat(user._groups).map(group => group[groupNameAttribute]) : []),
      ...(user.memberOf ? [].concat(user.memberOf).map(groupDn => rfc2253.parse(groupDn).get('CN')) : []),
    ] as CachableUserGroups;
  }

  private readFromCache(username: string, password: string, hash: string, callback: AuthCallback) {
    this.logger.debug(`using cache for ${username}`);
    // @ts-ignore
    this.fromCache(username)
      .then(cached => {
        this.logger.debug('cache result: ' + JSON.stringify(cached));
        if (cached) {
          cached.cacheHit = false;
          if (cached.error) {
            this.logger.error(cached.error);
            return callback(getInternalError(cached.error.message), false);

          } else if (cached.password && bcrypt.compareSync(password, cached.password)) {
            const userGroups = this.authenticatedUserGroups(cached.user, this.config.groupNameAttribute);
            userGroups.cacheHit = true;
            callback(null, userGroups);
          
          } else {
            this.logger.debug(`cache found but pw doesnt match: ${cached.password}, ${hash}`);
            callback(null, false);
          }
        } else {
          this.loadUser(username, password, hash, callback);
        }
      })
      .catch(err => {
        this.logger.error(err);
        callback(getInternalError(err), false);
      });
  }

  private loadUser(username: string, password: string, hash: string, callback: AuthCallback) {
    this.logger.debug(`loading user ${username}`);
    // ldap client
    const ldapClient = new LdapAuth(this.config.client_options);
    ldapClient.on('error', err => {
      this.logger.error({ username, err }, `${AuthCustomPlugin.LOGGING_PREFIX} error ${err}`);
    });

    let currentUser: any;
    let currentError: Error|string;

    ldapClient.authenticate(username, password, (error, result) => {
      this.logger.debug('ldap auth response: error: ' + JSON.stringify(error) + ', result: ' + JSON.stringify(result));
      this.shutdown(ldapClient);

      if (error) {
        currentError = error;
        const message = (error as Error).message ? (error as Error).message : (error as string);
        callback(getInternalError(message), false);

      } else if (result) {
        currentUser = result;
        const groups = this.authenticatedUserGroups(result, this.config.groupNameAttribute);
        if (this.config.cache) {
          this.toCache(username, hash, currentUser, currentError);
        }
        callback(null, groups);

      } else {
        callback(null, false);
      }
    });
  }

  private shutdown(ldapClient: LdapAuth) {
    ldapClient.close(err => {
      if(err) {
        this.logger.error(`error closing ldapAuth: ${err}`);
      }
    });
  }

  private toCache(username: string, hash: string, currentUser: any, currentError: any) {
    this.logger.debug(`caching user ${username}`);
    // @ts-ignore
    this.userCache.setItem(
      username,
      {
        password: hash,
        user: currentUser,
        error: currentError,
      },
      { ttl: this.expire }
    );
  }

  private fromCache(username: string): Promise<CachedUser | undefined> {
    this.logger.debug(`loading from cache: ${username}`);
    // @ts-ignore
    return this.userCache.getItem<CachedUser>(username);
  }
}

type CachedUser = { password: string; user: RemoteUser; error: Error; cacheHit: boolean };


export class CachableUserGroups extends Array<string> {
  cacheHit = false;
}

