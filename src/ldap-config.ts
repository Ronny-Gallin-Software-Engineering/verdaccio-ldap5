import { Config, Logger } from '@verdaccio/types';

export interface LdapConfig extends Config {
  groupNameAttribute?: string;
  client_options: LdapClientOptions;
  cache: CacheOptions;
}

export interface LdapClientOptions {
  log: Logger;
  cache: boolean;
  adminPassword: string;
}

export interface CacheOptions {
  expire: number;
}
