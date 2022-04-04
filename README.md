# verdaccio-ldap5

> a port of the verdaccio-ldap to version 5
> See  [verdaccio-ldap](https://github.com/Alexandre-io/verdaccio-ldap)

---

## Installation

```sh
$ npm install verdaccio
$ npm install verdaccio-ldap5
```

## Config

Add to your `config.yaml`:

```yaml
auth:
  ldap5:
    type: ldap
    # Only required if you are fetching groups that do not have a "cn" property. defaults to "cn"
    groupNameAttribute: "ou"
    # Optional, default false.
    cache:
      # max credentials to cache (default to 100 if cache is enabled)
      size: 100
      # cache expiration in seconds (default to 300 if cache is enabled)
      expire: 300
    client_options:
      url: "ldap://ldap.example.com"
      # Only required if you need auth to bind
      adminDn: "cn=admin,dc=example,dc=com"
      adminPassword: "admin"
      # Search base for users
      searchBase: "ou=People,dc=example,dc=com"
      searchFilter: "(uid={{username}})"
      # If you are using groups, this is also needed
      groupDnProperty: 'cn'
      groupSearchBase: 'ou=groups,dc=myorg,dc=com'
      # If you have memberOf support on your ldap
      searchAttributes: ['*', 'memberOf']
      # Else, if you don't (use one or the other):
      # groupSearchFilter: '(memberUid={{dn}})'
      # Optional
      reconnect: true
```

### LDAP Admin Password
If you run this plugin in k8s, you may want to set password by env with secretRef.
You can use `LDAP_ADMIN_PASS` to set ldap admin password, it will override the one in `config.yaml`.

## For plugin writers

It's called as:

```js
require('verdaccio-ldap5')(config, stuff)
```

Where:

 - config - module's own config
 - stuff - collection of different internal verdaccio objects
   - stuff.config - main config
   - stuff.logger - logger

This should export two functions:

 - `adduser(user, password, cb)`

   It should respond with:
    - `cb(err)` in case of an error (error will be returned to user)
    - `cb(null, false)` in case registration is disabled (next auth plugin will be executed)
    - `cb(null, true)` in case user registered successfully

   It's useful to set `err.status` property to set http status code (e.g. `err.status = 403`).

 - `authenticate(user, password, cb)`

   It should respond with:
    - `cb(err)` in case of a fatal error (error will be returned to user, keep those rare)
    - `cb(null, false)` in case user not authenticated (next auth plugin will be executed)
    - `cb(null, [groups])` in case user is authenticated

   Groups is an array of all users/usergroups this user has access to. You should probably include username itself here.
