FROM verdaccio/verdaccio:5.8.0
USER root
RUN yarn add verdaccio-ldap5
USER verdaccio