import { RemoteUser } from '@verdaccio/types';
import 'ts-jest';

import AuthCustomPlugin from '../src/index';
import { createTestee } from './test-commons';

let auth: AuthCustomPlugin;

describe('tests about access control', () => {

  beforeEach(() => {
    auth = createTestee();
  });

  const testee: RemoteUser = {
    real_groups: [],
    groups: ['Testuser'],
    name: 'Testuser'
  };

  const testee1: RemoteUser = {
    name: 'testee1',
    groups: ['testee1'],
    real_groups: []
  };

  const testee2: RemoteUser = {
    name: 'testee2',
    groups: ['testee2', 'testeegroup'],
    real_groups: []
  };

  const pgk: any = {
    access: ['Testuser', 'testeegroup'],
    publish: ['Testuser', 'testeegroup'],
    unpublish: ['Testuser', 'testeegroup']
  };

  test('is allowed to publish', done => {
    auth.allow_publish(testee, pgk, (error, result) => {
      expect(error).toBeNull();
      expect(result).toBe(true);
      done();
    });
  });

  test('is allowed to unpublish', done => {
    auth.allow_unpublish(testee, pgk, (error, result) => {
      expect(error).toBeNull();
      expect(result).toBe(true);
      done();
    });
  });

  test('is allowed to access', done => {
    auth.allow_access(testee, pgk, (error, result) => {
      expect(error).toBeNull();
      expect(result).toBe(true);
      done();
    });
  });

  test('is not allowed to access', done => {
    auth.allow_access(testee1, pgk, (error, result) => {
      expect(error).toBeNull();
      expect(result).toBe(false);
      done();
    });
  });

  test('is not allowed to publish', done => {
    auth.allow_publish(testee1, pgk, (error, result) => {
      expect(error).toBeNull();
      expect(result).toBe(false);
      done();
    });
  });

  test('is not allowed to unpublish', done => {
    auth.allow_unpublish(testee1, pgk, (error, result) => {
      expect(error).toBeNull();
      expect(result).toBe(false);
      done();
    });
  });

  test('is allowed to publish by group', done => {
    auth.allow_publish(testee2, pgk, (error, result) => {
      expect(error).toBeNull();
      expect(result).toBe(true);
      done();
    });
  });

  test('is allowed to access by group', done => {
    auth.allow_access(testee2, pgk, (error, result) => {
      expect(error).toBeNull();
      expect(result).toBe(true);
      done();
    });
  });
});
