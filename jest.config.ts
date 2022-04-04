import type { Config } from '@jest/types';
// Sync object
const config: Config.InitialOptions = {
  name: 'verdaccio-<%= name %>',
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx'],
  modulePathIgnorePatterns: ['lib/'],
  transform: {
    '^.+\\.(js|jsx|ts|tsx)$': 'babel-jest',
  },
  verbose: true,
  collectCoverage: true,
  coveragePathIgnorePatterns: ['node_modules'],
};
export default config;
