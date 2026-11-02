// Test harness: wires the typed API client to the contract mock through msw/node.
import { createApiClient, __setApiForTests } from '../api/client';
import { createMockBackend, mswFetch } from '../../mocks/msw';
import type { MockBackend } from '../../mocks/core';
import { resetWorld } from './helpers';

export const TEST_BASE = 'https://api.test';

export function setupMockApi(): { backend: MockBackend } {
  const backend = createMockBackend();
  beforeEach(() => {
    backend.reset();
    resetWorld();
    __setApiForTests(createApiClient(TEST_BASE, true, mswFetch(backend)));
  });
  afterAll(() => {
    __setApiForTests(undefined);
  });
  return { backend };
}
