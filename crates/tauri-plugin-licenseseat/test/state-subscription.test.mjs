import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';

import { emit } from '@tauri-apps/api/event';
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';

import {
  LICENSESEAT_EVENTS,
  LICENSESEAT_STATE_EVENTS,
  LicenseSeatPluginError,
  activateAndGetState,
  subscribeState,
} from '../dist/index.js';

globalThis.window = globalThis;

const delay = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

function state(sequence) {
  return {
    status: { status: 'active' },
    clientStatus: 'active',
    isOnline: true,
    fingerprint: `installation-${sequence}`,
    entitlements: [],
    isActivated: true,
    isValid: true,
    isOffline: false,
  };
}

function completion(expected) {
  let count = 0;
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return {
    mark() {
      count += 1;
      if (count === expected) resolve();
    },
    promise,
  };
}

async function within(promise, milliseconds = 1_000) {
  return Promise.race([
    promise,
    delay(milliseconds).then(() => {
      throw new Error('timed out waiting for state subscription delivery');
    }),
  ]);
}

afterEach(() => {
  clearMocks();
});

test('default state subscriptions refresh after heartbeat grant changes', () => {
  assert.ok(
    LICENSESEAT_STATE_EVENTS.includes(LICENSESEAT_EVENTS.HEARTBEAT_SUCCESS),
  );
});

test('activateAndGetState does not perform a redundant validation request', async () => {
  const commands = [];
  mockIPC((command) => {
    commands.push(command);
    if (command === 'plugin:licenseseat|activate') {
      return {
        licenseKey: 'LICENSE-KEY',
        deviceId: 'installation-1',
        activationId: 'activation-1',
        activatedAt: '2026-07-14T00:00:00Z',
      };
    }
    if (command === 'plugin:licenseseat|get_state') return state(1);
    return undefined;
  });

  const snapshot = await activateAndGetState('LICENSE-KEY');

  assert.equal(snapshot.fingerprint, 'installation-1');
  assert.deepEqual(commands, [
    'plugin:licenseseat|activate',
    'plugin:licenseseat|get_state',
  ]);
});

test('subscribeState de-duplicates repeated event registrations', async () => {
  let reads = 0;
  mockIPC(
    (command) => {
      if (command === 'plugin:licenseseat|get_state') return state(++reads);
      return undefined;
    },
    { shouldMockEvents: true },
  );

  const delivered = [];
  const done = completion(1);
  const unsubscribe = await subscribeState(
    ({ state: snapshot }) => {
      delivered.push(snapshot.fingerprint);
      done.mark();
    },
    {
      events: [
        LICENSESEAT_EVENTS.LICENSE_STATE_CHANGED,
        LICENSESEAT_EVENTS.LICENSE_STATE_CHANGED,
      ],
    },
  );

  await emit(LICENSESEAT_EVENTS.LICENSE_STATE_CHANGED, null);
  await within(done.promise);
  await delay(20);

  assert.deepEqual(delivered, ['installation-1']);
  await unsubscribe();
});

test('subscribeState serializes state reads and async listener delivery', async () => {
  let stateSequence = 0;
  let activeStateReads = 0;
  let maxStateReads = 0;
  mockIPC(
    async (command) => {
      if (command !== 'plugin:licenseseat|get_state') return undefined;
      const sequence = ++stateSequence;
      activeStateReads += 1;
      maxStateReads = Math.max(maxStateReads, activeStateReads);
      await delay(sequence === 1 ? 40 : 1);
      activeStateReads -= 1;
      return state(sequence);
    },
    { shouldMockEvents: true },
  );

  const delivered = [];
  let activeListeners = 0;
  let maxListeners = 0;
  const done = completion(2);
  const unsubscribe = await subscribeState(
    async ({ state: snapshot }) => {
      activeListeners += 1;
      maxListeners = Math.max(maxListeners, activeListeners);
      await delay(10);
      delivered.push(snapshot.fingerprint);
      activeListeners -= 1;
      done.mark();
    },
    { events: [LICENSESEAT_EVENTS.VALIDATION_SUCCESS] },
  );

  await emit(LICENSESEAT_EVENTS.VALIDATION_SUCCESS, { sequence: 1 });
  await emit(LICENSESEAT_EVENTS.VALIDATION_SUCCESS, { sequence: 2 });
  await within(done.promise);

  assert.deepEqual(delivered, ['installation-1', 'installation-2']);
  assert.equal(maxStateReads, 1);
  assert.equal(maxListeners, 1);
  await unsubscribe();
});

test('subscribeState reports one handler failure and continues delivering', async () => {
  let stateSequence = 0;
  mockIPC(
    (command) => {
      if (command === 'plugin:licenseseat|get_state') {
        return state(++stateSequence);
      }
      return undefined;
    },
    { shouldMockEvents: true },
  );

  const errors = [];
  const delivered = [];
  const done = completion(1);
  const unsubscribe = await subscribeState(
    ({ state: snapshot }) => {
      if (snapshot.fingerprint === 'installation-1') {
        throw new Error('renderer handler failed');
      }
      delivered.push(snapshot.fingerprint);
      done.mark();
    },
    {
      events: [LICENSESEAT_EVENTS.VALIDATION_SUCCESS],
      onError: (error) => errors.push(error),
    },
  );

  await emit(LICENSESEAT_EVENTS.VALIDATION_SUCCESS, null);
  await emit(LICENSESEAT_EVENTS.VALIDATION_SUCCESS, null);
  await within(done.promise);

  assert.deepEqual(delivered, ['installation-2']);
  assert.equal(errors.length, 1);
  assert.ok(errors[0] instanceof LicenseSeatPluginError);
  assert.match(errors[0].message, /renderer handler failed/);
  await unsubscribe();
});

test('unsubscribe suppresses queued delivery and drains before resolving', async () => {
  let stateSequence = 0;
  let releaseStateRead;
  let markStateReadStarted;
  const stateReadStarted = new Promise((resolve) => {
    markStateReadStarted = resolve;
  });
  const stateReadReleased = new Promise((resolve) => {
    releaseStateRead = resolve;
  });
  mockIPC(
    async (command) => {
      if (command === 'plugin:licenseseat|get_state') {
        stateSequence += 1;
        markStateReadStarted();
        await stateReadReleased;
        return state(stateSequence);
      }
      return undefined;
    },
    { shouldMockEvents: true },
  );

  const delivered = [];
  const unsubscribe = await subscribeState(
    ({ state: snapshot }) => {
      delivered.push(snapshot.fingerprint);
    },
    { events: [LICENSESEAT_EVENTS.VALIDATION_SUCCESS] },
  );

  await emit(LICENSESEAT_EVENTS.VALIDATION_SUCCESS, null);
  await emit(LICENSESEAT_EVENTS.VALIDATION_SUCCESS, null);
  await within(stateReadStarted);
  const stopped = unsubscribe();
  releaseStateRead();
  await stopped;

  assert.deepEqual(delivered, []);
  assert.equal(stateSequence, 1);
});
