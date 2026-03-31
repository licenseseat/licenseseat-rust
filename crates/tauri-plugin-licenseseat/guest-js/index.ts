/**
 * LicenseSeat Tauri Plugin - TypeScript Bindings
 *
 * @module @licenseseat/tauri-plugin
 *
 * @example
 * ```typescript
 * import { activate, getStatus, hasEntitlement } from '@licenseseat/tauri-plugin';
 *
 * // Activate a license
 * const license = await activate('YOUR-LICENSE-KEY');
 *
 * // Check status
 * const status = await getStatus();
 * console.log(status.status); // 'active' | 'inactive' | 'invalid' | ...
 *
 * // Check entitlements
 * if (await hasEntitlement('pro-features')) {
 *   // Enable pro features
 * }
 * ```
 */

import { invoke } from '@tauri-apps/api/core';
import { listen, type Event, type UnlistenFn } from '@tauri-apps/api/event';

// ============================================================================
// Types
// ============================================================================

/** License activation response */
export interface License {
  licenseKey: string;
  deviceId: string;
  activationId: string;
  activatedAt: string;
}

/** License status response */
export interface LicenseStatus {
  status: 'active' | 'inactive' | 'invalid' | 'pending' | 'offline_valid' | 'offline_invalid';
  message?: string;
  license?: string;
  device?: string;
  activatedAt?: string;
  lastValidated?: string;
}

/** Entitlement check response */
export interface EntitlementStatus {
  active: boolean;
  reason?: 'nolicense' | 'notfound' | 'expired';
  expiresAt?: string;
}

/** Active entitlement record */
export interface Entitlement {
  key: string;
  expiresAt?: string;
  metadata?: Record<string, unknown>;
}

/** Activation options */
export interface ActivationOptions {
  fingerprint?: string;
  deviceId?: string;
  deviceFingerprint?: string;
  deviceName?: string;
  metadata?: Record<string, unknown>;
}

/** Validation result from the API */
export interface ValidationResult {
  object: string;
  valid: boolean;
  code?: string;
  message?: string;
  warnings?: Array<{
    code: string;
    message: string;
  }>;
  license: {
    object: string;
    key: string;
    status: string;
    startsAt?: string;
    expiresAt?: string;
    mode: string;
    planKey: string;
    seatLimit?: number;
    activeSeats: number;
    activeEntitlements: Entitlement[];
    metadata?: Record<string, unknown>;
    product: {
      slug: string;
      name: string;
    };
  };
  activation?: {
    object: string;
    id: string;
    deviceId: string;
    deviceName?: string;
    licenseKey: string;
    activatedAt: string;
    deactivatedAt?: string;
    ipAddress?: string;
    metadata?: Record<string, unknown>;
  };
  offline: boolean;
}

/** Release metadata */
export interface Release {
  object: string;
  version: string;
  channel: string;
  platform: string;
  productSlug: string;
  publishedAt?: string;
}

/** Paginated release list */
export interface ReleaseList {
  object: string;
  data: Release[];
  hasMore: boolean;
  nextCursor?: string;
}

/** Release listing options */
export interface ReleaseListOptions {
  channel?: string;
  platform?: string;
  limit?: number;
}

/** Download token */
export interface DownloadToken {
  object: string;
  token: string;
  expiresAt?: string;
}

/** Machine-file metadata */
export interface MachineFile {
  certificate: string;
  algorithm: string;
  ttl: number;
  issuedAt?: string;
  expiresAt?: string;
  licenseKey: string;
  fingerprint: string;
}

/** Legacy offline entitlement */
export interface OfflineEntitlement {
  key: string;
  expiresAt?: number;
}

/** Legacy offline token payload */
export interface OfflineTokenPayload {
  schemaVersion: number;
  licenseKey: string;
  productSlug: string;
  planKey: string;
  mode: string;
  seatLimit?: number;
  deviceId?: string;
  iat: number;
  exp: number;
  nbf: number;
  licenseExpiresAt?: number;
  kid: string;
  entitlements: OfflineEntitlement[];
  metadata?: Record<string, unknown>;
}

/** Legacy offline token signature */
export interface OfflineTokenSignature {
  algorithm: string;
  keyId: string;
  value: string;
}

/** Legacy offline token */
export interface OfflineToken {
  object: string;
  token: OfflineTokenPayload;
  signature: OfflineTokenSignature;
  canonical: string;
}

/** Machine-file checkout options */
export interface MachineFileCheckoutOptions {
  fingerprint?: string;
  deviceId?: string;
  deviceFingerprint?: string;
  ttlDays?: number;
  gracePeriodDays?: number;
  includeLicense?: boolean;
  fingerprintComponents?: Record<string, string>;
}

/** Manual machine-file verification options */
export interface MachineFileVerificationOptions {
  publicKeyB64?: string;
  licenseKey?: string;
  fingerprint?: string;
}

/** Decrypted machine-file payload */
export interface MachineFilePayload {
  schemaVersion: number;
  issued: string;
  iat: number;
  expiry: string;
  exp: number;
  nbf: number;
  ttl: number;
  gracePeriod: number;
  licenseKey: string;
  licenseExpiresAt?: number;
  keyId: string;
  sdkVersion?: string;
  machineId: string;
  fingerprint: string;
  fingerprintComponents: Record<string, string>;
  deviceName: string;
  platform: string;
  createdAt?: string;
  metadata: Record<string, unknown>;
  license?: ValidationResult['license'];
}

/** Result of machine-file verification */
export interface MachineFileVerificationResult {
  valid: boolean;
  code?: string;
  message?: string;
  payload?: MachineFilePayload;
}

/** Restore result */
export interface RestoreResult {
  restored: boolean;
  status: LicenseStatus;
  license?: License;
  validation?: ValidationResult;
  error?: string;
}

/** Stable client-status string */
export type ClientStatusValue = LicenseStatus['status'];

/** Aggregated plugin state snapshot */
export interface LicenseSeatState {
  status: LicenseStatus;
  clientStatus: ClientStatusValue;
  isOnline: boolean;
  fingerprint: string;
  license?: License;
  validation?: ValidationResult;
  entitlements: Entitlement[];
  planKey?: string;
  licenseMode?: string;
  isActivated: boolean;
  isValid: boolean;
  isOffline: boolean;
}

export interface HeartbeatRecord {
  object: string;
  receivedAt: string;
  license: ValidationResult['license'];
}

export interface HealthRecord {
  object: string;
  status: string;
  apiVersion: string;
  timestamp: string;
}

export interface SigningKeyRecord {
  object: string;
  keyId: string;
  algorithm: string;
  publicKey: string;
  createdAt?: string;
  status: string;
}

export interface LicenseSeatAdminConfig {
  apiBaseUrl: string;
  apiKey: string;
  productSlug: string;
  storagePrefix: string;
  storagePath?: string;
  deviceIdentifier?: string;
  signingPublicKey?: string;
  signingKeyId?: string;
  autoValidateIntervalSeconds: number;
  heartbeatIntervalSeconds: number;
  networkRecheckIntervalSeconds: number;
  requestTimeoutSeconds: number;
  verifySsl: boolean;
  offlineFallbackMode: string;
  offlineTokenRefreshIntervalSeconds: number;
  enableLegacyOfflineTokens: boolean;
  maxOfflineDays: number;
  telemetryEnabled: boolean;
  debug: boolean;
  appVersion?: string;
  appBuild?: string;
}

export interface LicenseSeatAdminCachePaths {
  cacheDir?: string;
  licensePath?: string;
  machineFilePath?: string;
  offlineTokenPath?: string;
  lastSeenTimestampPath?: string;
  signingKeyPath?: string;
}

export interface LicenseSeatAdminRuntime {
  isAutoValidating: boolean;
  isHeartbeatRunning: boolean;
  nextAutoValidationAt?: string;
  lastSeenTimestamp?: number;
  lastHeartbeat?: HeartbeatRecord;
  lastHeartbeatError?: string;
  lastHealth?: HealthRecord;
  lastHealthError?: string;
}

export interface LicenseSeatAdminSnapshot {
  capturedAt: string;
  config: LicenseSeatAdminConfig;
  cachePaths: LicenseSeatAdminCachePaths;
  state: LicenseSeatState;
  runtime: LicenseSeatAdminRuntime;
  signingKeyId?: string;
  offlineToken?: OfflineToken;
  machineFile?: MachineFile;
  machineFileVerification?: MachineFileVerificationResult;
  signingKey?: SigningKeyRecord;
}

/** Event payloads emitted by the Tauri plugin */
export type LicenseSeatEventPayload = License | ValidationResult | string | null;

/** Stable Tauri event names emitted by the plugin */
export const LICENSESEAT_EVENTS = {
  ACTIVATION_START: 'licenseseat://activation-start',
  ACTIVATION_SUCCESS: 'licenseseat://activation-success',
  ACTIVATION_ERROR: 'licenseseat://activation-error',
  VALIDATION_START: 'licenseseat://validation-start',
  VALIDATION_SUCCESS: 'licenseseat://validation-success',
  VALIDATION_FAILED: 'licenseseat://validation-failed',
  VALIDATION_ERROR: 'licenseseat://validation-error',
  VALIDATION_OFFLINE_SUCCESS: 'licenseseat://validation-offline-success',
  VALIDATION_OFFLINE_FAILED: 'licenseseat://validation-offline-failed',
  VALIDATION_AUTH_FAILED: 'licenseseat://validation-auth-failed',
  VALIDATION_AUTO_FAILED: 'licenseseat://validation-auto-failed',
  DEACTIVATION_START: 'licenseseat://deactivation-start',
  DEACTIVATION_SUCCESS: 'licenseseat://deactivation-success',
  DEACTIVATION_ERROR: 'licenseseat://deactivation-error',
  HEARTBEAT_SUCCESS: 'licenseseat://heartbeat-success',
  HEARTBEAT_ERROR: 'licenseseat://heartbeat-error',
  LICENSE_LOADED: 'licenseseat://license-loaded',
  LICENSE_REVOKED: 'licenseseat://license-revoked',
  OFFLINE_TOKEN_FETCHING: 'licenseseat://offlineToken-fetching',
  OFFLINE_TOKEN_FETCHED: 'licenseseat://offlineToken-fetched',
  OFFLINE_TOKEN_FETCH_ERROR: 'licenseseat://offlineToken-fetchError',
  OFFLINE_TOKEN_READY: 'licenseseat://offlineToken-ready',
  OFFLINE_TOKEN_VERIFIED: 'licenseseat://offlineToken-verified',
  OFFLINE_TOKEN_VERIFICATION_FAILED: 'licenseseat://offlineToken-verificationFailed',
  MACHINE_FILE_FETCHING: 'licenseseat://machineFile-fetching',
  MACHINE_FILE_FETCHED: 'licenseseat://machineFile-fetched',
  MACHINE_FILE_FETCH_ERROR: 'licenseseat://machineFile-fetchError',
  MACHINE_FILE_READY: 'licenseseat://machineFile-ready',
  MACHINE_FILE_VERIFIED: 'licenseseat://machineFile-verified',
  MACHINE_FILE_VERIFICATION_FAILED: 'licenseseat://machineFile-verificationFailed',
  OFFLINE_VALIDATION_START: 'licenseseat://offlineValidation-start',
  OFFLINE_VALIDATION_SUCCESS: 'licenseseat://offlineValidation-success',
  OFFLINE_VALIDATION_FAILED: 'licenseseat://offlineValidation-failed',
  OFFLINE_ASSETS_REFRESHED: 'licenseseat://offlineAssets-refreshed',
  AUTO_VALIDATION_CYCLE: 'licenseseat://autovalidation-cycle',
  AUTO_VALIDATION_STOPPED: 'licenseseat://autovalidation-stopped',
  NETWORK_ONLINE: 'licenseseat://network-online',
  NETWORK_OFFLINE: 'licenseseat://network-offline',
  SDK_RESET: 'licenseseat://sdk-reset',
  SDK_ERROR: 'licenseseat://sdk-error',
} as const;

/** Any stable event name emitted by the plugin */
export type LicenseSeatEventName =
  (typeof LICENSESEAT_EVENTS)[keyof typeof LICENSESEAT_EVENTS];

/** Events that can change the observable licensing state */
export const LICENSESEAT_STATE_EVENTS = [
  LICENSESEAT_EVENTS.ACTIVATION_SUCCESS,
  LICENSESEAT_EVENTS.VALIDATION_SUCCESS,
  LICENSESEAT_EVENTS.VALIDATION_FAILED,
  LICENSESEAT_EVENTS.VALIDATION_ERROR,
  LICENSESEAT_EVENTS.VALIDATION_OFFLINE_SUCCESS,
  LICENSESEAT_EVENTS.VALIDATION_OFFLINE_FAILED,
  LICENSESEAT_EVENTS.VALIDATION_AUTH_FAILED,
  LICENSESEAT_EVENTS.VALIDATION_AUTO_FAILED,
  LICENSESEAT_EVENTS.DEACTIVATION_SUCCESS,
  LICENSESEAT_EVENTS.LICENSE_LOADED,
  LICENSESEAT_EVENTS.LICENSE_REVOKED,
  LICENSESEAT_EVENTS.OFFLINE_ASSETS_REFRESHED,
  LICENSESEAT_EVENTS.NETWORK_ONLINE,
  LICENSESEAT_EVENTS.NETWORK_OFFLINE,
  LICENSESEAT_EVENTS.SDK_RESET,
] as const;

/** Structured state-change notification */
export interface LicenseSeatStateChange {
  eventName: LicenseSeatEventName | null;
  payload: LicenseSeatEventPayload;
  state: LicenseSeatState;
}

/** Subscription options for state-change listeners */
export interface SubscribeStateOptions {
  emitCurrent?: boolean;
  events?: readonly LicenseSeatEventName[];
}

/** Plugin error */
export interface LicenseSeatError {
  code?: string;
  message: string;
  status?: number;
}

/** Concrete error type thrown by the JS bindings */
export class LicenseSeatPluginError extends Error implements LicenseSeatError {
  code?: string;
  status?: number;

  constructor(
    message: string,
    options: {
      code?: string;
      status?: number;
      cause?: unknown;
    } = {}
  ) {
    super(message);
    this.name = 'LicenseSeatError';
    this.code = options.code;
    this.status = options.status;

    if (options.cause !== undefined) {
      (this as Error & { cause?: unknown }).cause = options.cause;
    }
  }
}

export interface BootstrapStateOptions {
  validateIfActivated?: boolean;
}

type UnknownRecord = Record<string, unknown>;

function asRecord(value: unknown): UnknownRecord | null {
  return value && typeof value === 'object' ? (value as UnknownRecord) : null;
}

function readText(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function parseStructuredErrorString(value: string): unknown | null {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function isGenericErrorMessage(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return (
    normalized === 'unknown error' ||
    normalized === 'error' ||
    normalized === 'unexpected error'
  );
}

function getErrorCandidates(error: unknown): UnknownRecord[] {
  const record = asRecord(error);
  if (!record) return [];

  return [
    record,
    asRecord(record.error),
    asRecord(record.data),
    asRecord(record.payload),
    asRecord(record.cause),
    asRecord(record.details),
  ].filter((candidate): candidate is UnknownRecord => candidate !== null);
}

function extractKnownErrorMessage(error: unknown): string | null {
  if (typeof error === 'string') {
    const value = error.trim();
    if (value.length === 0) return null;

    const parsed = parseStructuredErrorString(value);
    const parsedMessage = parsed ? extractKnownErrorMessage(parsed) : null;
    if (parsedMessage) return parsedMessage;

    return isGenericErrorMessage(value) ? null : value;
  }

  if (error instanceof Error) {
    const value = error.message.trim();
    if (value.length > 0 && !isGenericErrorMessage(value)) {
      const parsed = parseStructuredErrorString(value);
      return (parsed ? extractKnownErrorMessage(parsed) : null) ?? value;
    }
  }

  for (const candidate of getErrorCandidates(error)) {
    for (const value of [
      readText(candidate.message),
      readText(candidate.detail),
      readText(candidate.title),
      readText(candidate.error),
    ]) {
      if (value && !isGenericErrorMessage(value)) return value;
    }

    const nestedMessage = readText(candidate.message);
    const parsed = nestedMessage ? parseStructuredErrorString(nestedMessage) : null;
    const parsedMessage = parsed ? extractKnownErrorMessage(parsed) : null;
    if (parsedMessage) return parsedMessage;
  }

  return null;
}

function extractCode(error: unknown): string | undefined {
  for (const candidate of getErrorCandidates(error)) {
    const code = readText(candidate.code);
    if (code) return code;
  }

  return undefined;
}

function extractStatus(error: unknown): number | undefined {
  for (const candidate of getErrorCandidates(error)) {
    if (typeof candidate.status === 'number') return candidate.status;
  }

  return undefined;
}

function summarizeHtmlError(errorMessage: string, status?: number): string | null {
  const trimmed = errorMessage.trim().toLowerCase();
  const looksLikeHtml =
    trimmed.startsWith('<!doctype html') ||
    trimmed.startsWith('<html') ||
    trimmed.includes('<head>') ||
    trimmed.includes('<body>');
  if (!looksLikeHtml) return null;

  const titleMatch = errorMessage.match(/<title>(.*?)<\/title>/i);
  const title = titleMatch?.[1]?.trim();
  const suffix = status ? ` (${status})` : '';

  if (title) return `License server returned an HTML error page${suffix}: ${title}`;
  return `License server returned an HTML error page${suffix}`;
}

function fallbackErrorMessage(
  error: unknown,
  code?: string,
  status?: number
): string {
  if (code && status) return `${code} (${status})`;
  if (code) return code;
  if (status) return `Request failed (${status})`;

  if (error instanceof Error) {
    const value = error.message.trim();
    if (value.length > 0) return value;
  }

  if (typeof error === 'string') {
    const value = error.trim();
    if (value.length > 0) return value;
  }

  return 'Unknown error';
}

/**
 * Normalize unknown Tauri/plugin errors into a stable LicenseSeat error shape.
 */
export function normalizeError(error: unknown): LicenseSeatPluginError {
  if (error instanceof LicenseSeatPluginError) return error;

  const code = extractCode(error);
  const status = extractStatus(error);
  const rawMessage =
    extractKnownErrorMessage(error) ?? fallbackErrorMessage(error, code, status);
  const summarizedMessage = summarizeHtmlError(rawMessage, status) ?? rawMessage;
  const message =
    summarizedMessage.length > 300
      ? `${summarizedMessage.slice(0, 297)}...`
      : summarizedMessage;

  return new LicenseSeatPluginError(message, { code, status, cause: error });
}

async function invokeLicenseSeat<T>(
  command: string,
  args?: Record<string, unknown>
): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    throw normalizeError(error);
  }
}

// ============================================================================
// API Functions
// ============================================================================

/**
 * Activate a license key.
 *
 * @param licenseKey - The license key to activate
 * @param options - Optional activation options
 * @returns The activated license details
 * @throws {LicenseSeatError} If activation fails
 *
 * @example
 * ```typescript
 * const license = await activate('XXXX-XXXX-XXXX-XXXX');
 * console.log(`Activated on device: ${license.deviceId}`);
 * ```
 */
export async function activate(
  licenseKey: string,
  options?: ActivationOptions
): Promise<License> {
  return invokeLicenseSeat<License>('plugin:licenseseat|activate', {
    licenseKey,
    options,
  });
}

/**
 * Validate an explicit license key.
 *
 * @param licenseKey - The license key to validate
 * @returns The validation result
 */
export async function validateKey(licenseKey: string): Promise<ValidationResult> {
  return invokeLicenseSeat<ValidationResult>('plugin:licenseseat|validate_key', {
    licenseKey,
  });
}

/**
 * Validate the current license.
 *
 * @returns The validation result
 * @throws {LicenseSeatError} If validation fails
 */
export async function validate(): Promise<ValidationResult> {
  return invokeLicenseSeat<ValidationResult>('plugin:licenseseat|validate');
}

/**
 * Deactivate the current license.
 *
 * @throws {LicenseSeatError} If deactivation fails
 */
export async function deactivate(): Promise<void> {
  return invokeLicenseSeat<void>('plugin:licenseseat|deactivate');
}

/**
 * Deactivate an explicit license/fingerprint pair.
 *
 * @param licenseKey - The license key to deactivate
 * @param fingerprint - Optional fingerprint override
 */
export async function deactivateKey(
  licenseKey: string,
  fingerprint?: string
): Promise<void> {
  return invokeLicenseSeat<void>('plugin:licenseseat|deactivate_key', {
    licenseKey,
    fingerprint,
  });
}

/**
 * Send a heartbeat for the current license.
 *
 * @throws {LicenseSeatError} If heartbeat fails
 */
export async function heartbeat(): Promise<void> {
  return invokeLicenseSeat<void>('plugin:licenseseat|heartbeat');
}

/**
 * Send a heartbeat for an explicit license/fingerprint pair.
 *
 * @param licenseKey - The license key
 * @param fingerprint - Optional fingerprint override
 */
export async function heartbeatKey(
  licenseKey: string,
  fingerprint?: string
): Promise<void> {
  return invokeLicenseSeat<void>('plugin:licenseseat|heartbeat_key', {
    licenseKey,
    fingerprint,
  });
}

/**
 * Get the current license status.
 *
 * @returns The current status
 */
export async function getStatus(): Promise<LicenseStatus> {
  return invokeLicenseSeat<LicenseStatus>('plugin:licenseseat|get_status');
}

/**
 * Get the stable client status string.
 */
export async function getClientStatus(): Promise<LicenseStatus['status']> {
  return invokeLicenseSeat<LicenseStatus['status']>('plugin:licenseseat|get_client_status');
}

/**
 * Check whether the SDK currently believes the API is reachable.
 */
export async function isOnline(): Promise<boolean> {
  return invokeLicenseSeat<boolean>('plugin:licenseseat|is_online');
}

/**
 * Get the current SDK fingerprint.
 */
export async function getFingerprint(): Promise<string> {
  return invokeLicenseSeat<string>('plugin:licenseseat|get_fingerprint');
}

/**
 * Restore a cached license session.
 */
export async function restoreLicense(): Promise<RestoreResult> {
  return invokeLicenseSeat<RestoreResult>('plugin:licenseseat|restore_license');
}

/**
 * Check whether the API is reachable.
 */
export async function health(): Promise<boolean> {
  return invokeLicenseSeat<boolean>('plugin:licenseseat|health');
}

/**
 * Check if an entitlement is active.
 *
 * @param entitlementKey - The entitlement key to check
 * @returns The entitlement status with details
 */
export async function checkEntitlement(
  entitlementKey: string
): Promise<EntitlementStatus> {
  return invokeLicenseSeat<EntitlementStatus>('plugin:licenseseat|check_entitlement', {
    entitlementKey,
  });
}

/**
 * Get the current active entitlements from the cached validation result.
 *
 * @returns The active entitlement records
 */
export async function getEntitlements(): Promise<Entitlement[]> {
  return invokeLicenseSeat<Entitlement[]>('plugin:licenseseat|get_entitlements');
}

/**
 * Check if an entitlement is active (convenience function).
 *
 * @param entitlementKey - The entitlement key to check
 * @returns true if the entitlement is active
 *
 * @example
 * ```typescript
 * if (await hasEntitlement('pro-features')) {
 *   enableProFeatures();
 * }
 * ```
 */
export async function hasEntitlement(entitlementKey: string): Promise<boolean> {
  return invokeLicenseSeat<boolean>('plugin:licenseseat|has_entitlement', {
    entitlementKey,
  });
}

/**
 * Get the current cached license.
 *
 * @returns The cached license or null if not activated
 */
export async function getLicense(): Promise<License | null> {
  return invokeLicenseSeat<License | null>('plugin:licenseseat|get_license');
}

/**
 * Get a consolidated view of the current plugin state.
 */
export async function getState(): Promise<LicenseSeatState> {
  return invokeLicenseSeat<LicenseSeatState>('plugin:licenseseat|get_state');
}

/**
 * Get a comprehensive admin snapshot of SDK config, runtime, cache, and offline artifacts.
 */
export async function getAdminSnapshot(): Promise<LicenseSeatAdminSnapshot> {
  return invokeLicenseSeat<LicenseSeatAdminSnapshot>('plugin:licenseseat|get_admin_snapshot');
}

/**
 * Restore a cached license session and return the updated state snapshot.
 */
export async function restoreAndGetState(): Promise<LicenseSeatState> {
  await restoreLicense();
  return getState();
}

/**
 * Activate a license, attempt an immediate validation, and return the latest state snapshot.
 *
 * Validation errors are intentionally swallowed so activation success can still
 * be observed through `getState()` and lifecycle events.
 */
export async function activateAndGetState(
  licenseKey: string,
  options?: ActivationOptions
): Promise<LicenseSeatState> {
  await activate(licenseKey, options);

  try {
    await validate();
  } catch {
    // Activation succeeded; return the freshest cached state even if validation failed.
  }

  return getState();
}

/**
 * Restore the cached session, optionally attempt one validation pass, and
 * return the latest state snapshot.
 *
 * Restore/validation errors are swallowed so app startup can proceed with the
 * best available cached state.
 */
export async function bootstrapState(
  options: BootstrapStateOptions = {}
): Promise<LicenseSeatState> {
  const { validateIfActivated = true } = options;

  try {
    await restoreLicense();
  } catch {
    // Startup helpers should return the latest observable state when possible.
  }

  let state = await getState();

  if (validateIfActivated && state.license) {
    try {
      await validate();
    } catch {
      // Keep the last known state if validation cannot complete.
    }

    state = await getState();
  }

  return state;
}

/**
 * Get the active entitlement keys from a previously fetched state snapshot.
 */
export function getActiveEntitlementKeysFromState(state: LicenseSeatState): string[] {
  return state.entitlements.map((entitlement) => entitlement.key);
}

/**
 * Check whether a previously fetched state snapshot has a specific entitlement.
 */
export function stateHasEntitlement(
  state: LicenseSeatState,
  entitlementKey: string
): boolean {
  return state.entitlements.some((entitlement) => entitlement.key === entitlementKey);
}

/**
 * Check whether a previously fetched state snapshot has any of the provided entitlements.
 */
export function stateHasAnyEntitlement(
  state: LicenseSeatState,
  entitlementKeys: readonly string[]
): boolean {
  return entitlementKeys.some((entitlementKey) =>
    stateHasEntitlement(state, entitlementKey)
  );
}

/**
 * Check whether a previously fetched state snapshot has all of the provided entitlements.
 */
export function stateHasAllEntitlements(
  state: LicenseSeatState,
  entitlementKeys: readonly string[]
): boolean {
  return entitlementKeys.every((entitlementKey) =>
    stateHasEntitlement(state, entitlementKey)
  );
}

/**
 * Get the active entitlement keys from the current state snapshot.
 */
export async function getActiveEntitlementKeys(): Promise<string[]> {
  return getActiveEntitlementKeysFromState(await getState());
}

/**
 * Check whether any of the provided entitlements are active in the current state snapshot.
 */
export async function hasAnyEntitlement(
  entitlementKeys: readonly string[]
): Promise<boolean> {
  return stateHasAnyEntitlement(await getState(), entitlementKeys);
}

/**
 * Check whether all of the provided entitlements are active in the current state snapshot.
 */
export async function hasAllEntitlements(
  entitlementKeys: readonly string[]
): Promise<boolean> {
  return stateHasAllEntitlements(await getState(), entitlementKeys);
}

/**
 * Get the active plan key from the current validation snapshot.
 */
export async function getPlanKey(): Promise<string | null> {
  return (await getState()).planKey ?? null;
}

/**
 * Get the current license mode from the validation snapshot.
 */
export async function getLicenseMode(): Promise<string | null> {
  return (await getState()).licenseMode ?? null;
}

/**
 * Listen for a specific LicenseSeat event.
 */
export async function listenEvent<T = LicenseSeatEventPayload>(
  eventName: LicenseSeatEventName,
  handler: (event: Event<T>) => void | Promise<void>
): Promise<UnlistenFn> {
  return listen<T>(eventName, handler);
}

/**
 * Subscribe to state-changing lifecycle events and receive a fresh state snapshot.
 */
export async function subscribeState(
  listener: (change: LicenseSeatStateChange) => void | Promise<void>,
  options: SubscribeStateOptions = {}
): Promise<UnlistenFn> {
  const { emitCurrent = false, events = LICENSESEAT_STATE_EVENTS } = options;
  const unlisteners = await Promise.all(
    events.map((eventName) =>
      listenEvent(eventName, async (event) => {
        await listener({
          eventName,
          payload: (event.payload ?? null) as LicenseSeatEventPayload,
          state: await getState(),
        });
      })
    )
  );

  if (emitCurrent) {
    await listener({
      eventName: null,
      payload: null,
      state: await getState(),
    });
  }

  return async () => {
    await Promise.all(unlisteners.map((unlisten) => unlisten()));
  };
}

/**
 * Alias for subscribeState.
 */
export const onStateChange = subscribeState;

/**
 * Get the latest release for a product.
 */
export async function getLatestRelease(
  productSlug?: string,
  channel?: string,
  platform?: string
): Promise<Release> {
  return invokeLicenseSeat<Release>('plugin:licenseseat|get_latest_release', {
    productSlug,
    channel,
    platform,
  });
}

/**
 * List releases for a product.
 */
export async function listReleases(
  productSlug?: string,
  options?: ReleaseListOptions
): Promise<ReleaseList> {
  return invokeLicenseSeat<ReleaseList>('plugin:licenseseat|list_releases', {
    productSlug,
    options,
  });
}

/**
 * Generate a download token for a release.
 */
export async function generateDownloadToken(
  version: string,
  licenseKey: string,
  productSlug?: string,
  platform?: string
): Promise<DownloadToken> {
  return invokeLicenseSeat<DownloadToken>('plugin:licenseseat|generate_download_token', {
    version,
    licenseKey,
    productSlug,
    platform,
  });
}

/**
 * Generate a legacy offline token for manual/offline workflows.
 */
export async function generateOfflineToken(
  licenseKey: string,
  fingerprint?: string,
  ttlDays?: number
): Promise<OfflineToken> {
  return invokeLicenseSeat<OfflineToken>('plugin:licenseseat|generate_offline_token', {
    licenseKey,
    fingerprint,
    ttlDays,
  });
}

/**
 * Verify a legacy offline token locally.
 */
export async function verifyOfflineToken(
  offlineToken: OfflineToken,
  publicKeyB64?: string
): Promise<boolean> {
  return invokeLicenseSeat<boolean>('plugin:licenseseat|verify_offline_token', {
    offlineToken,
    publicKeyB64,
  });
}

/**
 * Checkout a machine file for offline validation.
 */
export async function checkoutMachineFile(
  licenseKey: string,
  options?: MachineFileCheckoutOptions
): Promise<MachineFile> {
  return invokeLicenseSeat<MachineFile>('plugin:licenseseat|checkout_machine_file', {
    licenseKey,
    options,
  });
}

/**
 * Fetch and cache a signing key for offline verification.
 */
export async function fetchSigningKey(keyId: string): Promise<string> {
  return invokeLicenseSeat<string>('plugin:licenseseat|fetch_signing_key', {
    keyId,
  });
}

/**
 * Refresh the full offline asset set for the current license.
 */
export async function syncOfflineAssets(): Promise<void> {
  return invokeLicenseSeat<void>('plugin:licenseseat|sync_offline_assets');
}

/**
 * Verify a machine file locally.
 */
export async function verifyMachineFile(
  machineFile: MachineFile,
  options?: MachineFileVerificationOptions
): Promise<MachineFileVerificationResult> {
  return invokeLicenseSeat<MachineFileVerificationResult>('plugin:licenseseat|verify_machine_file', {
    machineFile,
    options,
  });
}

/**
 * Reset the SDK state (clears cache).
 */
export async function reset(): Promise<void> {
  return invokeLicenseSeat<void>('plugin:licenseseat|reset');
}

// ============================================================================
// Convenience Class
// ============================================================================

/**
 * LicenseSeat SDK class for object-oriented usage.
 *
 * @example
 * ```typescript
 * const sdk = new LicenseSeat();
 *
 * await sdk.activate('LICENSE-KEY');
 * const status = await sdk.getStatus();
 * ```
 */
const sharedApi = {
  activate,
  validateKey,
  validate,
  deactivate,
  deactivateKey,
  heartbeat,
  heartbeatKey,
  getStatus,
  getClientStatus,
  isOnline,
  getFingerprint,
  restoreLicense,
  health,
  checkEntitlement,
  getEntitlements,
  hasEntitlement,
  getLicense,
  getState,
  getAdminSnapshot,
  restoreAndGetState,
  activateAndGetState,
  bootstrapState,
  getActiveEntitlementKeys,
  getActiveEntitlementKeysFromState,
  getPlanKey,
  getLicenseMode,
  hasAnyEntitlement,
  hasAllEntitlements,
  stateHasEntitlement,
  stateHasAnyEntitlement,
  stateHasAllEntitlements,
  listenEvent,
  subscribeState,
  onStateChange,
  getLatestRelease,
  listReleases,
  generateDownloadToken,
  generateOfflineToken,
  verifyOfflineToken,
  checkoutMachineFile,
  fetchSigningKey,
  syncOfflineAssets,
  verifyMachineFile,
  reset,
  normalizeError,
};

type LicenseSeatSharedApi = typeof sharedApi;

export interface LicenseSeat extends LicenseSeatSharedApi {}

export class LicenseSeat {
  readonly events = LICENSESEAT_EVENTS;
  readonly stateEvents = LICENSESEAT_STATE_EVENTS;

  constructor() {
    Object.assign(this, sharedApi);
  }
}

const defaultExport = {
  LICENSESEAT_EVENTS,
  LICENSESEAT_STATE_EVENTS,
  ...sharedApi,
};

export default defaultExport;
