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

/** Plugin error */
export interface LicenseSeatError {
  code?: string;
  message: string;
  status?: number;
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
  return invoke<License>('plugin:licenseseat|activate', {
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
  return invoke<ValidationResult>('plugin:licenseseat|validate_key', {
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
  return invoke<ValidationResult>('plugin:licenseseat|validate');
}

/**
 * Deactivate the current license.
 *
 * @throws {LicenseSeatError} If deactivation fails
 */
export async function deactivate(): Promise<void> {
  return invoke<void>('plugin:licenseseat|deactivate');
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
  return invoke<void>('plugin:licenseseat|deactivate_key', {
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
  return invoke<void>('plugin:licenseseat|heartbeat');
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
  return invoke<void>('plugin:licenseseat|heartbeat_key', {
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
  return invoke<LicenseStatus>('plugin:licenseseat|get_status');
}

/**
 * Get the stable client status string.
 */
export async function getClientStatus(): Promise<LicenseStatus['status']> {
  return invoke<LicenseStatus['status']>('plugin:licenseseat|get_client_status');
}

/**
 * Check whether the SDK currently believes the API is reachable.
 */
export async function isOnline(): Promise<boolean> {
  return invoke<boolean>('plugin:licenseseat|is_online');
}

/**
 * Get the current SDK fingerprint.
 */
export async function getFingerprint(): Promise<string> {
  return invoke<string>('plugin:licenseseat|get_fingerprint');
}

/**
 * Restore a cached license session.
 */
export async function restoreLicense(): Promise<RestoreResult> {
  return invoke<RestoreResult>('plugin:licenseseat|restore_license');
}

/**
 * Check whether the API is reachable.
 */
export async function health(): Promise<boolean> {
  return invoke<boolean>('plugin:licenseseat|health');
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
  return invoke<EntitlementStatus>('plugin:licenseseat|check_entitlement', {
    entitlementKey,
  });
}

/**
 * Get the current active entitlements from the cached validation result.
 *
 * @returns The active entitlement records
 */
export async function getEntitlements(): Promise<Entitlement[]> {
  return invoke<Entitlement[]>('plugin:licenseseat|get_entitlements');
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
  return invoke<boolean>('plugin:licenseseat|has_entitlement', {
    entitlementKey,
  });
}

/**
 * Get the current cached license.
 *
 * @returns The cached license or null if not activated
 */
export async function getLicense(): Promise<License | null> {
  return invoke<License | null>('plugin:licenseseat|get_license');
}

/**
 * Get the latest release for a product.
 */
export async function getLatestRelease(
  productSlug?: string,
  channel?: string,
  platform?: string
): Promise<Release> {
  return invoke<Release>('plugin:licenseseat|get_latest_release', {
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
  return invoke<ReleaseList>('plugin:licenseseat|list_releases', {
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
  return invoke<DownloadToken>('plugin:licenseseat|generate_download_token', {
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
  return invoke<OfflineToken>('plugin:licenseseat|generate_offline_token', {
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
  return invoke<boolean>('plugin:licenseseat|verify_offline_token', {
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
  return invoke<MachineFile>('plugin:licenseseat|checkout_machine_file', {
    licenseKey,
    options,
  });
}

/**
 * Fetch and cache a signing key for offline verification.
 */
export async function fetchSigningKey(keyId: string): Promise<string> {
  return invoke<string>('plugin:licenseseat|fetch_signing_key', {
    keyId,
  });
}

/**
 * Verify a machine file locally.
 */
export async function verifyMachineFile(
  machineFile: MachineFile,
  options?: MachineFileVerificationOptions
): Promise<MachineFileVerificationResult> {
  return invoke<MachineFileVerificationResult>('plugin:licenseseat|verify_machine_file', {
    machineFile,
    options,
  });
}

/**
 * Reset the SDK state (clears cache).
 */
export async function reset(): Promise<void> {
  return invoke<void>('plugin:licenseseat|reset');
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
export class LicenseSeat {
  activate = activate;
  validateKey = validateKey;
  validate = validate;
  deactivate = deactivate;
  deactivateKey = deactivateKey;
  heartbeat = heartbeat;
  heartbeatKey = heartbeatKey;
  getEntitlements = getEntitlements;
  getStatus = getStatus;
  getClientStatus = getClientStatus;
  isOnline = isOnline;
  getFingerprint = getFingerprint;
  restoreLicense = restoreLicense;
  health = health;
  checkEntitlement = checkEntitlement;
  hasEntitlement = hasEntitlement;
  getLicense = getLicense;
  getLatestRelease = getLatestRelease;
  listReleases = listReleases;
  generateDownloadToken = generateDownloadToken;
  generateOfflineToken = generateOfflineToken;
  verifyOfflineToken = verifyOfflineToken;
  checkoutMachineFile = checkoutMachineFile;
  fetchSigningKey = fetchSigningKey;
  verifyMachineFile = verifyMachineFile;
  reset = reset;
}

// Default export
export default {
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
  getLatestRelease,
  listReleases,
  generateDownloadToken,
  generateOfflineToken,
  verifyOfflineToken,
  checkoutMachineFile,
  fetchSigningKey,
  verifyMachineFile,
  reset,
};
