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
  status: 'active' | 'inactive' | 'invalid' | 'pending' | 'offlineValid' | 'offlineInvalid';
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

/** Activation options */
export interface ActivationOptions {
  deviceId?: string;
  deviceName?: string;
  metadata?: Record<string, unknown>;
}

/** Validation result from the API */
export interface ValidationResult {
  object: string;
  valid: boolean;
  code?: string;
  message?: string;
  license: {
    key: string;
    status: string;
    planKey: string;
    activeEntitlements: Array<{
      key: string;
      expiresAt?: string;
    }>;
  };
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
 * Send a heartbeat for the current license.
 *
 * @throws {LicenseSeatError} If heartbeat fails
 */
export async function heartbeat(): Promise<void> {
  return invoke<void>('plugin:licenseseat|heartbeat');
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
  validate = validate;
  deactivate = deactivate;
  heartbeat = heartbeat;
  getStatus = getStatus;
  checkEntitlement = checkEntitlement;
  hasEntitlement = hasEntitlement;
  getLicense = getLicense;
  reset = reset;
}

// Default export
export default {
  activate,
  validate,
  deactivate,
  heartbeat,
  getStatus,
  checkEntitlement,
  hasEntitlement,
  getLicense,
  reset,
};
