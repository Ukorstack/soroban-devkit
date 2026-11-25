/**
 * PasskeyRegister.ts
 *
 * Registration component for the Soroban smart account passkey workflow.
 *
 * Wraps PasskeyAdapter.registerPasskey with application-level logic:
 *   - Generates a cryptographically random challenge.
 *   - Derives a stable userId from the account alias.
 *   - Formats the returned public key as a hex string for display / storage.
 *   - Emits structured events for the parent UI to react to.
 *
 * Usage:
 *   const reg = new PasskeyRegister({ rpId: 'playground.soroban.org', rpName: 'Soroban Playground' });
 *   const result = await reg.register({ displayName: 'Alice' });
 */

'use strict';

import {
  registerPasskey,
  type PasskeyRegistrationResult,
  type PasskeyRegistrationOptions,
  PasskeyError,
} from '../wallets/PasskeyAdapter.js';

export interface PasskeyRegisterConfig {
  /** Relying Party identifier (hostname). */
  rpId: string;
  /** Relying Party display name shown in the passkey prompt. */
  rpName: string;
  /**
   * Whether to require user verification (biometric/PIN).
   * Default: 'required' (Soroban smart accounts enforce UV on-chain).
   */
  userVerification?: UserVerificationRequirement;
}

export interface RegisterRequest {
  /** Human-readable label for the account (shown in the authenticator prompt). */
  displayName: string;
}

export interface RegisterSuccess {
  status: 'ok';
  credentialId: string;
  /** Uncompressed P-256 public key as lowercase hex (130 hex chars). */
  publicKeyHex: string;
  raw: PasskeyRegistrationResult;
}

export interface RegisterFailure {
  status: 'error';
  code: string;
  message: string;
}

export type RegisterOutcome = RegisterSuccess | RegisterFailure;

export class PasskeyRegister {
  private readonly config: Required<PasskeyRegisterConfig>;

  constructor(config: PasskeyRegisterConfig) {
    this.config = {
      rpId: config.rpId,
      rpName: config.rpName,
      userVerification: config.userVerification ?? 'required',
    };
  }

  /**
   * Register a new passkey for the given display name.
   *
   * Generates a 32-byte random challenge and a stable 16-byte userId derived
   * from the display name, then delegates to PasskeyAdapter.registerPasskey.
   */
  async register(req: RegisterRequest): Promise<RegisterOutcome> {
    // 32-byte single-use challenge
    const challenge = new Uint8Array(32);
    globalThis.crypto.getRandomValues(challenge);

    // Stable 16-byte userId: SHA-256(displayName) truncated to 16 bytes.
    // Using a deterministic derivation means re-registration with the same
    // name maps to the same userId, which some authenticators use to deduplicate.
    const nameBytes = new TextEncoder().encode(req.displayName);
    const hashBuf = await globalThis.crypto.subtle.digest('SHA-256', nameBytes);
    const userId = new Uint8Array(hashBuf).slice(0, 16);

    const opts: PasskeyRegistrationOptions = {
      displayName: req.displayName,
      userId,
      rpId: this.config.rpId,
      rpName: this.config.rpName,
      challenge,
      userVerification: this.config.userVerification,
    };

    try {
      const result = await registerPasskey(opts);
      const publicKeyHex = Array.from(result.publicKeyUncompressed)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      return {
        status: 'ok',
        credentialId: result.credentialId,
        publicKeyHex,
        raw: result,
      };
    } catch (err: unknown) {
      if (err instanceof PasskeyError) {
        return { status: 'error', code: err.code, message: err.message };
      }
      return {
        status: 'error',
        code: 'REGISTRATION_FAILED',
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }
}
