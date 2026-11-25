/**
 * PasskeySign.ts
 *
 * Signing component for the Soroban smart account passkey workflow.
 *
 * Wraps PasskeyAdapter.signWithPasskey with application-level logic:
 *   - Accepts a hex-encoded transaction hash and a credential id.
 *   - Converts the hex hash to raw bytes before passing to the adapter.
 *   - Returns the P1363 signature and XDR-encoded payloads in formats
 *     ready for submission to contracts/account-abstraction.
 *
 * Usage:
 *   const signer = new PasskeySigner({ rpId: 'playground.soroban.org' });
 *   const sig = await signer.sign({
 *     txHashHex: 'ab12...',       // 64 hex chars (32 bytes)
 *     credentialId: 'base64url...',
 *   });
 */

'use strict';

import {
  signWithPasskey,
  type PasskeySignaturePayload,
  type PasskeySigningOptions,
  PasskeyError,
} from '../wallets/PasskeyAdapter.js';

export interface PasskeySignerConfig {
  /** Relying Party identifier (must match the one used at registration). */
  rpId: string;
  /**
   * Whether to require user verification (biometric/PIN).
   * Default: 'required' (matches what Soroban smart accounts enforce on-chain).
   */
  userVerification?: UserVerificationRequirement;
}

export interface SignRequest {
  /**
   * The 32-byte Stellar transaction hash as a 64-character lowercase hex string.
   * Computed as SHA-256(XDR TransactionSignaturePayload for the target network).
   */
  txHashHex: string;
  /** The credential id returned by PasskeyRegister.register. */
  credentialId: string;
}

export interface SignSuccess {
  status: 'ok';
  /**
   * IEEE P1363 signature (64 bytes) as lowercase hex.
   * Pass this directly to the Soroban smart account invocation.
   */
  signatureHex: string;
  /**
   * XDR-encoded authenticatorData as lowercase hex.
   * The Soroban contract uses this to reconstruct the signed message.
   */
  authenticatorDataXdrHex: string;
  /**
   * XDR-encoded clientDataJSON as lowercase hex.
   * The Soroban contract hashes this and verifies it was signed.
   */
  clientDataJsonXdrHex: string;
  /**
   * The full signed message (SHA-256 of authData || SHA-256(clientDataJSON))
   * as lowercase hex. Useful for debugging and off-chain verification.
   */
  signedMessageHex: string;
  /** Raw payload for callers that need the Uint8Array values directly. */
  raw: PasskeySignaturePayload;
}

export interface SignFailure {
  status: 'error';
  code: string;
  message: string;
}

export type SignOutcome = SignSuccess | SignFailure;

/** Convert a 64-char hex string to a 32-byte Uint8Array. */
function hexToBytes(hex: string): Uint8Array {
  if (hex.length !== 64 || !/^[0-9a-f]+$/i.test(hex)) {
    throw new Error(
      `txHashHex must be exactly 64 lowercase hex characters (32 bytes), got "${hex.slice(0, 20)}${hex.length > 20 ? '…' : ''}"`,
    );
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Convert a Uint8Array to a lowercase hex string. */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export class PasskeySigner {
  private readonly config: Required<PasskeySignerConfig>;

  constructor(config: PasskeySignerConfig) {
    this.config = {
      rpId: config.rpId,
      userVerification: config.userVerification ?? 'required',
    };
  }

  /**
   * Sign a Soroban transaction hash with the user's passkey.
   *
   * @param req.txHashHex     64 hex-char transaction hash (32 bytes).
   * @param req.credentialId  base64url credential ID from registration.
   */
  async sign(req: SignRequest): Promise<SignOutcome> {
    let txHash: Uint8Array;
    try {
      txHash = hexToBytes(req.txHashHex);
    } catch (err: unknown) {
      return {
        status: 'error',
        code: 'SIGNING_FAILED',
        message: err instanceof Error ? err.message : String(err),
      };
    }

    const opts: PasskeySigningOptions = {
      txHash,
      credentialId: req.credentialId,
      rpId: this.config.rpId,
      userVerification: this.config.userVerification,
    };

    try {
      const payload = await signWithPasskey(opts);
      return {
        status: 'ok',
        signatureHex: bytesToHex(payload.signatureP1363),
        authenticatorDataXdrHex: bytesToHex(payload.authenticatorDataXdr),
        clientDataJsonXdrHex: bytesToHex(payload.clientDataJsonXdr),
        signedMessageHex: bytesToHex(payload.signedMessage),
        raw: payload,
      };
    } catch (err: unknown) {
      if (err instanceof PasskeyError) {
        return { status: 'error', code: err.code, message: err.message };
      }
      return {
        status: 'error',
        code: 'SIGNING_FAILED',
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }
}
