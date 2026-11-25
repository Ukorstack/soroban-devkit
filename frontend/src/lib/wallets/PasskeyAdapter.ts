/**
 * PasskeyAdapter.ts
 *
 * WebAuthn / Passkey adapter for Soroban smart account biometric signing.
 *
 * Implements FRONTEND-269: formats secp256r1 ECDSA signatures to the
 * IEEE P1363 (R || S 64-byte) format required by Soroban, validates FIDO2
 * authenticatorData flags (User Presence, User Verification), and encodes
 * clientDataJSON and authenticatorData as XDR bytes for on-chain verification.
 *
 * References:
 *   - W3C WebAuthn Level 3: https://www.w3.org/TR/webauthn-3/
 *   - FIDO2 authenticatorData: https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
 *   - Soroban smart accounts: contracts/account-abstraction
 */

'use strict';

// ---------------------------------------------------------------------------
// FIDO2 authenticatorData flag bits (§6.1 of W3C WebAuthn Level 3)
// ---------------------------------------------------------------------------

/** Bit 0 of the flags byte — authenticator confirmed user presence. */
const FLAG_USER_PRESENCE = 0x01;

/** Bit 2 of the flags byte — authenticator performed user verification (PIN / biometric). */
const FLAG_USER_VERIFICATION = 0x04;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Options for credential registration (navigator.credentials.create). */
export interface PasskeyRegistrationOptions {
  /** Human-readable label shown to the user during biometric prompt. */
  displayName: string;
  /** Unique identifier for this user (not displayed). Must be stable. */
  userId: Uint8Array;
  /** Relying Party identifier (hostname, e.g. "playground.soroban.org"). */
  rpId: string;
  /** Relying Party display name shown in the passkey prompt. */
  rpName: string;
  /**
   * Random challenge bytes. Must be generated server-side (or by the dApp)
   * and must be single-use. Min 16 bytes, recommended 32 bytes.
   */
  challenge: Uint8Array;
  /**
   * Whether to require user verification (biometric/PIN) in addition to
   * user presence. Defaults to "required". Soroban smart accounts expect
   * user verification for every signing operation.
   */
  userVerification?: UserVerificationRequirement;
}

/** Result of a successful credential registration. */
export interface PasskeyRegistrationResult {
  /** The credential id assigned by the authenticator (base64url encoded). */
  credentialId: string;
  /** The raw credential id bytes (for XDR encoding). */
  credentialIdBytes: Uint8Array;
  /**
   * The uncompressed secp256r1 public key (65 bytes: 0x04 || X || Y).
   * Pass this to your Soroban smart account initializer.
   */
  publicKeyUncompressed: Uint8Array;
  /** Raw authenticatorData bytes for on-chain storage if needed. */
  authenticatorData: Uint8Array;
  /** Raw clientDataJSON bytes. */
  clientDataJSON: Uint8Array;
}

/** Options for signing a transaction hash with a passkey. */
export interface PasskeySigningOptions {
  /**
   * The 32-byte transaction hash to sign. This is the Stellar transaction
   * payload hash (SHA-256 of the XDR TransactionSignaturePayload).
   */
  txHash: Uint8Array;
  /**
   * The credential id previously returned by registerPasskey. Used to
   * select the correct passkey from the authenticator.
   */
  credentialId: string;
  /** Relying Party identifier (must match the one used at registration). */
  rpId: string;
  /**
   * Whether to require user verification. Must be "required" for Soroban
   * smart accounts that enforce the UV flag on-chain.
   */
  userVerification?: UserVerificationRequirement;
}

/** The signing output ready for submission to a Soroban smart account. */
export interface PasskeySignaturePayload {
  /**
   * IEEE P1363 signature: 64 bytes, big-endian R (32 bytes) || S (32 bytes).
   * This is the format Soroban's secp256r1 host function expects.
   */
  signatureP1363: Uint8Array;
  /**
   * XDR-encoded authenticatorData bytes. Submit this alongside the signature
   * so the Soroban contract can reconstruct and verify the signed message.
   */
  authenticatorDataXdr: Uint8Array;
  /**
   * XDR-encoded clientDataJSON bytes. The contract hashes
   * SHA-256(clientDataJSON) and verifies it was included in the signed data.
   */
  clientDataJsonXdr: Uint8Array;
  /**
   * The full 32-byte message that was actually signed by the authenticator:
   *   SHA-256(authenticatorData || SHA-256(clientDataJSON))
   * Useful for off-chain verification or debugging.
   */
  signedMessage: Uint8Array;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class PasskeyError extends Error {
  constructor(
    message: string,
    public readonly code:
      | 'NOT_SUPPORTED'
      | 'REGISTRATION_FAILED'
      | 'SIGNING_FAILED'
      | 'FLAG_UP_MISSING'
      | 'FLAG_UV_MISSING'
      | 'INVALID_SIGNATURE'
      | 'UNSUPPORTED_KEY_TYPE'
      | 'CHALLENGE_MISMATCH',
  ) {
    super(message);
    this.name = 'PasskeyError';
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Base64url-encode a byte array without padding, as required by WebAuthn
 * and the FIDO2 credential ID format.
 */
export function base64urlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Base64url-decode a string to a Uint8Array. Accepts strings with or
 * without padding.
 */
export function base64urlDecode(s: string): Uint8Array {
  // Restore standard base64 padding
  const padded = s.replace(/-/g, '+').replace(/_/g, '/');
  const withPad = padded + '='.repeat((4 - (padded.length % 4)) % 4);
  const binary = atob(withPad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encode a byte array as an XDR opaque variable-length bytes value:
 *   4-byte big-endian length || data || 0–3 zero padding bytes.
 *
 * This is the minimal XDR encoding for `opaque<>` (variable length bytes),
 * used by Soroban's ScBytes type. The contract decodes it back to raw bytes.
 */
export function encodeXdrBytes(data: Uint8Array): Uint8Array {
  const len = data.length;
  const paddingNeeded = (4 - (len % 4)) % 4;
  const result = new Uint8Array(4 + len + paddingNeeded);
  const view = new DataView(result.buffer);
  view.setUint32(0, len, false /* big-endian */);
  result.set(data, 4);
  // Padding bytes are already 0 (Uint8Array default).
  return result;
}

/**
 * Validate the authenticatorData flags byte.
 *
 * The FIDO2 spec (§6.1) requires:
 *   - UP (bit 0) must always be set: the user was present.
 *   - UV (bit 2) must be set when userVerification is "required".
 *
 * Soroban smart accounts typically enforce UV on-chain; failing early here
 * surfaces the problem before attempting a chain submission.
 *
 * @param flags       The single flags byte from authenticatorData[32].
 * @param requireUV   Whether to enforce the User Verification flag.
 */
export function validateAuthenticatorFlags(flags: number, requireUV: boolean): void {
  if (!(flags & FLAG_USER_PRESENCE)) {
    throw new PasskeyError(
      'Authenticator did not confirm user presence (UP flag is not set). ' +
        'The passkey assertion is invalid.',
      'FLAG_UP_MISSING',
    );
  }
  if (requireUV && !(flags & FLAG_USER_VERIFICATION)) {
    throw new PasskeyError(
      'Authenticator did not perform user verification (UV flag is not set). ' +
        'Enable biometric or PIN unlock and try again.',
      'FLAG_UV_MISSING',
    );
  }
}

/**
 * Convert a DER-encoded secp256r1 ECDSA signature to IEEE P1363 format.
 *
 * WebAuthn returns signatures in DER (ASN.1 SEQUENCE of two INTEGERs for R
 * and S). Soroban's secp256r1 host function expects IEEE P1363:
 * 64 bytes, big-endian R (32 bytes) || S (32 bytes), with no leading 0x00
 * padding bytes and values left-padded to 32 bytes if shorter.
 *
 * DER INTEGER encoding rules:
 *   - A leading 0x00 byte is added when the high bit of the value is set
 *     (to indicate the value is positive). We strip it here.
 *   - Integers shorter than 32 bytes must be left-padded with 0x00.
 *
 * @param derSig  Raw DER bytes of the ECDSA signature.
 * @returns       64-byte Uint8Array in R || S format.
 */
export function derToP1363(derSig: Uint8Array): Uint8Array {
  // Minimum viable DER SEQUENCE: 0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s>
  if (derSig.length < 8) {
    throw new PasskeyError(
      `DER signature too short: ${derSig.length} bytes`,
      'INVALID_SIGNATURE',
    );
  }

  let pos = 0;

  // SEQUENCE tag
  if (derSig[pos++] !== 0x30) {
    throw new PasskeyError('DER signature: expected SEQUENCE tag 0x30', 'INVALID_SIGNATURE');
  }

  // SEQUENCE length (may be long form for large sigs, but secp256r1 is always short)
  const seqLen = derSig[pos++];
  if (pos + seqLen > derSig.length) {
    throw new PasskeyError('DER signature: SEQUENCE length exceeds buffer', 'INVALID_SIGNATURE');
  }

  // Helper: parse one INTEGER component
  const readInt = (): Uint8Array => {
    if (derSig[pos++] !== 0x02) {
      throw new PasskeyError('DER signature: expected INTEGER tag 0x02', 'INVALID_SIGNATURE');
    }
    const intLen = derSig[pos++];
    if (intLen === 0 || pos + intLen > derSig.length) {
      throw new PasskeyError('DER signature: INTEGER length invalid', 'INVALID_SIGNATURE');
    }
    let raw = derSig.slice(pos, pos + intLen);
    pos += intLen;
    // Strip leading 0x00 added for sign disambiguation
    while (raw.length > 1 && raw[0] === 0x00) {
      raw = raw.slice(1);
    }
    return raw;
  };

  const r = readInt();
  const s = readInt();

  if (r.length > 32 || s.length > 32) {
    throw new PasskeyError(
      `DER signature: R (${r.length}B) or S (${s.length}B) exceeds 32 bytes`,
      'INVALID_SIGNATURE',
    );
  }

  // Left-pad R and S to 32 bytes each
  const p1363 = new Uint8Array(64);
  p1363.set(r, 32 - r.length);       // R in bytes 0–31
  p1363.set(s, 64 - s.length);       // S in bytes 32–63
  return p1363;
}

/**
 * Extract the uncompressed secp256r1 public key (65 bytes) from the
 * COSE_Key structure embedded in the attestation's authData.
 *
 * The authenticator returns the credential public key as a CBOR-encoded
 * COSE_Key map (RFC 8152). For EC2 keys (kty = 2, crv = P-256):
 *   - Key -1 (crv): 1 (P-256)
 *   - Key -2 (x):   32-byte X coordinate
 *   - Key -3 (y):   32-byte Y coordinate
 *
 * This parser handles the minimal CBOR needed for a P-256 COSE_Key. It does
 * not implement full CBOR decoding to avoid a runtime dependency.
 */
export function extractP256PublicKey(coseKeyBytes: Uint8Array): Uint8Array {
  // We use a simplified CBOR parser targeting the COSE_Key map format.
  // The map always has at least: kty, alg, crv, x, y.
  const x = coseExtractCoord(coseKeyBytes, -2);
  const y = coseExtractCoord(coseKeyBytes, -3);
  if (!x || !y) {
    throw new PasskeyError(
      'Could not extract X/Y coordinates from COSE_Key. ' +
        'Only P-256 (secp256r1) keys are supported.',
      'UNSUPPORTED_KEY_TYPE',
    );
  }
  // Uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes)
  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(x, 1);
  out.set(y, 33);
  return out;
}

/**
 * Minimal CBOR decoder for byte-string values in a COSE_Key map.
 *
 * CBOR integer keys are either positive (0x00–0x17 for 0–23, 0x18 for 1-byte
 * value, etc.) or negative (0x20–0x37 for -1 to -24, 0x38 for -1-byte value).
 * This handles the common range used by COSE (keys -1 through -3).
 *
 * Returns the byte string associated with `targetKey`, or null if not found.
 */
function coseExtractCoord(cbor: Uint8Array, targetKey: number): Uint8Array | null {
  let i = 0;

  // Skip the outer map header (major type 5, length in lower 5 bits)
  if (i >= cbor.length || (cbor[i] >> 5) !== 5) return null;
  const mapLen = cbor[i++] & 0x1f;

  for (let entry = 0; entry < mapLen; entry++) {
    if (i >= cbor.length) break;

    // Decode integer key
    const keyByte = cbor[i++];
    const majorType = keyByte >> 5;
    const info = keyByte & 0x1f;
    let key: number;

    if (majorType === 0) {
      // Positive integer
      key = info < 24 ? info : cbor[i++];
    } else if (majorType === 1) {
      // Negative integer: value is -1 - n
      key = -(1 + (info < 24 ? info : cbor[i++]));
    } else {
      // Not an integer key — skip the value and continue
      i = skipCborValue(cbor, i - 1);
      i = skipCborValue(cbor, i);
      continue;
    }

    // Decode the value
    if (i >= cbor.length) break;
    const valByte = cbor[i];
    const valMajor = valByte >> 5;
    const valInfo = valByte & 0x1f;

    if (key === targetKey && valMajor === 2 /* byte string */) {
      i++;
      let bstrLen: number;
      if (valInfo < 24) {
        bstrLen = valInfo;
      } else if (valInfo === 24) {
        bstrLen = cbor[i++];
      } else {
        return null; // unexpected length encoding
      }
      return cbor.slice(i, i + bstrLen);
    }

    // Skip value for non-target keys
    i = skipCborValue(cbor, i);
  }
  return null;
}

/**
 * Skip one CBOR value at `pos` and return the index past it.
 * Handles integers, byte strings, text strings, arrays, and maps
 * in the depth-0 range sufficient for a flat COSE_Key map.
 */
function skipCborValue(cbor: Uint8Array, pos: number): number {
  if (pos >= cbor.length) return pos;
  const byte = cbor[pos++];
  const major = byte >> 5;
  const info = byte & 0x1f;

  let additionalBytes: number;
  if (info < 24) {
    additionalBytes = 0;
    if (major === 0 || major === 1) return pos; // integer, no payload
    if (major === 7) return pos; // simple / float
    // For major 2 (bstr), 3 (tstr): `info` is the length
    return pos + info;
  } else if (info === 24) {
    const n = cbor[pos++];
    if (major === 0 || major === 1 || major === 7) return pos;
    return pos + n;
  } else if (info === 25) {
    const n = (cbor[pos] << 8) | cbor[pos + 1];
    pos += 2;
    if (major === 0 || major === 1 || major === 7) return pos;
    return pos + n;
  }
  // For arrays/maps (not needed here) or anything else, skip 0 extra
  return pos;
}

// ---------------------------------------------------------------------------
// SHA-256 utility (uses SubtleCrypto; falls back to Node.js crypto in tests)
// ---------------------------------------------------------------------------

/**
 * SHA-256 hash of `data`. Uses the WebCrypto SubtleCrypto API available in
 * all modern browsers and in Node.js >= 15 (via globalThis.crypto).
 */
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hashBuf = await globalThis.crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hashBuf);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Register a new passkey credential for a Soroban smart account.
 *
 * Calls `navigator.credentials.create()` with FIDO2 / WebAuthn parameters
 * and returns the credential ID and public key needed to initialise the
 * on-chain account.
 *
 * @throws {PasskeyError} with code 'NOT_SUPPORTED' if the browser does not
 *   support WebAuthn, or 'REGISTRATION_FAILED' on any credential creation error.
 */
export async function registerPasskey(
  opts: PasskeyRegistrationOptions,
): Promise<PasskeyRegistrationResult> {
  if (
    typeof navigator === 'undefined' ||
    !navigator.credentials ||
    typeof PublicKeyCredential === 'undefined'
  ) {
    throw new PasskeyError(
      'WebAuthn is not supported in this environment.',
      'NOT_SUPPORTED',
    );
  }

  const userVerification = opts.userVerification ?? 'required';

  let credential: PublicKeyCredential;
  try {
    credential = (await navigator.credentials.create({
      publicKey: {
        challenge: opts.challenge,
        rp: { id: opts.rpId, name: opts.rpName },
        user: {
          id: opts.userId,
          name: opts.displayName,
          displayName: opts.displayName,
        },
        pubKeyCredParams: [
          // ES256 (-7) — secp256r1 / P-256, the only curve Soroban supports
          { type: 'public-key', alg: -7 },
        ],
        authenticatorSelection: {
          userVerification,
          // Prefer a platform (device-bound) authenticator so TouchID / FaceID
          // is used instead of a roaming hardware key.
          authenticatorAttachment: 'platform',
          residentKey: 'preferred',
        },
        attestation: 'none', // We don't need attestation for account creation
      },
    })) as PublicKeyCredential;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new PasskeyError(
      `Passkey registration failed: ${msg}`,
      'REGISTRATION_FAILED',
    );
  }

  const response = credential.response as AuthenticatorAttestationResponse;
  const authData = new Uint8Array(response.getAuthenticatorData());
  const clientDataJSON = new Uint8Array(response.clientDataJSON);
  const credentialIdBytes = new Uint8Array(credential.rawId);

  // Extract the public key from the COSE_Key in authData.
  // authData layout: rpIdHash (32) || flags (1) || signCount (4) || attestedCredentialData
  // attestedCredentialData: aaguid (16) || credIdLen (2) || credId (credIdLen) || pubKey (CBOR)
  const AUTHDATA_MIN = 32 + 1 + 4 + 16 + 2;
  if (authData.length < AUTHDATA_MIN) {
    throw new PasskeyError(
      'authenticatorData is too short to contain attested credential data.',
      'REGISTRATION_FAILED',
    );
  }

  // Validate flags
  const flags = authData[32];
  validateAuthenticatorFlags(flags, userVerification === 'required');

  // Parse attested credential data
  const credIdLenOffset = 32 + 1 + 4 + 16;
  const credIdLen = (authData[credIdLenOffset] << 8) | authData[credIdLenOffset + 1];
  const pubKeyOffset = credIdLenOffset + 2 + credIdLen;
  const coseKeyBytes = authData.slice(pubKeyOffset);
  const publicKeyUncompressed = extractP256PublicKey(coseKeyBytes);

  return {
    credentialId: base64urlEncode(credentialIdBytes),
    credentialIdBytes,
    publicKeyUncompressed,
    authenticatorData: authData,
    clientDataJSON,
  };
}

/**
 * Sign a Soroban transaction hash with a registered passkey.
 *
 * The authenticator signs:
 *   authenticatorData || SHA-256(clientDataJSON)
 *
 * This function:
 *   1. Passes `txHash` as the WebAuthn challenge so the signed clientDataJSON
 *      binds the passkey assertion to this specific transaction.
 *   2. Validates UP and UV flags in the returned authenticatorData.
 *   3. Converts the DER-encoded secp256r1 signature to IEEE P1363 (R || S).
 *   4. XDR-encodes authenticatorData and clientDataJSON for the Soroban contract.
 *
 * @throws {PasskeyError} on any validation failure or signing error.
 */
export async function signWithPasskey(
  opts: PasskeySigningOptions,
): Promise<PasskeySignaturePayload> {
  if (
    typeof navigator === 'undefined' ||
    !navigator.credentials ||
    typeof PublicKeyCredential === 'undefined'
  ) {
    throw new PasskeyError(
      'WebAuthn is not supported in this environment.',
      'NOT_SUPPORTED',
    );
  }

  if (opts.txHash.length !== 32) {
    throw new PasskeyError(
      `txHash must be exactly 32 bytes (got ${opts.txHash.length}).`,
      'SIGNING_FAILED',
    );
  }

  const userVerification = opts.userVerification ?? 'required';
  const credentialIdBytes = base64urlDecode(opts.credentialId);

  let assertion: PublicKeyCredential;
  try {
    assertion = (await navigator.credentials.get({
      publicKey: {
        // The challenge is the raw 32-byte transaction hash. The authenticator
        // embeds it in clientDataJSON (as base64url), which is included in the
        // signed payload, binding this assertion to this exact transaction.
        challenge: opts.txHash,
        rpId: opts.rpId,
        allowCredentials: [
          { type: 'public-key', id: credentialIdBytes },
        ],
        userVerification,
      },
    })) as PublicKeyCredential;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new PasskeyError(
      `Passkey signing failed: ${msg}`,
      'SIGNING_FAILED',
    );
  }

  const response = assertion.response as AuthenticatorAssertionResponse;
  const authData = new Uint8Array(response.authenticatorData);
  const clientDataJSON = new Uint8Array(response.clientDataJSON);
  const derSignature = new Uint8Array(response.signature);

  // --- Validate FIDO2 authenticatorData flags ---
  if (authData.length < 37) {
    throw new PasskeyError(
      'authenticatorData is too short to contain flags byte.',
      'SIGNING_FAILED',
    );
  }
  const flags = authData[32];
  validateAuthenticatorFlags(flags, userVerification === 'required');

  // --- Validate challenge round-trip ---
  // The browser-parsed clientDataJSON must contain our original challenge.
  const clientDataText = new TextDecoder().decode(clientDataJSON);
  let clientDataParsed: { challenge?: string; type?: string };
  try {
    clientDataParsed = JSON.parse(clientDataText) as { challenge?: string; type?: string };
  } catch {
    throw new PasskeyError('clientDataJSON is not valid JSON.', 'SIGNING_FAILED');
  }
  const receivedChallenge = base64urlDecode(clientDataParsed.challenge ?? '');
  if (
    receivedChallenge.length !== opts.txHash.length ||
    !receivedChallenge.every((b, i) => b === opts.txHash[i])
  ) {
    throw new PasskeyError(
      'Challenge in clientDataJSON does not match the submitted txHash. ' +
        'Possible replay or tampering detected.',
      'CHALLENGE_MISMATCH',
    );
  }

  // --- Convert DER signature to IEEE P1363 ---
  const signatureP1363 = derToP1363(derSignature);

  // --- Encode for XDR / Soroban contract ---
  const authenticatorDataXdr = encodeXdrBytes(authData);
  const clientDataJsonXdr = encodeXdrBytes(clientDataJSON);

  // --- Reconstruct the signed message for off-chain verification ---
  // The authenticator signs: authenticatorData || SHA-256(clientDataJSON)
  const clientDataHash = await sha256(clientDataJSON);
  const preimage = new Uint8Array(authData.length + 32);
  preimage.set(authData, 0);
  preimage.set(clientDataHash, authData.length);
  const signedMessage = await sha256(preimage);

  return {
    signatureP1363,
    authenticatorDataXdr,
    clientDataJsonXdr,
    signedMessage,
  };
}
