/**
 * Public key validation using Trust-On-First-Use (TOFU) pattern
 * Prevents MITM attacks by detecting public key changes
 */

import { openDB, DBSchema, IDBPDatabase } from 'idb';

interface KeyFingerprintDB extends DBSchema {
  fingerprints: {
    key: string; // userId
    value: {
      userId: string;
      fingerprint: string;
      publicKeyJwk: string;
      firstSeen: number; // timestamp
      lastVerified: number; // timestamp
    };
  };
}

const DB_NAME = 'keyFingerprints';
const DB_VERSION = 1;

async function getDB(): Promise<IDBPDatabase<KeyFingerprintDB>> {
  return openDB<KeyFingerprintDB>(DB_NAME, DB_VERSION, {
    upgrade(db) {
      if (!db.objectStoreNames.contains('fingerprints')) {
        db.createObjectStore('fingerprints', { keyPath: 'userId' });
      }
    },
  });
}

/**
 * Compute SHA-256 fingerprint of public key
 */
export async function computeKeyFingerprint(publicKeyJwk: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(publicKeyJwk);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = new Uint8Array(hashBuffer);
  return Array.from(hashArray)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Format fingerprint for display (XX:XX:XX:... format)
 */
export function formatFingerprint(fingerprint: string): string {
  return fingerprint.match(/.{1,2}/g)?.join(':').toUpperCase() || fingerprint;
}

/**
 * Validate public key using TOFU pattern
 */
export async function validatePublicKey(
  userId: string,
  publicKeyJwk: string
): Promise<{
  valid: boolean;
  reason: string;
  isFirstSeen: boolean;
  fingerprint: string;
}> {
  const fingerprint = await computeKeyFingerprint(publicKeyJwk);
  const db = await getDB();

  const stored = await db.get('fingerprints', userId);

  if (!stored) {
    // First time seeing this user's key
    return {
      valid: true,
      reason: 'First time seeing this public key',
      isFirstSeen: true,
      fingerprint,
    };
  }

  if (stored.fingerprint === fingerprint) {
    // Key matches - update last verified timestamp
    await db.put('fingerprints', {
      ...stored,
      lastVerified: Date.now(),
    });

    return {
      valid: true,
      reason: 'Public key matches stored fingerprint',
      isFirstSeen: false,
      fingerprint,
    };
  }

  // Key changed - POTENTIAL MITM!
  return {
    valid: false,
    reason: 'Public key has changed since first exchange',
    isFirstSeen: false,
    fingerprint,
  };
}

/**
 * Store key fingerprint after user confirmation
 */
export async function storeKeyFingerprint(
  userId: string,
  publicKeyJwk: string,
  fingerprint: string
): Promise<void> {
  const db = await getDB();
  await db.put('fingerprints', {
    userId,
    fingerprint,
    publicKeyJwk,
    firstSeen: Date.now(),
    lastVerified: Date.now(),
  });
}

/**
 * Update stored key fingerprint (after user confirms key change is legitimate)
 */
export async function updateKeyFingerprint(
  userId: string,
  publicKeyJwk: string,
  fingerprint: string
): Promise<void> {
  const db = await getDB();
  const stored = await db.get('fingerprints', userId);

  await db.put('fingerprints', {
    userId,
    fingerprint,
    publicKeyJwk,
    firstSeen: stored?.firstSeen || Date.now(),
    lastVerified: Date.now(),
  });
}
