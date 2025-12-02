/**
 * Session Key Storage using IndexedDB
 *
 * Manages AES-256-GCM session keys derived from ECDH key exchange.
 * Session keys are stored per-conversation (deterministic user pair ID).
 *
 * Storage Strategy:
 * - Database: secureMessagingKeys (shared with identity keys)
 * - Object Store: sessionKeys (separate from privateKeys)
 * - Key Path: conversationId (deterministic: sorted userId concatenation)
 * - Expiration: 30 days from creation
 *
 * Security: Session keys stored client-side only, never sent to server
 */

import type { SessionMetadata, SessionKeyData } from '@/types/keyExchange';
import { KEY_EXCHANGE_CONFIG } from '@/types/keyExchange';

const DB_NAME = 'secureMessagingKeys';
const DB_VERSION = 2; // Increment from Phase 1 version
const PRIVATE_KEYS_STORE = 'privateKeys'; // Existing from Phase 1
const SESSION_KEYS_STORE = 'sessionKeys'; // NEW for Phase 2
const EPHEMERAL_KEYS_STORE = 'ephemeralKeys'; // NEW for temporary storage

/**
 * Initialize IndexedDB with session key stores
 * Upgrades database from v1 (Phase 1) to v2 (Phase 2)
 */
function initDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => {
      reject(new Error('Failed to open IndexedDB'));
    };

    request.onsuccess = () => {
      resolve(request.result);
    };

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      const oldVersion = event.oldVersion;

      console.log(`📦 Upgrading IndexedDB from version ${oldVersion} to ${DB_VERSION}`);

      // Create privateKeys store if it doesn't exist (from Phase 1)
      if (!db.objectStoreNames.contains(PRIVATE_KEYS_STORE)) {
        db.createObjectStore(PRIVATE_KEYS_STORE, { keyPath: 'userId' });
        console.log('✅ Created privateKeys object store');
      }

      // Create sessionKeys store (NEW in Phase 2)
      if (!db.objectStoreNames.contains(SESSION_KEYS_STORE)) {
        db.createObjectStore(SESSION_KEYS_STORE, { keyPath: 'conversationId' });
        console.log('✅ Created sessionKeys object store');
      }

      // Create ephemeralKeys store (NEW in Phase 2)
      if (!db.objectStoreNames.contains(EPHEMERAL_KEYS_STORE)) {
        const ephemeralStore = db.createObjectStore(EPHEMERAL_KEYS_STORE, { keyPath: 'sessionId' });
        // Index by expiration for cleanup
        ephemeralStore.createIndex('expiresAt', 'expiresAt', { unique: false });
        console.log('✅ Created ephemeralKeys object store');
      }
    };
  });
}

/**
 * Store session key in IndexedDB
 *
 * @param conversationId - Deterministic conversation ID (sorted userIds)
 * @param sessionKey - AES-256-GCM session key (CryptoKey)
 * @param metadata - Session metadata (userIds, timestamps, etc.)
 * @returns Promise<void>
 */
export async function storeSessionKey(
  conversationId: string,
  sessionKey: CryptoKey,
  metadata: SessionMetadata
): Promise<void> {
  try {
    const db = await initDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([SESSION_KEYS_STORE], 'readwrite');
      const store = transaction.objectStore(SESSION_KEYS_STORE);

      // Calculate expiration (30 days from now)
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + KEY_EXCHANGE_CONFIG.SESSION_KEY_EXPIRATION_DAYS);

      const data: SessionKeyData = {
        ...metadata,
        conversationId,
        sessionKey,
        expiresAt,
      };

      const request = store.put(data);

      request.onsuccess = () => {
        console.log('✅ Session key stored in IndexedDB for', conversationId);
        resolve();
      };

      request.onerror = () => {
        reject(new Error('Failed to store session key'));
      };
    });
  } catch (error) {
    console.error('❌ Session key storage error:', error);
    throw new Error('Failed to store session key in IndexedDB');
  }
}

/**
 * Retrieve session key from IndexedDB
 *
 * @param conversationId - Conversation ID
 * @returns Promise<CryptoKey | null> - Session key or null if not found/expired
 */
export async function getSessionKey(conversationId: string): Promise<CryptoKey | null> {
  try {
    const db = await initDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([SESSION_KEYS_STORE], 'readonly');
      const store = transaction.objectStore(SESSION_KEYS_STORE);
      const request = store.get(conversationId);

      request.onsuccess = () => {
        const result: SessionKeyData | undefined = request.result;

        if (!result) {
          console.log('⚠️ No session key found for', conversationId);
          resolve(null);
          return;
        }

        // Check expiration
        const now = new Date();
        if (result.expiresAt && now > result.expiresAt) {
          console.log('⚠️ Session key expired for', conversationId);
          // Delete expired key
          deleteSessionKey(conversationId);
          resolve(null);
          return;
        }

        console.log('✅ Session key retrieved from IndexedDB');
        resolve(result.sessionKey);
      };

      request.onerror = () => {
        reject(new Error('Failed to retrieve session key'));
      };
    });
  } catch (error) {
    console.error('❌ Session key retrieval error:', error);
    throw new Error('Failed to retrieve session key from IndexedDB');
  }
}

/**
 * Get session key metadata
 *
 * @param conversationId - Conversation ID
 * @returns Promise<SessionMetadata | null> - Metadata or null if not found
 */
export async function getSessionMetadata(conversationId: string): Promise<SessionMetadata | null> {
  try {
    const db = await initDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([SESSION_KEYS_STORE], 'readonly');
      const store = transaction.objectStore(SESSION_KEYS_STORE);
      const request = store.get(conversationId);

      request.onsuccess = () => {
        const result: SessionKeyData | undefined = request.result;

        if (!result) {
          resolve(null);
          return;
        }

        // Return metadata without the CryptoKey
        const metadata: SessionMetadata = {
          conversationId: result.conversationId,
          userId1: result.userId1,
          userId2: result.userId2,
          sessionId: result.sessionId,
          createdAt: result.createdAt,
          expiresAt: result.expiresAt,
          keyExchangeCompletedAt: result.keyExchangeCompletedAt,
        };

        resolve(metadata);
      };

      request.onerror = () => {
        reject(new Error('Failed to retrieve session metadata'));
      };
    });
  } catch (error) {
    console.error('❌ Session metadata retrieval error:', error);
    return null;
  }
}

/**
 * Check if session key exists and is not expired
 *
 * @param conversationId - Conversation ID
 * @returns Promise<boolean> - True if valid session key exists
 */
export async function hasValidSessionKey(conversationId: string): Promise<boolean> {
  const sessionKey = await getSessionKey(conversationId);
  return sessionKey !== null;
}

/**
 * Check if session key is expired
 *
 * @param conversationId - Conversation ID
 * @returns Promise<boolean> - True if expired or not found
 */
export async function isSessionKeyExpired(conversationId: string): Promise<boolean> {
  const metadata = await getSessionMetadata(conversationId);

  if (!metadata) {
    return true; // No key = expired
  }

  const now = new Date();
  return now > metadata.expiresAt;
}

/**
 * Delete session key from IndexedDB
 *
 * @param conversationId - Conversation ID
 * @returns Promise<void>
 */
export async function deleteSessionKey(conversationId: string): Promise<void> {
  try {
    const db = await initDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([SESSION_KEYS_STORE], 'readwrite');
      const store = transaction.objectStore(SESSION_KEYS_STORE);
      const request = store.delete(conversationId);

      request.onsuccess = () => {
        console.log('✅ Session key deleted from IndexedDB');
        resolve();
      };

      request.onerror = () => {
        reject(new Error('Failed to delete session key'));
      };
    });
  } catch (error) {
    console.error('❌ Session key deletion error:', error);
    throw new Error('Failed to delete session key from IndexedDB');
  }
}

/**
 * List all session keys with metadata
 *
 * @returns Promise<SessionMetadata[]> - Array of session metadata
 */
export async function listSessionKeys(): Promise<SessionMetadata[]> {
  try {
    const db = await initDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([SESSION_KEYS_STORE], 'readonly');
      const store = transaction.objectStore(SESSION_KEYS_STORE);
      const request = store.getAll();

      request.onsuccess = () => {
        const results: SessionKeyData[] = request.result;

        // Extract metadata (without CryptoKey)
        const metadataList: SessionMetadata[] = results.map((data) => ({
          conversationId: data.conversationId,
          userId1: data.userId1,
          userId2: data.userId2,
          sessionId: data.sessionId,
          createdAt: data.createdAt,
          expiresAt: data.expiresAt,
          keyExchangeCompletedAt: data.keyExchangeCompletedAt,
          isExpired: new Date() > data.expiresAt,
        }));

        console.log('✅ Retrieved', metadataList.length, 'session keys');
        resolve(metadataList);
      };

      request.onerror = () => {
        reject(new Error('Failed to list session keys'));
      };
    });
  } catch (error) {
    console.error('❌ Failed to list session keys:', error);
    return [];
  }
}

/**
 * Clean up expired session keys
 *
 * Deletes all session keys that have passed their expiration date.
 *
 * @returns Promise<number> - Number of keys deleted
 */
export async function cleanupExpiredKeys(): Promise<number> {
  try {
    console.log('🧹 Cleaning up expired session keys...');

    const allKeys = await listSessionKeys();
    const now = new Date();
    let deletedCount = 0;

    for (const metadata of allKeys) {
      if (now > metadata.expiresAt) {
        await deleteSessionKey(metadata.conversationId);
        deletedCount++;
      }
    }

    console.log('✅ Cleaned up', deletedCount, 'expired session keys');
    return deletedCount;
  } catch (error) {
    console.error('❌ Cleanup failed:', error);
    return 0;
  }
}

/**
 * Store ephemeral private key temporarily during key exchange
 *
 * @param sessionId - Key exchange session ID
 * @param ephemeralPrivateKey - ECDH private key (CryptoKey)
 * @returns Promise<void>
 */
export async function storeEphemeralKey(
  sessionId: string,
  ephemeralPrivateKey: CryptoKey
): Promise<void> {
  try {
    const db = await initDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([EPHEMERAL_KEYS_STORE], 'readwrite');
      const store = transaction.objectStore(EPHEMERAL_KEYS_STORE);

      // Ephemeral keys expire after 10 minutes
      const expiresAt = new Date();
      expiresAt.setMinutes(expiresAt.getMinutes() + 10);

      const data = {
        sessionId,
        ephemeralPrivateKey,
        createdAt: new Date(),
        expiresAt,
      };

      const request = store.put(data);

      request.onsuccess = () => {
        console.log('✅ Ephemeral key stored for session', sessionId);
        resolve();
      };

      request.onerror = () => {
        reject(new Error('Failed to store ephemeral key'));
      };
    });
  } catch (error) {
    console.error('❌ Ephemeral key storage error:', error);
    throw new Error('Failed to store ephemeral key');
  }
}

/**
 * Retrieve ephemeral private key
 *
 * @param sessionId - Key exchange session ID
 * @returns Promise<CryptoKey | null> - Ephemeral key or null if not found/expired
 */
export async function getEphemeralKey(sessionId: string): Promise<CryptoKey | null> {
  try {
    const db = await initDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([EPHEMERAL_KEYS_STORE], 'readonly');
      const store = transaction.objectStore(EPHEMERAL_KEYS_STORE);
      const request = store.get(sessionId);

      request.onsuccess = () => {
        const result = request.result;

        if (!result) {
          console.log('⚠️ No ephemeral key found for session', sessionId);
          resolve(null);
          return;
        }

        // Check expiration
        const now = new Date();
        if (now > result.expiresAt) {
          console.log('⚠️ Ephemeral key expired');
          deleteEphemeralKey(sessionId);
          resolve(null);
          return;
        }

        resolve(result.ephemeralPrivateKey);
      };

      request.onerror = () => {
        reject(new Error('Failed to retrieve ephemeral key'));
      };
    });
  } catch (error) {
    console.error('❌ Ephemeral key retrieval error:', error);
    return null;
  }
}

/**
 * Delete ephemeral key (should be called after session key is derived)
 *
 * @param sessionId - Key exchange session ID
 * @returns Promise<void>
 */
export async function deleteEphemeralKey(sessionId: string): Promise<void> {
  try {
    const db = await initDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([EPHEMERAL_KEYS_STORE], 'readwrite');
      const store = transaction.objectStore(EPHEMERAL_KEYS_STORE);
      const request = store.delete(sessionId);

      request.onsuccess = () => {
        console.log('✅ Ephemeral key deleted');
        resolve();
      };

      request.onerror = () => {
        reject(new Error('Failed to delete ephemeral key'));
      };
    });
  } catch (error) {
    console.error('❌ Ephemeral key deletion error:', error);
    throw new Error('Failed to delete ephemeral key');
  }
}

/**
 * Clear all session keys (use with caution)
 *
 * @returns Promise<void>
 */
export async function clearAllSessionKeys(): Promise<void> {
  try {
    const db = await initDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([SESSION_KEYS_STORE], 'readwrite');
      const store = transaction.objectStore(SESSION_KEYS_STORE);
      const request = store.clear();

      request.onsuccess = () => {
        console.log('✅ All session keys cleared from IndexedDB');
        resolve();
      };

      request.onerror = () => {
        reject(new Error('Failed to clear session keys'));
      };
    });
  } catch (error) {
    console.error('❌ Clear session keys error:', error);
    throw new Error('Failed to clear all session keys');
  }
}

/**
 * Get session key status between two users
 *
 * Helper for UI to determine what action to show:
 * - 'exists': Valid session key exists → show "View Chat"
 * - 'expired': Session key expired → show "Renew Exchange"
 * - 'none': No session key → show "Start Exchange"
 *
 * @param myUserId - Current user ID
 * @param peerUserId - Peer user ID
 * @returns Promise<'exists' | 'expired' | 'none'> - Session key status
 */
export async function getSessionKeyStatus(
  myUserId: string,
  peerUserId: string
): Promise<'exists' | 'expired' | 'none'> {
  try {
    // Import getConversationId from protocol to avoid circular dependency
    const { getConversationId } = await import('./protocol');
    const conversationId = getConversationId(myUserId, peerUserId);

    // Check if valid session key exists
    const hasValid = await hasValidSessionKey(conversationId);
    if (hasValid) {
      return 'exists';
    }

    // Check if there's metadata (key existed but may be expired)
    const metadata = await getSessionMetadata(conversationId);
    if (metadata) {
      const now = new Date();
      if (now > metadata.expiresAt) {
        return 'expired';
      }
    }

    return 'none';
  } catch (error) {
    console.error('❌ Failed to get session key status:', error);
    return 'none';
  }
}
