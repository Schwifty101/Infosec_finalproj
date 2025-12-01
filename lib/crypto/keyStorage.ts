/**
 * Client-Side Private Key Storage using IndexedDB
 *
 * CRITICAL SECURITY REQUIREMENTS:
 * - Private keys stored ONLY in IndexedDB (client-side)
 * - Private keys NEVER sent to server
 * - Keys persist across browser sessions
 * - Keys are non-extractable when possible
 */

const DB_NAME = 'secureMessagingKeys';
const DB_VERSION = 1;
const STORE_NAME = 'privateKeys';

/**
 * Initialize IndexedDB database
 * Creates object store for private keys if it doesn't exist
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

      // Create object store if it doesn't exist
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'userId' });
        console.log('✅ IndexedDB object store created');
      }
    };
  });
}

/**
 * Store private key in IndexedDB
 *
 * @param userId - User ID to associate with the key
 * @param privateKeyJwk - Private key in JWK format (string)
 * @returns Promise<void>
 */
export async function storePrivateKey(
  userId: string,
  privateKeyJwk: string
): Promise<void> {
  try {
    const db = await initDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readwrite');
      const store = transaction.objectStore(STORE_NAME);

      const data = {
        userId,
        privateKey: privateKeyJwk,
        storedAt: new Date().toISOString(),
      };

      const request = store.put(data);

      request.onsuccess = () => {
        console.log('✅ Private key stored in IndexedDB');
        resolve();
      };

      request.onerror = () => {
        reject(new Error('Failed to store private key'));
      };
    });
  } catch (error) {
    console.error('❌ Key storage error:', error);
    throw new Error('Failed to store private key in IndexedDB');
  }
}

/**
 * Retrieve private key from IndexedDB
 *
 * @param userId - User ID
 * @returns Promise<string | null> - Private key JWK or null if not found
 */
export async function getPrivateKey(userId: string): Promise<string | null> {
  try {
    const db = await initDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readonly');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.get(userId);

      request.onsuccess = () => {
        const result = request.result;
        if (result && result.privateKey) {
          console.log('✅ Private key retrieved from IndexedDB');
          resolve(result.privateKey);
        } else {
          console.log('⚠️ No private key found for user');
          resolve(null);
        }
      };

      request.onerror = () => {
        reject(new Error('Failed to retrieve private key'));
      };
    });
  } catch (error) {
    console.error('❌ Key retrieval error:', error);
    throw new Error('Failed to retrieve private key from IndexedDB');
  }
}

/**
 * Delete private key from IndexedDB
 *
 * @param userId - User ID
 * @returns Promise<void>
 */
export async function deletePrivateKey(userId: string): Promise<void> {
  try {
    const db = await initDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.delete(userId);

      request.onsuccess = () => {
        console.log('✅ Private key deleted from IndexedDB');
        resolve();
      };

      request.onerror = () => {
        reject(new Error('Failed to delete private key'));
      };
    });
  } catch (error) {
    console.error('❌ Key deletion error:', error);
    throw new Error('Failed to delete private key from IndexedDB');
  }
}

/**
 * Check if private key exists for user
 *
 * @param userId - User ID
 * @returns Promise<boolean>
 */
export async function hasPrivateKey(userId: string): Promise<boolean> {
  const key = await getPrivateKey(userId);
  return key !== null;
}

/**
 * Clear all private keys from IndexedDB
 * Use with caution - this will delete all stored keys
 *
 * @returns Promise<void>
 */
export async function clearAllKeys(): Promise<void> {
  try {
    const db = await initDB();

    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.clear();

      request.onsuccess = () => {
        console.log('✅ All private keys cleared from IndexedDB');
        resolve();
      };

      request.onerror = () => {
        reject(new Error('Failed to clear private keys'));
      };
    });
  } catch (error) {
    console.error('❌ Clear keys error:', error);
    throw new Error('Failed to clear all private keys');
  }
}
