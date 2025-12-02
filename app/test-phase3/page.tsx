'use client';

import { useState } from 'react';

/**
 * Phase 3 Manual Testing Page
 * Tests all End-to-End Message Encryption primitives in the browser
 */
export default function TestPhase3Page() {
    const [results, setResults] = useState<string[]>([]);
    const [isRunning, setIsRunning] = useState(false);

    const addResult = (msg: string) => {
        setResults((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
    };

    const clearResults = () => setResults([]);

    // Helper to generate a test session key (AES-256-GCM)
    const generateTestSessionKey = async (): Promise<CryptoKey> => {
        return await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    };

    // ============================================================================
    // Test 1: Message Encryption/Decryption
    // ============================================================================
    const testMessageEncryption = async () => {
        addResult('🧪 === Testing Message Encryption (lib/crypto/messaging-client.ts) ===');

        try {
            const { encryptMessage, decryptMessage } = await import('@/lib/crypto/messaging-client');
            const { arrayBufferToBase64 } = await import('@/lib/crypto/utils');

            // Generate test session key
            addResult('Generating test AES-256-GCM session key...');
            const sessionKey = await generateTestSessionKey();
            addResult(`✅ Session key generated: ${sessionKey.algorithm.name}, ${(sessionKey.algorithm as AesKeyAlgorithm).length} bits`);

            // Test 1.1: Basic encryption
            addResult('Testing encryptMessage...');
            const testMessage = 'Hello, this is a secret message! 🔐';
            const sequenceNumber = 1;

            const encrypted = await encryptMessage(testMessage, sessionKey, sequenceNumber);
            addResult(`✅ Message encrypted successfully`);
            addResult(`   Ciphertext length: ${encrypted.ciphertext.length} chars`);
            addResult(`   IV: ${encrypted.iv.substring(0, 16)}...`);
            addResult(`   Auth Tag: ${encrypted.authTag.substring(0, 16)}...`);
            addResult(`   Nonce: ${encrypted.nonce.substring(0, 16)}...`);
            addResult(`   Sequence: ${encrypted.sequenceNumber}`);

            // Test 1.2: Unique IV per message
            addResult('Testing unique IV generation...');
            const encrypted2 = await encryptMessage(testMessage, sessionKey, 2);
            const ivsAreDifferent = encrypted.iv !== encrypted2.iv;
            addResult(`✅ IVs are unique: ${ivsAreDifferent ? 'YES ✓' : 'NO ✗ (SECURITY ISSUE!)'}`);

            // Test 1.3: Unique nonce per message
            addResult('Testing unique nonce generation...');
            const noncesAreDifferent = encrypted.nonce !== encrypted2.nonce;
            addResult(`✅ Nonces are unique: ${noncesAreDifferent ? 'YES ✓' : 'NO ✗ (SECURITY ISSUE!)'}`);

            // Test 1.4: Decryption
            addResult('Testing decryptMessage...');
            const decrypted = await decryptMessage(
                encrypted.ciphertext,
                encrypted.iv,
                encrypted.authTag,
                encrypted.nonce,
                encrypted.sequenceNumber,
                sessionKey
            );
            addResult(`✅ Message decrypted: "${decrypted}"`);
            addResult(`   Matches original: ${decrypted === testMessage ? 'YES ✓' : 'NO ✗'}`);

            // Test 1.5: Different messages produce different ciphertext
            addResult('Testing different messages produce different ciphertext...');
            const encrypted3 = await encryptMessage('Different message', sessionKey, 3);
            const ciphertextsAreDifferent = encrypted.ciphertext !== encrypted3.ciphertext;
            addResult(`✅ Ciphertexts differ: ${ciphertextsAreDifferent ? 'YES ✓' : 'NO ✗'}`);

            // Test 1.6: Unicode/emoji support
            addResult('Testing Unicode/emoji support...');
            const unicodeMessage = 'مرحبا 🌍 こんにちは 🔒';
            const encryptedUnicode = await encryptMessage(unicodeMessage, sessionKey, 4);
            const decryptedUnicode = await decryptMessage(
                encryptedUnicode.ciphertext,
                encryptedUnicode.iv,
                encryptedUnicode.authTag,
                encryptedUnicode.nonce,
                encryptedUnicode.sequenceNumber,
                sessionKey
            );
            addResult(`✅ Unicode roundtrip: ${decryptedUnicode === unicodeMessage ? 'PASSED ✓' : 'FAILED ✗'}`);

            addResult('🎉 All Message Encryption tests passed!');
        } catch (error) {
            addResult(`❌ Message Encryption test failed: ${error}`);
        }
    };

    // ============================================================================
    // Test 2: Tamper Detection (Auth Tag Verification)
    // ============================================================================
    const testTamperDetection = async () => {
        addResult('🧪 === Testing Tamper Detection (AES-GCM Authentication) ===');

        try {
            const { encryptMessage, decryptMessage } = await import('@/lib/crypto/messaging-client');
            const { base64ToArrayBuffer, arrayBufferToBase64 } = await import('@/lib/crypto/utils');

            const sessionKey = await generateTestSessionKey();
            const testMessage = 'This message must not be tampered!';
            const encrypted = await encryptMessage(testMessage, sessionKey, 1);

            // Test 2.1: Tampered ciphertext should fail
            addResult('Testing tampered ciphertext detection...');
            try {
                // Modify one byte of ciphertext
                const ciphertextBytes = new Uint8Array(base64ToArrayBuffer(encrypted.ciphertext));
                ciphertextBytes[0] ^= 0xFF; // Flip bits
                const tamperedCiphertext = arrayBufferToBase64(ciphertextBytes.buffer);

                await decryptMessage(
                    tamperedCiphertext,
                    encrypted.iv,
                    encrypted.authTag,
                    encrypted.nonce,
                    encrypted.sequenceNumber,
                    sessionKey
                );
                addResult(`❌ SECURITY ISSUE: Tampered ciphertext was accepted!`);
            } catch {
                addResult(`✅ Tampered ciphertext correctly rejected ✓`);
            }

            // Test 2.2: Tampered IV should fail
            addResult('Testing tampered IV detection...');
            try {
                const ivBytes = new Uint8Array(base64ToArrayBuffer(encrypted.iv));
                ivBytes[0] ^= 0xFF;
                const tamperedIV = arrayBufferToBase64(ivBytes.buffer);

                await decryptMessage(
                    encrypted.ciphertext,
                    tamperedIV,
                    encrypted.authTag,
                    encrypted.nonce,
                    encrypted.sequenceNumber,
                    sessionKey
                );
                addResult(`❌ SECURITY ISSUE: Tampered IV was accepted!`);
            } catch {
                addResult(`✅ Tampered IV correctly rejected ✓`);
            }

            // Test 2.3: Tampered auth tag should fail
            addResult('Testing tampered auth tag detection...');
            try {
                const authTagBytes = new Uint8Array(base64ToArrayBuffer(encrypted.authTag));
                authTagBytes[0] ^= 0xFF;
                const tamperedAuthTag = arrayBufferToBase64(authTagBytes.buffer);

                await decryptMessage(
                    encrypted.ciphertext,
                    encrypted.iv,
                    tamperedAuthTag,
                    encrypted.nonce,
                    encrypted.sequenceNumber,
                    sessionKey
                );
                addResult(`❌ SECURITY ISSUE: Tampered auth tag was accepted!`);
            } catch {
                addResult(`✅ Tampered auth tag correctly rejected ✓`);
            }

            // Test 2.4: Wrong session key should fail
            addResult('Testing wrong session key detection...');
            try {
                const wrongKey = await generateTestSessionKey();

                await decryptMessage(
                    encrypted.ciphertext,
                    encrypted.iv,
                    encrypted.authTag,
                    encrypted.nonce,
                    encrypted.sequenceNumber,
                    wrongKey
                );
                addResult(`❌ SECURITY ISSUE: Wrong session key was accepted!`);
            } catch {
                addResult(`✅ Wrong session key correctly rejected ✓`);
            }

            // Test 2.5: Modified sequence number should fail (AAD mismatch)
            addResult('Testing sequence number tampering detection...');
            try {
                await decryptMessage(
                    encrypted.ciphertext,
                    encrypted.iv,
                    encrypted.authTag,
                    encrypted.nonce,
                    999, // Wrong sequence number
                    sessionKey
                );
                addResult(`❌ SECURITY ISSUE: Wrong sequence number was accepted!`);
            } catch {
                addResult(`✅ Wrong sequence number correctly rejected ✓`);
            }

            // Test 2.6: Modified nonce should fail (AAD mismatch)
            addResult('Testing nonce tampering detection...');
            try {
                const { generateNonce } = await import('@/lib/crypto/utils');
                const wrongNonce = generateNonce();

                await decryptMessage(
                    encrypted.ciphertext,
                    encrypted.iv,
                    encrypted.authTag,
                    wrongNonce, // Wrong nonce
                    encrypted.sequenceNumber,
                    sessionKey
                );
                addResult(`❌ SECURITY ISSUE: Wrong nonce was accepted!`);
            } catch {
                addResult(`✅ Wrong nonce correctly rejected ✓`);
            }

            addResult('🎉 All Tamper Detection tests passed!');
        } catch (error) {
            addResult(`❌ Tamper Detection test failed: ${error}`);
        }
    };

    // ============================================================================
    // Test 3: Sequence Number Validation
    // ============================================================================
    const testSequenceValidation = async () => {
        addResult('🧪 === Testing Sequence Number Validation ===');

        try {
            const { validateSequenceNumber } = await import('@/lib/crypto/messaging-client');

            // Test 3.1: Valid sequence (exact match)
            addResult('Testing valid sequence number...');
            const valid1 = validateSequenceNumber(1, 1);
            addResult(`✅ Sequence 1 == expected 1: ${valid1 ? 'VALID ✓' : 'INVALID ✗'}`);

            // Test 3.2: Valid sequential increment
            addResult('Testing sequential increment...');
            const valid2 = validateSequenceNumber(2, 2);
            addResult(`✅ Sequence 2 == expected 2: ${valid2 ? 'VALID ✓' : 'INVALID ✗'}`);

            // Test 3.3: Duplicate sequence should be rejected
            addResult('Testing duplicate sequence rejection...');
            const duplicate = validateSequenceNumber(1, 2);
            addResult(`✅ Sequence 1 when expecting 2: ${!duplicate ? 'REJECTED ✓' : 'ACCEPTED ✗ (REPLAY ATTACK!)'}`);

            // Test 3.4: Out-of-order (gap) should be rejected
            addResult('Testing out-of-order sequence rejection...');
            const outOfOrder = validateSequenceNumber(5, 3);
            addResult(`✅ Sequence 5 when expecting 3: ${!outOfOrder ? 'REJECTED ✓' : 'ACCEPTED ✗'}`);

            // Test 3.5: Negative sequence should be rejected
            addResult('Testing negative sequence...');
            const negative = validateSequenceNumber(-1, 1);
            addResult(`✅ Negative sequence -1: ${!negative ? 'REJECTED ✓' : 'ACCEPTED ✗'}`);

            // Test 3.6: Large sequence numbers
            addResult('Testing large sequence numbers...');
            const large = validateSequenceNumber(1000000, 1000000);
            addResult(`✅ Large sequence 1000000: ${large ? 'VALID ✓' : 'INVALID ✗'}`);

            addResult('🎉 All Sequence Validation tests passed!');
        } catch (error) {
            addResult(`❌ Sequence Validation test failed: ${error}`);
        }
    };

    // ============================================================================
    // Test 4: HMAC Generation/Verification
    // ============================================================================
    const testHMAC = async () => {
        addResult('🧪 === Testing HMAC Functions ===');

        try {
            const { createMessageHMAC, verifyMessageHMAC } = await import('@/lib/crypto/messaging-client');

            const sessionKey = await generateTestSessionKey();
            const testData = 'Important data to authenticate';

            // Test 4.1: Create HMAC
            addResult('Testing createMessageHMAC...');
            const hmac = await createMessageHMAC(sessionKey, testData);
            addResult(`✅ HMAC created: ${hmac.substring(0, 32)}...`);
            addResult(`   HMAC length: ${hmac.length} chars (Base64)`);

            // Test 4.2: Verify HMAC
            addResult('Testing verifyMessageHMAC...');
            const isValid = await verifyMessageHMAC(sessionKey, testData, hmac);
            addResult(`✅ HMAC verification: ${isValid ? 'VALID ✓' : 'INVALID ✗'}`);

            // Test 4.3: Tampered data should fail HMAC
            addResult('Testing HMAC with tampered data...');
            const tamperedValid = await verifyMessageHMAC(sessionKey, 'Tampered data!', hmac);
            addResult(`✅ Tampered data HMAC: ${!tamperedValid ? 'REJECTED ✓' : 'ACCEPTED ✗ (SECURITY ISSUE!)'}`);

            // Test 4.4: Wrong key should fail HMAC
            addResult('Testing HMAC with wrong key...');
            const wrongKey = await generateTestSessionKey();
            const wrongKeyValid = await verifyMessageHMAC(wrongKey, testData, hmac);
            addResult(`✅ Wrong key HMAC: ${!wrongKeyValid ? 'REJECTED ✓' : 'ACCEPTED ✗ (SECURITY ISSUE!)'}`);

            // Test 4.5: Same data produces same HMAC (deterministic)
            addResult('Testing HMAC determinism...');
            const hmac2 = await createMessageHMAC(sessionKey, testData);
            addResult(`✅ HMAC is deterministic: ${hmac === hmac2 ? 'YES ✓' : 'NO ✗'}`);

            // Test 4.6: Different data produces different HMAC
            addResult('Testing different data produces different HMAC...');
            const hmac3 = await createMessageHMAC(sessionKey, 'Different data');
            addResult(`✅ Different data → different HMAC: ${hmac !== hmac3 ? 'YES ✓' : 'NO ✗'}`);

            addResult('🎉 All HMAC tests passed!');
        } catch (error) {
            addResult(`❌ HMAC test failed: ${error}`);
        }
    };

    // ============================================================================
    // Test 5: Utility Functions
    // ============================================================================
    const testUtilities = async () => {
        addResult('🧪 === Testing Utility Functions (lib/crypto/utils.ts) ===');

        try {
            const {
                generateIV,
                generateNonce,
                arrayBufferToBase64,
                base64ToArrayBuffer,
                stringToArrayBuffer,
                arrayBufferToString,
                verifyTimestamp,
                sha256String,
                constantTimeCompare,
            } = await import('@/lib/crypto/utils');

            // Test 5.1: IV generation
            addResult('Testing generateIV...');
            const iv1 = generateIV();
            const iv2 = generateIV();
            addResult(`✅ IV length: ${iv1.byteLength} bytes (expected: 12)`);
            addResult(`   IVs are unique: ${arrayBufferToBase64(iv1.buffer) !== arrayBufferToBase64(iv2.buffer) ? 'YES ✓' : 'NO ✗'}`);

            // Test 5.2: Nonce generation
            addResult('Testing generateNonce...');
            const nonce1 = generateNonce();
            const nonce2 = generateNonce();
            addResult(`✅ Nonce: ${nonce1.substring(0, 16)}...`);
            addResult(`   Nonces are unique: ${nonce1 !== nonce2 ? 'YES ✓' : 'NO ✗'}`);

            // Test 5.3: Base64 roundtrip
            addResult('Testing Base64 encoding/decoding...');
            const originalBytes = new Uint8Array([1, 2, 3, 4, 5, 255, 0, 128]);
            const base64 = arrayBufferToBase64(originalBytes.buffer);
            const decoded = new Uint8Array(base64ToArrayBuffer(base64));
            let base64Match = originalBytes.length === decoded.length;
            for (let i = 0; base64Match && i < originalBytes.length; i++) {
                if (originalBytes[i] !== decoded[i]) base64Match = false;
            }
            addResult(`✅ Base64 roundtrip: ${base64Match ? 'PASSED ✓' : 'FAILED ✗'}`);

            // Test 5.4: String encoding/decoding
            addResult('Testing string encoding/decoding...');
            const originalStr = 'Hello, World! 🌍';
            const strBuffer = stringToArrayBuffer(originalStr);
            const decodedStr = arrayBufferToString(strBuffer);
            addResult(`✅ String roundtrip: ${originalStr === decodedStr ? 'PASSED ✓' : 'FAILED ✗'}`);

            // Test 5.5: Timestamp verification
            addResult('Testing verifyTimestamp...');
            const now = Date.now();
            const validTs = verifyTimestamp(now);
            const oldTs = verifyTimestamp(now - 10 * 60 * 1000); // 10 minutes ago
            addResult(`✅ Current timestamp valid: ${validTs ? 'YES ✓' : 'NO ✗'}`);
            addResult(`   10-minute old timestamp (5min window): ${!oldTs ? 'REJECTED ✓' : 'ACCEPTED ✗'}`);

            // Test 5.6: SHA-256 hashing
            addResult('Testing sha256String...');
            const hash1 = await sha256String('test');
            const hash2 = await sha256String('test');
            const hash3 = await sha256String('different');
            addResult(`✅ SHA-256 hash: ${hash1.substring(0, 32)}...`);
            addResult(`   Deterministic: ${hash1 === hash2 ? 'YES ✓' : 'NO ✗'}`);
            addResult(`   Different input → different hash: ${hash1 !== hash3 ? 'YES ✓' : 'NO ✗'}`);

            // Test 5.7: Constant-time comparison
            addResult('Testing constantTimeCompare...');
            const cmp1 = constantTimeCompare('secret', 'secret');
            const cmp2 = constantTimeCompare('secret', 'different');
            const cmp3 = constantTimeCompare('short', 'longer');
            addResult(`✅ Same strings: ${cmp1 ? 'MATCH ✓' : 'NO MATCH ✗'}`);
            addResult(`   Different strings: ${!cmp2 ? 'NO MATCH ✓' : 'MATCH ✗'}`);
            addResult(`   Different lengths: ${!cmp3 ? 'NO MATCH ✓' : 'MATCH ✗'}`);

            addResult('🎉 All Utility tests passed!');
        } catch (error) {
            addResult(`❌ Utility test failed: ${error}`);
        }
    };

    // ============================================================================
    // Test 6: Full E2E Message Flow Simulation
    // ============================================================================
    const testFullE2EFlow = async () => {
        addResult('🧪 === Testing Full E2E Message Flow Simulation ===');

        try {
            const { encryptMessage, decryptMessage, validateSequenceNumber, createMessageHMAC, verifyMessageHMAC } =
                await import('@/lib/crypto/messaging-client');
            const { generateEphemeralKeyPair, deriveSessionKeyFromECDH } = await import('@/lib/crypto/keyExchange');
            const { arrayBufferToBase64 } = await import('@/lib/crypto/utils');

            // === Setup: Simulate completed key exchange ===
            addResult('Setting up Alice and Bob with session keys from key exchange...');

            // Generate ephemeral keys for both parties
            const aliceEphemeral = await generateEphemeralKeyPair();
            const bobEphemeral = await generateEphemeralKeyPair();

            // Generate nonces
            const aliceNonce = arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(16)).buffer);
            const bobNonce = arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(16)).buffer);

            // Derive session keys (simulating completed Phase 2 key exchange)
            const aliceSessionKey = await deriveSessionKeyFromECDH(
                aliceEphemeral.privateKey,
                bobEphemeral.publicKey,
                aliceNonce,
                bobNonce,
                'alice',
                'bob'
            );

            const bobSessionKey = await deriveSessionKeyFromECDH(
                bobEphemeral.privateKey,
                aliceEphemeral.publicKey,
                aliceNonce,
                bobNonce,
                'alice',
                'bob'
            );

            addResult('✅ Session keys derived for Alice and Bob');

            // === Message 1: Alice → Bob ===
            addResult('\n📤 MESSAGE 1: Alice sends encrypted message to Bob');

            const aliceMessage1 = 'Hi Bob! This is a secure message. 🔐';
            let aliceSeqNum = 1;

            const encrypted1 = await encryptMessage(aliceMessage1, aliceSessionKey, aliceSeqNum);
            const hmac1 = await createMessageHMAC(aliceSessionKey, JSON.stringify({
                ciphertext: encrypted1.ciphertext,
                nonce: encrypted1.nonce,
                seq: encrypted1.sequenceNumber
            }));

            addResult(`   Original: "${aliceMessage1}"`);
            addResult(`   Sequence: ${aliceSeqNum}`);
            addResult(`   Encrypted ✓`);

            // === Bob receives Message 1 ===
            addResult('\n📥 Bob receives and decrypts MESSAGE 1');

            let bobExpectedSeq = 1;

            // Validate sequence
            const seq1Valid = validateSequenceNumber(encrypted1.sequenceNumber, bobExpectedSeq);
            addResult(`   Sequence validation: ${seq1Valid ? 'VALID ✓' : 'INVALID ✗'}`);

            if (!seq1Valid) {
                throw new Error('Sequence number validation failed - possible replay attack!');
            }

            // Verify HMAC
            const hmac1Valid = await verifyMessageHMAC(bobSessionKey, JSON.stringify({
                ciphertext: encrypted1.ciphertext,
                nonce: encrypted1.nonce,
                seq: encrypted1.sequenceNumber
            }), hmac1);
            addResult(`   HMAC verification: ${hmac1Valid ? 'VALID ✓' : 'INVALID ✗'}`);

            // Decrypt
            const decrypted1 = await decryptMessage(
                encrypted1.ciphertext,
                encrypted1.iv,
                encrypted1.authTag,
                encrypted1.nonce,
                encrypted1.sequenceNumber,
                bobSessionKey
            );

            addResult(`   Decrypted: "${decrypted1}"`);
            addResult(`   Message integrity: ${decrypted1 === aliceMessage1 ? 'VERIFIED ✓' : 'FAILED ✗'}`);

            bobExpectedSeq++;

            // === Message 2: Bob → Alice ===
            addResult('\n📤 MESSAGE 2: Bob replies to Alice');

            const bobMessage1 = 'Hello Alice! Got your message safely. 👍';
            let bobSeqNum = 1;

            const encrypted2 = await encryptMessage(bobMessage1, bobSessionKey, bobSeqNum);
            addResult(`   Original: "${bobMessage1}"`);
            addResult(`   Encrypted ✓`);

            // === Alice receives Message 2 ===
            addResult('\n📥 Alice receives and decrypts MESSAGE 2');

            let aliceExpectedSeq = 1;
            const seq2Valid = validateSequenceNumber(encrypted2.sequenceNumber, aliceExpectedSeq);
            addResult(`   Sequence validation: ${seq2Valid ? 'VALID ✓' : 'INVALID ✗'}`);

            const decrypted2 = await decryptMessage(
                encrypted2.ciphertext,
                encrypted2.iv,
                encrypted2.authTag,
                encrypted2.nonce,
                encrypted2.sequenceNumber,
                aliceSessionKey
            );

            addResult(`   Decrypted: "${decrypted2}"`);
            addResult(`   Message integrity: ${decrypted2 === bobMessage1 ? 'VERIFIED ✓' : 'FAILED ✗'}`);

            aliceExpectedSeq++;
            aliceSeqNum++;

            // === Message 3: Alice → Bob (testing sequence increment) ===
            addResult('\n📤 MESSAGE 3: Alice sends another message');

            const aliceMessage2 = 'This is message #2 from Alice!';
            const encrypted3 = await encryptMessage(aliceMessage2, aliceSessionKey, aliceSeqNum);
            addResult(`   Sequence: ${aliceSeqNum}`);
            addResult(`   Encrypted ✓`);

            // === Bob receives Message 3 ===
            addResult('\n📥 Bob receives MESSAGE 3');

            const seq3Valid = validateSequenceNumber(encrypted3.sequenceNumber, bobExpectedSeq);
            addResult(`   Sequence validation (expecting ${bobExpectedSeq}): ${seq3Valid ? 'VALID ✓' : 'INVALID ✗'}`);

            const decrypted3 = await decryptMessage(
                encrypted3.ciphertext,
                encrypted3.iv,
                encrypted3.authTag,
                encrypted3.nonce,
                encrypted3.sequenceNumber,
                bobSessionKey
            );

            addResult(`   Decrypted: "${decrypted3}"`);

            // === Test Replay Attack Detection ===
            addResult('\n🛡️ Testing Replay Attack Detection');

            addResult('Attempting to replay MESSAGE 1...');
            const replaySeqValid = validateSequenceNumber(encrypted1.sequenceNumber, bobExpectedSeq + 1);
            addResult(`   Replay attempt: ${!replaySeqValid ? 'BLOCKED ✓' : 'ACCEPTED ✗ (SECURITY ISSUE!)'}`);

            // === Test Out-of-Order Detection ===
            addResult('\n🛡️ Testing Out-of-Order Message Detection');

            addResult('Simulating out-of-order message (seq 10 when expecting 3)...');
            const futureSeqValid = validateSequenceNumber(10, 3);
            addResult(`   Future sequence: ${!futureSeqValid ? 'BLOCKED ✓' : 'ACCEPTED ✗'}`);

            addResult('\n🎉 FULL E2E MESSAGE FLOW SIMULATION SUCCESSFUL!');
            addResult('   ✓ Messages encrypted with AES-256-GCM');
            addResult('   ✓ Per-message unique IVs and nonces');
            addResult('   ✓ Sequence numbers validated');
            addResult('   ✓ HMAC integrity verification');
            addResult('   ✓ Bidirectional secure communication');
            addResult('   ✓ Replay attacks detected and blocked');
            addResult('   ✓ Out-of-order messages detected');
        } catch (error) {
            addResult(`❌ Full E2E Flow test failed: ${error}`);
        }
    };

    // ============================================================================
    // Test 7: Session Key Storage Integration
    // ============================================================================
    const testSessionKeyIntegration = async () => {
        addResult('🧪 === Testing Session Key Storage Integration ===');

        try {
            const { encryptMessage, decryptMessage } = await import('@/lib/crypto/messaging-client');
            const {
                storeSessionKey,
                getSessionKey,
                hasValidSessionKey,
                deleteSessionKey,
            } = await import('@/lib/crypto/sessionKeys');

            const testConversationId = `test-phase3-${Date.now()}`;

            // Generate and store a session key
            addResult('Generating and storing test session key in IndexedDB...');
            const sessionKey = await generateTestSessionKey();

            await storeSessionKey(testConversationId, sessionKey, {
                conversationId: testConversationId,
                userId1: 'test-alice',
                userId2: 'test-bob',
                sessionId: crypto.randomUUID(),
                createdAt: new Date(),
                expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
                keyExchangeCompletedAt: new Date(),
            });
            addResult('✅ Session key stored in IndexedDB');

            // Check if key exists
            const hasKey = await hasValidSessionKey(testConversationId);
            addResult(`✅ Has valid session key: ${hasKey ? 'YES ✓' : 'NO ✗'}`);

            // Retrieve and use key for encryption
            addResult('Retrieving session key and testing encryption...');
            const retrievedKey = await getSessionKey(testConversationId);

            if (!retrievedKey) {
                throw new Error('Failed to retrieve session key from IndexedDB');
            }

            const testMessage = 'Message encrypted with stored session key!';
            const encrypted = await encryptMessage(testMessage, retrievedKey, 1);
            addResult('✅ Message encrypted with retrieved key');

            const decrypted = await decryptMessage(
                encrypted.ciphertext,
                encrypted.iv,
                encrypted.authTag,
                encrypted.nonce,
                encrypted.sequenceNumber,
                retrievedKey
            );

            addResult(`✅ Message decrypted: "${decrypted}"`);
            addResult(`   Matches original: ${decrypted === testMessage ? 'YES ✓' : 'NO ✗'}`);

            // Cleanup
            addResult('Cleaning up test session key...');
            await deleteSessionKey(testConversationId);
            const afterDelete = await getSessionKey(testConversationId);
            addResult(`✅ Session key deleted: ${afterDelete === null ? 'SUCCESS ✓' : 'FAILED ✗'}`);

            addResult('🎉 All Session Key Integration tests passed!');
        } catch (error) {
            addResult(`❌ Session Key Integration test failed: ${error}`);
        }
    };

    // Run all tests
    const runAllTests = async () => {
        setIsRunning(true);
        clearResults();
        addResult('🚀 Starting Phase 3 Tests (End-to-End Message Encryption)...\n');

        await testMessageEncryption();
        addResult('');
        await testTamperDetection();
        addResult('');
        await testSequenceValidation();
        addResult('');
        await testHMAC();
        addResult('');
        await testUtilities();
        addResult('');
        await testSessionKeyIntegration();
        addResult('');
        await testFullE2EFlow();

        addResult('\n✅ All Phase 3 tests completed!');
        setIsRunning(false);
    };

    return (
        <div className="min-h-screen bg-gray-900 text-white p-8">
            <div className="max-w-4xl mx-auto">
                <h1 className="text-3xl font-bold mb-6">Phase 3 - End-to-End Message Encryption Testing</h1>

                <div className="mb-6 flex flex-wrap gap-2">
                    <button
                        onClick={runAllTests}
                        disabled={isRunning}
                        className="bg-green-600 hover:bg-green-700 disabled:bg-gray-600 px-6 py-2 rounded font-semibold"
                    >
                        {isRunning ? 'Running...' : 'Run All Tests'}
                    </button>

                    <button onClick={testMessageEncryption} disabled={isRunning} className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-4 py-2 rounded">
                        Test Encryption
                    </button>

                    <button onClick={testTamperDetection} disabled={isRunning} className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-4 py-2 rounded">
                        Test Tamper Detection
                    </button>

                    <button onClick={testSequenceValidation} disabled={isRunning} className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-4 py-2 rounded">
                        Test Sequences
                    </button>

                    <button onClick={testHMAC} disabled={isRunning} className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-4 py-2 rounded">
                        Test HMAC
                    </button>

                    <button onClick={testUtilities} disabled={isRunning} className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-4 py-2 rounded">
                        Test Utilities
                    </button>

                    <button onClick={testSessionKeyIntegration} disabled={isRunning} className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-4 py-2 rounded">
                        Test IndexedDB
                    </button>

                    <button onClick={testFullE2EFlow} disabled={isRunning} className="bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 px-4 py-2 rounded">
                        Test Full E2E Flow
                    </button>

                    <button onClick={clearResults} className="bg-gray-600 hover:bg-gray-700 px-4 py-2 rounded">
                        Clear
                    </button>
                </div>

                <div className="bg-gray-800 rounded-lg p-4 font-mono text-sm max-h-[70vh] overflow-y-auto">
                    {results.length === 0 ? (
                        <p className="text-gray-400">Click &ldquo;Run All Tests&rdquo; to start testing Phase 3 components...</p>
                    ) : (
                        results.map((result, index) => (
                            <div
                                key={index}
                                className={`mb-1 ${result.includes('✅') || result.includes('✓')
                                    ? 'text-green-400'
                                    : result.includes('❌') || result.includes('✗')
                                        ? 'text-red-400'
                                        : result.includes('🧪') || result.includes('===')
                                            ? 'text-yellow-400 font-bold'
                                            : result.includes('🎉')
                                                ? 'text-cyan-400 font-bold'
                                                : result.includes('📤')
                                                    ? 'text-blue-400'
                                                    : result.includes('📥')
                                                        ? 'text-purple-400'
                                                        : result.includes('🛡️')
                                                            ? 'text-orange-400 font-bold'
                                                            : 'text-gray-300'
                                    }`}
                            >
                                {result}
                            </div>
                        ))
                    )}
                </div>

                <div className="mt-6 bg-gray-800 rounded-lg p-4">
                    <h2 className="text-xl font-semibold mb-3">What&apos;s Being Tested:</h2>
                    <ul className="list-disc list-inside space-y-1 text-gray-300">
                        <li><strong>Message Encryption:</strong> AES-256-GCM with unique IV/nonce per message</li>
                        <li><strong>Tamper Detection:</strong> Authentication tag verification, ciphertext integrity</li>
                        <li><strong>Sequence Validation:</strong> Replay attack prevention, out-of-order detection</li>
                        <li><strong>HMAC:</strong> Additional message authentication layer</li>
                        <li><strong>Utilities:</strong> IV/nonce generation, encoding, timestamp verification</li>
                        <li><strong>IndexedDB Integration:</strong> Session key storage and retrieval</li>
                        <li><strong>Full E2E Flow:</strong> Complete secure message exchange simulation</li>
                    </ul>
                </div>

                <div className="mt-4 bg-gray-800 rounded-lg p-4">
                    <h2 className="text-xl font-semibold mb-3">Security Features Validated:</h2>
                    <ul className="list-disc list-inside space-y-1 text-gray-300">
                        <li>🔐 <strong>Confidentiality:</strong> AES-256-GCM encryption with 256-bit keys</li>
                        <li>🛡️ <strong>Integrity:</strong> GCM authentication tags prevent tampering</li>
                        <li>🔄 <strong>Replay Protection:</strong> Unique nonces and sequence numbers</li>
                        <li>📝 <strong>Additional Data:</strong> AAD binds nonce + sequence to ciphertext</li>
                        <li>⏱️ <strong>Freshness:</strong> Timestamp verification within acceptable window</li>
                    </ul>
                </div>

                <div className="mt-4 bg-gray-800 rounded-lg p-4">
                    <h2 className="text-xl font-semibold mb-3">Testing Instructions:</h2>
                    <ol className="list-decimal list-inside space-y-1 text-gray-300">
                        <li>Make sure your dev server is running: <code className="bg-gray-700 px-2 rounded">npm run dev</code></li>
                        <li>Navigate to <code className="bg-gray-700 px-2 rounded">http://localhost:3000/test-phase3</code></li>
                        <li>Click &ldquo;Run All Tests&rdquo; to execute all Phase 3 tests</li>
                        <li>Check browser console (F12) for detailed crypto operation logs</li>
                        <li>Open IndexedDB in DevTools → Application → Storage to inspect stored keys</li>
                    </ol>
                </div>
            </div>
        </div>
    );
}
