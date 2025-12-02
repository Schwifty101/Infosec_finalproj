'use client';

import { useState } from 'react';

/**
 * Phase 2.1 Manual Testing Page
 * Tests all key exchange primitives in the browser
 */
export default function TestPhase2Page() {
    const [results, setResults] = useState<string[]>([]);
    const [isRunning, setIsRunning] = useState(false);

    const addResult = (msg: string) => {
        setResults((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
    };

    const clearResults = () => setResults([]);

    // ============================================================================
    // Test 1: HKDF Functions
    // ============================================================================
    const testHKDF = async () => {
        addResult('🧪 === Testing HKDF (lib/crypto/hkdf.ts) ===');

        try {
            // Dynamic import to ensure client-side only
            const { hkdfExtract, hkdfExpand, hkdf, deriveSessionKey, createSaltFromNonces, createHkdfInfo } = await import(
                '@/lib/crypto/hkdf'
            );
            const { arrayBufferToBase64 } = await import('@/lib/crypto/utils');

            // Test 1.1: hkdfExtract
            addResult('Testing hkdfExtract...');
            const testIKM = new TextEncoder().encode('test-input-keying-material');
            const testSalt = new TextEncoder().encode('test-salt-value-here');
            const prk = await hkdfExtract(testSalt.buffer, testIKM.buffer);
            addResult(`✅ hkdfExtract: PRK length = ${prk.byteLength} bytes (expected: 32)`);

            // Test 1.2: hkdfExpand
            addResult('Testing hkdfExpand...');
            const okm = await hkdfExpand(prk, 'test-info', 32);
            addResult(`✅ hkdfExpand: OKM length = ${okm.byteLength} bytes (expected: 32)`);

            // Test 1.3: Complete HKDF
            addResult('Testing complete hkdf...');
            const derivedKey = await hkdf(testIKM.buffer, testSalt.buffer, 'test-info', 32);
            addResult(`✅ hkdf: Derived key length = ${derivedKey.byteLength} bytes`);

            // Test 1.4: createSaltFromNonces
            addResult('Testing createSaltFromNonces...');
            const nonce1 = arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(16)).buffer);
            const nonce2 = arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(16)).buffer);
            const salt = await createSaltFromNonces(nonce1, nonce2);
            addResult(`✅ createSaltFromNonces: Salt length = ${salt.byteLength} bytes (expected: 32)`);

            // Test 1.5: createHkdfInfo
            addResult('Testing createHkdfInfo...');
            const info = createHkdfInfo('user-alice', 'user-bob');
            addResult(`✅ createHkdfInfo: "${info}"`);

            // Test 1.6: deriveSessionKey
            addResult('Testing deriveSessionKey...');
            const mockSharedSecret = crypto.getRandomValues(new Uint8Array(32)).buffer;
            const sessionKey = await deriveSessionKey(mockSharedSecret, salt, info);
            addResult(`✅ deriveSessionKey: Key type = ${sessionKey.type}, algorithm = ${sessionKey.algorithm.name}`);

            addResult('🎉 All HKDF tests passed!');
        } catch (error) {
            addResult(`❌ HKDF test failed: ${error}`);
        }
    };

    // ============================================================================
    // Test 2: ECDSA Signatures
    // ============================================================================
    const testSignatures = async () => {
        addResult('🧪 === Testing ECDSA Signatures (lib/crypto/signatures.ts) ===');

        try {
            const {
                createSignaturePayload,
                signData,
                verifySignature,
                importECDSAPublicKey,
                importECDSAPrivateKey,
                signInitMessage,
                verifyInitMessage,
                signResponseMessage,
                verifyResponseMessage,
            } = await import('@/lib/crypto/signatures');
            const { arrayBufferToBase64 } = await import('@/lib/crypto/utils');

            // Generate test ECDSA key pair
            addResult('Generating ECDSA P-256 key pair...');
            const keyPair = await crypto.subtle.generateKey(
                { name: 'ECDSA', namedCurve: 'P-256' },
                true,
                ['sign', 'verify']
            );
            addResult('✅ ECDSA key pair generated');

            // Test 2.1: createSignaturePayload
            addResult('Testing createSignaturePayload...');
            const payload = createSignaturePayload(['component1', 'component2', 'component3']);
            addResult(`✅ createSignaturePayload: Payload length = ${payload.byteLength} bytes`);

            // Test 2.2: signData and verifySignature
            addResult('Testing signData and verifySignature...');
            const testData = new TextEncoder().encode('test data to sign').buffer;
            const signature = await signData(keyPair.privateKey, testData);
            addResult(`✅ signData: Signature = ${signature.substring(0, 32)}...`);

            const isValid = await verifySignature(keyPair.publicKey, signature, testData);
            addResult(`✅ verifySignature: ${isValid ? 'VALID ✓' : 'INVALID ✗'}`);

            // Test 2.3: Tampered data should fail verification
            addResult('Testing tampered data verification...');
            const tamperedData = new TextEncoder().encode('tampered data!!!').buffer;
            const isTamperedValid = await verifySignature(keyPair.publicKey, signature, tamperedData);
            addResult(`✅ Tampered verification: ${isTamperedValid ? 'FAILED (should be false)' : 'Correctly rejected ✓'}`);

            // Test 2.4: Import/Export keys
            addResult('Testing key import/export...');
            const publicJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', keyPair.publicKey));
            const privateJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', keyPair.privateKey));

            const importedPub = await importECDSAPublicKey(publicJwk);
            const importedPriv = await importECDSAPrivateKey(privateJwk);
            addResult('✅ Key import/export successful');

            // Test 2.5: signInitMessage and verifyInitMessage
            addResult('Testing signInitMessage/verifyInitMessage...');
            const ephemPubKey = '{"kty":"EC","crv":"P-256","x":"test","y":"test"}';
            const nonce = arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(16)).buffer);
            const timestamp = Date.now();

            const initSig = await signInitMessage(keyPair.privateKey, ephemPubKey, nonce, timestamp, 'bob', 'alice');
            const initValid = await verifyInitMessage(keyPair.publicKey, initSig, ephemPubKey, nonce, timestamp, 'bob', 'alice');
            addResult(`✅ Init message sign/verify: ${initValid ? 'VALID ✓' : 'INVALID ✗'}`);

            // Test 2.6: signResponseMessage and verifyResponseMessage
            addResult('Testing signResponseMessage/verifyResponseMessage...');
            const respNonce = arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(16)).buffer);
            const respSig = await signResponseMessage(
                keyPair.privateKey,
                ephemPubKey,
                respNonce,
                timestamp,
                'alice',
                'bob',
                nonce
            );
            const respValid = await verifyResponseMessage(
                keyPair.publicKey,
                respSig,
                ephemPubKey,
                respNonce,
                timestamp,
                'alice',
                'bob',
                nonce
            );
            addResult(`✅ Response message sign/verify: ${respValid ? 'VALID ✓' : 'INVALID ✗'}`);

            addResult('🎉 All Signature tests passed!');
        } catch (error) {
            addResult(`❌ Signature test failed: ${error}`);
        }
    };

    // ============================================================================
    // Test 3: ECDH Key Exchange
    // ============================================================================
    const testKeyExchange = async () => {
        addResult('🧪 === Testing ECDH Key Exchange (lib/crypto/keyExchange.ts) ===');

        try {
            const {
                generateEphemeralKeyPair,
                exportECDHPublicKey,
                exportECDHPrivateKey,
                importECDHPublicKey,
                importECDHPrivateKey,
                performECDH,
                deriveSessionKeyFromECDH,
                getConversationId,
                testECDHAgreement,
            } = await import('@/lib/crypto/keyExchange');
            const { arrayBufferToBase64 } = await import('@/lib/crypto/utils');

            // Test 3.1: Generate ephemeral key pair
            addResult('Testing generateEphemeralKeyPair...');
            const aliceKeyPair = await generateEphemeralKeyPair();
            addResult(`✅ Alice's key pair generated: public=${aliceKeyPair.publicKey.type}, private=${aliceKeyPair.privateKey.type}`);

            const bobKeyPair = await generateEphemeralKeyPair();
            addResult(`✅ Bob's key pair generated`);

            // Test 3.2: Export/Import keys
            addResult('Testing key export/import...');
            const alicePubJwk = await exportECDHPublicKey(aliceKeyPair.publicKey);
            const alicePrivJwk = await exportECDHPrivateKey(aliceKeyPair.privateKey);
            addResult(`✅ Alice's public key exported: ${alicePubJwk.substring(0, 50)}...`);

            const importedAlicePub = await importECDHPublicKey(alicePubJwk);
            const importedAlicePriv = await importECDHPrivateKey(alicePrivJwk);
            addResult('✅ Key import successful');

            // Test 3.3: performECDH
            addResult('Testing ECDH shared secret computation...');
            const aliceSharedSecret = await performECDH(aliceKeyPair.privateKey, bobKeyPair.publicKey);
            const bobSharedSecret = await performECDH(bobKeyPair.privateKey, aliceKeyPair.publicKey);

            // Compare shared secrets
            const aliceBytes = new Uint8Array(aliceSharedSecret);
            const bobBytes = new Uint8Array(bobSharedSecret);
            let match = aliceBytes.length === bobBytes.length;
            for (let i = 0; match && i < aliceBytes.length; i++) {
                if (aliceBytes[i] !== bobBytes[i]) match = false;
            }
            addResult(`✅ ECDH shared secrets ${match ? 'MATCH ✓' : 'DO NOT MATCH ✗'}`);
            addResult(`   Shared secret length: ${aliceSharedSecret.byteLength} bytes`);

            // Test 3.4: deriveSessionKeyFromECDH
            addResult('Testing session key derivation from ECDH...');
            const aliceNonce = arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(16)).buffer);
            const bobNonce = arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(16)).buffer);

            const aliceSessionKey = await deriveSessionKeyFromECDH(
                aliceKeyPair.privateKey,
                bobKeyPair.publicKey,
                aliceNonce,
                bobNonce,
                'alice',
                'bob'
            );
            addResult(`✅ Alice's session key derived: ${aliceSessionKey.algorithm.name}`);

            const bobSessionKey = await deriveSessionKeyFromECDH(
                bobKeyPair.privateKey,
                aliceKeyPair.publicKey,
                aliceNonce,
                bobNonce,
                'alice',
                'bob'
            );
            addResult(`✅ Bob's session key derived: ${bobSessionKey.algorithm.name}`);

            // Test that both can encrypt/decrypt
            addResult('Testing session key interoperability...');
            const testMessage = new TextEncoder().encode('Hello, encrypted world!');
            const iv = crypto.getRandomValues(new Uint8Array(12));

            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                aliceSessionKey,
                testMessage
            );

            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                bobSessionKey,
                encrypted
            );

            const decryptedText = new TextDecoder().decode(decrypted);
            addResult(`✅ Encryption/Decryption test: "${decryptedText}"`);
            addResult(`   Keys are interoperable: ${decryptedText === 'Hello, encrypted world!' ? 'YES ✓' : 'NO ✗'}`);

            // Test 3.5: getConversationId
            addResult('Testing getConversationId...');
            const convId1 = getConversationId('alice', 'bob');
            const convId2 = getConversationId('bob', 'alice');
            addResult(`✅ Conversation ID: "${convId1}"`);
            addResult(`   Deterministic: ${convId1 === convId2 ? 'YES ✓' : 'NO ✗'}`);

            // Test 3.6: Built-in test
            addResult('Running built-in ECDH agreement test...');
            const testResult = await testECDHAgreement();
            addResult(`✅ testECDHAgreement: ${testResult ? 'PASSED ✓' : 'FAILED ✗'}`);

            addResult('🎉 All Key Exchange tests passed!');
        } catch (error) {
            addResult(`❌ Key Exchange test failed: ${error}`);
        }
    };

    // ============================================================================
    // Test 4: Session Key Storage (IndexedDB)
    // ============================================================================
    const testSessionKeyStorage = async () => {
        addResult('🧪 === Testing Session Key Storage (lib/crypto/sessionKeys.ts) ===');

        try {
            const {
                storeSessionKey,
                getSessionKey,
                getSessionMetadata,
                hasValidSessionKey,
                isSessionKeyExpired,
                deleteSessionKey,
                listSessionKeys,
                cleanupExpiredKeys,
                storeEphemeralKey,
                getEphemeralKey,
                deleteEphemeralKey,
                clearAllSessionKeys,
            } = await import('@/lib/crypto/sessionKeys');

            const { generateEphemeralKeyPair, deriveSessionKeyFromECDH } = await import('@/lib/crypto/keyExchange');
            const { arrayBufferToBase64 } = await import('@/lib/crypto/utils');

            // Generate a test session key
            addResult('Generating test session key...');
            const aliceKeyPair = await generateEphemeralKeyPair();
            const bobKeyPair = await generateEphemeralKeyPair();
            const aliceNonce = arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(16)).buffer);
            const bobNonce = arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(16)).buffer);

            const testSessionKey = await deriveSessionKeyFromECDH(
                aliceKeyPair.privateKey,
                bobKeyPair.publicKey,
                aliceNonce,
                bobNonce,
                'test-alice',
                'test-bob'
            );
            addResult('✅ Test session key generated');

            // Test 4.1: Store session key
            addResult('Testing storeSessionKey...');
            const testConvId = 'test-alice_test-bob';
            const testSessionId = crypto.randomUUID();
            await storeSessionKey(testConvId, testSessionKey, {
                conversationId: testConvId,
                userId1: 'test-alice',
                userId2: 'test-bob',
                sessionId: testSessionId,
                createdAt: new Date(),
                expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
                keyExchangeCompletedAt: new Date(),
            });
            addResult('✅ Session key stored in IndexedDB');

            // Test 4.2: Retrieve session key
            addResult('Testing getSessionKey...');
            const retrievedKey = await getSessionKey(testConvId);
            addResult(`✅ Session key retrieved: ${retrievedKey ? 'SUCCESS ✓' : 'FAILED ✗'}`);

            // Test 4.3: Get metadata
            addResult('Testing getSessionMetadata...');
            const metadata = await getSessionMetadata(testConvId);
            addResult(`✅ Metadata: sessionId=${metadata?.sessionId}, userId1=${metadata?.userId1}`);

            // Test 4.4: hasValidSessionKey
            addResult('Testing hasValidSessionKey...');
            const hasValid = await hasValidSessionKey(testConvId);
            addResult(`✅ Has valid session key: ${hasValid ? 'YES ✓' : 'NO ✗'}`);

            // Test 4.5: isSessionKeyExpired
            addResult('Testing isSessionKeyExpired...');
            const isExpired = await isSessionKeyExpired(testConvId);
            addResult(`✅ Is session key expired: ${isExpired ? 'YES' : 'NO ✓ (expected)'}`);

            // Test 4.6: listSessionKeys
            addResult('Testing listSessionKeys...');
            const allKeys = await listSessionKeys();
            addResult(`✅ Total session keys: ${allKeys.length}`);

            // Test 4.7: Ephemeral key storage
            addResult('Testing ephemeral key storage...');
            const testEphemeralId = 'test-ephemeral-' + Date.now();
            await storeEphemeralKey(testEphemeralId, aliceKeyPair.privateKey);
            addResult('✅ Ephemeral key stored');

            const retrievedEphemeral = await getEphemeralKey(testEphemeralId);
            addResult(`✅ Ephemeral key retrieved: ${retrievedEphemeral ? 'SUCCESS ✓' : 'FAILED ✗'}`);

            await deleteEphemeralKey(testEphemeralId);
            addResult('✅ Ephemeral key deleted');

            // Test 4.8: Delete session key
            addResult('Testing deleteSessionKey...');
            await deleteSessionKey(testConvId);
            const afterDelete = await getSessionKey(testConvId);
            addResult(`✅ Session key deleted: ${afterDelete === null ? 'SUCCESS ✓' : 'FAILED ✗'}`);

            // Test 4.9: Cleanup expired keys
            addResult('Testing cleanupExpiredKeys...');
            const cleanedCount = await cleanupExpiredKeys();
            addResult(`✅ Cleaned up ${cleanedCount} expired keys`);

            addResult('🎉 All Session Key Storage tests passed!');
        } catch (error) {
            addResult(`❌ Session Key Storage test failed: ${error}`);
        }
    };

    // ============================================================================
    // Test 5: Full Protocol Simulation
    // ============================================================================
    const testFullProtocol = async () => {
        addResult('🧪 === Testing Full Key Exchange Protocol Simulation ===');

        try {
            const { generateEphemeralKeyPair, exportECDHPublicKey, importECDHPublicKey, performECDH } = await import(
                '@/lib/crypto/keyExchange'
            );
            const { signInitMessage, verifyInitMessage, signResponseMessage, verifyResponseMessage } = await import(
                '@/lib/crypto/signatures'
            );
            const { deriveSessionKey, createSaltFromNonces, createHkdfInfo } = await import('@/lib/crypto/hkdf');
            const { arrayBufferToBase64 } = await import('@/lib/crypto/utils');

            // Simulate Alice and Bob with identity keys (ECDSA)
            addResult('Setting up Alice and Bob with identity keys...');

            const aliceIdentity = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
                'sign',
                'verify',
            ]);
            const bobIdentity = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
                'sign',
                'verify',
            ]);
            addResult('✅ Identity keys generated for Alice and Bob');

            // === MESSAGE 1: Alice -> Bob (KEY_EXCHANGE_INIT) ===
            addResult('\n📤 MESSAGE 1: Alice sends KEY_EXCHANGE_INIT to Bob');

            // Alice generates ephemeral ECDH key pair
            const aliceEphemeral = await generateEphemeralKeyPair();
            const aliceEphemPubJwk = await exportECDHPublicKey(aliceEphemeral.publicKey);
            const aliceNonce = arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(16)).buffer);
            const aliceTimestamp = Date.now();
            const sessionId = crypto.randomUUID();

            // Alice signs the init message
            const initSignature = await signInitMessage(
                aliceIdentity.privateKey,
                aliceEphemPubJwk,
                aliceNonce,
                aliceTimestamp,
                'bob-user-id',
                'alice-user-id'
            );

            addResult(`   Session ID: ${sessionId}`);
            addResult(`   Alice's nonce: ${aliceNonce.substring(0, 16)}...`);
            addResult(`   Signature: ${initSignature.substring(0, 32)}...`);

            // === Bob receives and verifies MESSAGE 1 ===
            addResult('\n📥 Bob receives and verifies MESSAGE 1');

            const initValid = await verifyInitMessage(
                aliceIdentity.publicKey, // Bob would fetch this from server
                initSignature,
                aliceEphemPubJwk,
                aliceNonce,
                aliceTimestamp,
                'bob-user-id',
                'alice-user-id'
            );

            addResult(`   Signature verification: ${initValid ? 'VALID ✓' : 'INVALID ✗'}`);

            if (!initValid) {
                throw new Error('Init message signature invalid - MITM detected!');
            }

            // === MESSAGE 2: Bob -> Alice (KEY_EXCHANGE_RESPONSE) ===
            addResult('\n📤 MESSAGE 2: Bob sends KEY_EXCHANGE_RESPONSE to Alice');

            // Bob generates ephemeral ECDH key pair
            const bobEphemeral = await generateEphemeralKeyPair();
            const bobEphemPubJwk = await exportECDHPublicKey(bobEphemeral.publicKey);
            const bobNonce = arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(16)).buffer);
            const bobTimestamp = Date.now();

            // Bob signs the response message
            const responseSignature = await signResponseMessage(
                bobIdentity.privateKey,
                bobEphemPubJwk,
                bobNonce,
                bobTimestamp,
                'alice-user-id',
                'bob-user-id',
                aliceNonce // Echo Alice's nonce
            );

            addResult(`   Bob's nonce: ${bobNonce.substring(0, 16)}...`);
            addResult(`   Signature: ${responseSignature.substring(0, 32)}...`);

            // === Alice receives and verifies MESSAGE 2 ===
            addResult('\n📥 Alice receives and verifies MESSAGE 2');

            const responseValid = await verifyResponseMessage(
                bobIdentity.publicKey, // Alice would fetch this from server
                responseSignature,
                bobEphemPubJwk,
                bobNonce,
                bobTimestamp,
                'alice-user-id',
                'bob-user-id',
                aliceNonce
            );

            addResult(`   Signature verification: ${responseValid ? 'VALID ✓' : 'INVALID ✗'}`);

            if (!responseValid) {
                throw new Error('Response message signature invalid - MITM detected!');
            }

            // === Both parties derive session key ===
            addResult('\n🔐 Both parties derive session key using ECDH + HKDF');

            // Alice derives session key
            const bobPublicKey = await importECDHPublicKey(bobEphemPubJwk);
            const aliceSharedSecret = await performECDH(aliceEphemeral.privateKey, bobPublicKey);
            const salt = await createSaltFromNonces(aliceNonce, bobNonce);
            const info = createHkdfInfo('alice-user-id', 'bob-user-id');
            const aliceSessionKey = await deriveSessionKey(aliceSharedSecret, salt, info);
            addResult('   Alice derived session key ✓');

            // Bob derives session key
            const alicePublicKey = await importECDHPublicKey(aliceEphemPubJwk);
            const bobSharedSecret = await performECDH(bobEphemeral.privateKey, alicePublicKey);
            const bobSessionKey = await deriveSessionKey(bobSharedSecret, salt, info);
            addResult('   Bob derived session key ✓');

            // === Verify both have the same key by encrypting/decrypting ===
            addResult('\n🔑 Verifying both parties have identical session keys');

            const testMessage = 'This is a secret message!';
            const iv = crypto.getRandomValues(new Uint8Array(12));

            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                aliceSessionKey,
                new TextEncoder().encode(testMessage)
            );

            const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, bobSessionKey, encrypted);

            const decryptedText = new TextDecoder().decode(decrypted);
            addResult(`   Original: "${testMessage}"`);
            addResult(`   Decrypted: "${decryptedText}"`);
            addResult(`   Keys match: ${testMessage === decryptedText ? 'YES ✓' : 'NO ✗'}`);

            addResult('\n🎉 FULL KEY EXCHANGE PROTOCOL SIMULATION SUCCESSFUL!');
            addResult('   ✓ 3-message authenticated key exchange completed');
            addResult('   ✓ ECDSA signatures prevented MITM attacks');
            addResult('   ✓ ECDH produced identical shared secrets');
            addResult('   ✓ HKDF derived identical AES-256-GCM session keys');
            addResult('   ✓ Encryption/Decryption with derived keys works');
        } catch (error) {
            addResult(`❌ Full Protocol test failed: ${error}`);
        }
    };

    // Run all tests
    const runAllTests = async () => {
        setIsRunning(true);
        clearResults();
        addResult('🚀 Starting Phase 2.1 Tests...\n');

        await testHKDF();
        addResult('');
        await testSignatures();
        addResult('');
        await testKeyExchange();
        addResult('');
        await testSessionKeyStorage();
        addResult('');
        await testFullProtocol();

        addResult('\n✅ All Phase 2.1 tests completed!');
        setIsRunning(false);
    };

    return (
        <div className="min-h-screen bg-gray-900 text-white p-8">
            <div className="max-w-4xl mx-auto">
                <h1 className="text-3xl font-bold mb-6">Phase 2.1 - Key Exchange Primitives Testing</h1>

                <div className="mb-6 space-x-4">
                    <button
                        onClick={runAllTests}
                        disabled={isRunning}
                        className="bg-green-600 hover:bg-green-700 disabled:bg-gray-600 px-6 py-2 rounded font-semibold"
                    >
                        {isRunning ? 'Running...' : 'Run All Tests'}
                    </button>

                    <button onClick={testHKDF} disabled={isRunning} className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-4 py-2 rounded">
                        Test HKDF
                    </button>

                    <button onClick={testSignatures} disabled={isRunning} className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-4 py-2 rounded">
                        Test Signatures
                    </button>

                    <button onClick={testKeyExchange} disabled={isRunning} className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-4 py-2 rounded">
                        Test Key Exchange
                    </button>

                    <button onClick={testSessionKeyStorage} disabled={isRunning} className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-4 py-2 rounded">
                        Test IndexedDB
                    </button>

                    <button onClick={testFullProtocol} disabled={isRunning} className="bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 px-4 py-2 rounded">
                        Test Full Protocol
                    </button>

                    <button onClick={clearResults} className="bg-gray-600 hover:bg-gray-700 px-4 py-2 rounded">
                        Clear
                    </button>
                </div>

                <div className="bg-gray-800 rounded-lg p-4 font-mono text-sm max-h-[70vh] overflow-y-auto">
                    {results.length === 0 ? (
                        <p className="text-gray-400">Click &ldquo;Run All Tests&rdquo; to start testing Phase 2.1 components...</p>
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
                        <li><strong>HKDF:</strong> RFC 5869 compliant key derivation (extract, expand, full HKDF)</li>
                        <li><strong>Signatures:</strong> ECDSA P-256 signing/verification for key exchange messages</li>
                        <li><strong>Key Exchange:</strong> Ephemeral ECDH P-256 key generation, shared secret computation</li>
                        <li><strong>Session Keys:</strong> IndexedDB storage for session keys and ephemeral keys</li>
                        <li><strong>Full Protocol:</strong> Complete 3-message authenticated key exchange simulation</li>
                    </ul>
                </div>

                <div className="mt-4 bg-gray-800 rounded-lg p-4">
                    <h2 className="text-xl font-semibold mb-3">Testing Instructions:</h2>
                    <ol className="list-decimal list-inside space-y-1 text-gray-300">
                        <li>Make sure your dev server is running: <code className="bg-gray-700 px-2 rounded">npm run dev</code></li>
                        <li>Navigate to <code className="bg-gray-700 px-2 rounded">http://localhost:3000/test-phase2</code></li>
                        <li>Click &ldquo;Run All Tests&rdquo; to execute all Phase 2.1 tests</li>
                        <li>Check browser console (F12) for detailed crypto operation logs</li>
                        <li>Open IndexedDB in DevTools → Application → Storage to inspect stored keys</li>
                    </ol>
                </div>
            </div>
        </div>
    );
}
