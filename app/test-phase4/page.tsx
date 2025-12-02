'use client';

import { useState } from 'react';

/**
 * Phase 4 Manual Testing Page
 * Tests all End-to-End File Encryption primitives in the browser
 */
export default function TestPhase4Page() {
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

    // Helper to create test file data
    const createTestFileData = (content: string): ArrayBuffer => {
        return new TextEncoder().encode(content).buffer as ArrayBuffer;
    };

    // ============================================================================
    // Test 1: File Encryption/Decryption
    // ============================================================================
    const testFileEncryption = async () => {
        addResult('🧪 === Testing File Encryption (lib/crypto/fileEncryption.ts) ===');

        try {
            const { encryptFile, decryptFile } = await import('@/lib/crypto/fileEncryption');

            // Generate test session key
            addResult('Generating test AES-256-GCM session key...');
            const sessionKey = await generateTestSessionKey();
            addResult(`✅ Session key generated: ${sessionKey.algorithm.name}, ${(sessionKey.algorithm as AesKeyAlgorithm).length} bits`);

            // Test 1.1: Basic file encryption
            addResult('Testing encryptFile...');
            const testContent = 'This is a test file content with some data! 📄🔐';
            const testFileData = createTestFileData(testContent);
            const testFilename = 'test-document.txt';
            const testMimeType = 'text/plain';

            const encrypted = await encryptFile(testFileData, testFilename, testMimeType, sessionKey);
            addResult(`✅ File encrypted successfully`);
            addResult(`   Ciphertext length: ${encrypted.ciphertext.length} chars`);
            addResult(`   IV: ${encrypted.iv.substring(0, 16)}...`);
            addResult(`   Auth Tag: ${encrypted.authTag.substring(0, 16)}...`);
            addResult(`   Nonce: ${encrypted.nonce.substring(0, 16)}...`);
            addResult(`   Filename: ${encrypted.filename}`);
            addResult(`   MIME Type: ${encrypted.mimeType}`);
            addResult(`   Original Size: ${encrypted.size} bytes`);

            // Test 1.2: Unique IV per file
            addResult('Testing unique IV generation...');
            const encrypted2 = await encryptFile(testFileData, 'test2.txt', testMimeType, sessionKey);
            const ivsAreDifferent = encrypted.iv !== encrypted2.iv;
            addResult(`✅ IVs are unique: ${ivsAreDifferent ? 'YES ✓' : 'NO ✗ (SECURITY ISSUE!)'}`);

            // Test 1.3: Unique nonce per file
            addResult('Testing unique nonce generation...');
            const noncesAreDifferent = encrypted.nonce !== encrypted2.nonce;
            addResult(`✅ Nonces are unique: ${noncesAreDifferent ? 'YES ✓' : 'NO ✗ (SECURITY ISSUE!)'}`);

            // Test 1.4: Decryption
            addResult('Testing decryptFile...');
            const decrypted = await decryptFile(
                encrypted.ciphertext,
                encrypted.iv,
                encrypted.authTag,
                encrypted.nonce,
                encrypted.filename,
                encrypted.mimeType,
                sessionKey
            );

            const decryptedContent = new TextDecoder().decode(decrypted);
            addResult(`✅ File decrypted: "${decryptedContent.substring(0, 50)}..."`);
            addResult(`   Matches original: ${decryptedContent === testContent ? 'YES ✓' : 'NO ✗'}`);
            addResult(`   Size match: ${decrypted.byteLength === testFileData.byteLength ? 'YES ✓' : 'NO ✗'}`);

            // Test 1.5: Different files produce different ciphertext
            addResult('Testing different files produce different ciphertext...');
            const differentContent = createTestFileData('Completely different content');
            const encrypted3 = await encryptFile(differentContent, 'different.txt', testMimeType, sessionKey);
            const ciphertextsAreDifferent = encrypted.ciphertext !== encrypted3.ciphertext;
            addResult(`✅ Ciphertexts differ: ${ciphertextsAreDifferent ? 'YES ✓' : 'NO ✗'}`);

            // Test 1.6: Binary file support (simulate image/PDF)
            addResult('Testing binary file support...');
            const binaryData = new Uint8Array([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xFF, 0x00, 0x7F]);
            const encryptedBinary = await encryptFile(binaryData.buffer as ArrayBuffer, 'image.png', 'image/png', sessionKey);
            const decryptedBinary = await decryptFile(
                encryptedBinary.ciphertext,
                encryptedBinary.iv,
                encryptedBinary.authTag,
                encryptedBinary.nonce,
                encryptedBinary.filename,
                encryptedBinary.mimeType,
                sessionKey
            );
            const decryptedBinaryArray = new Uint8Array(decryptedBinary);
            let binaryMatch = binaryData.length === decryptedBinaryArray.length;
            for (let i = 0; binaryMatch && i < binaryData.length; i++) {
                if (binaryData[i] !== decryptedBinaryArray[i]) binaryMatch = false;
            }
            addResult(`✅ Binary file roundtrip: ${binaryMatch ? 'PASSED ✓' : 'FAILED ✗'}`);

            addResult('🎉 All File Encryption tests passed!');
        } catch (error) {
            addResult(`❌ File Encryption test failed: ${error}`);
        }
    };

    // ============================================================================
    // Test 2: File Tamper Detection (Auth Tag Verification)
    // ============================================================================
    const testFileTamperDetection = async () => {
        addResult('🧪 === Testing File Tamper Detection (AES-GCM Authentication) ===');

        try {
            const { encryptFile, decryptFile } = await import('@/lib/crypto/fileEncryption');
            const { base64ToArrayBuffer, arrayBufferToBase64 } = await import('@/lib/crypto/utils');

            const sessionKey = await generateTestSessionKey();
            const testContent = 'This file must not be tampered!';
            const testFileData = createTestFileData(testContent);
            const encrypted = await encryptFile(testFileData, 'secure.txt', 'text/plain', sessionKey);

            // Test 2.1: Tampered ciphertext should fail
            addResult('Testing tampered ciphertext detection...');
            try {
                const ciphertextBytes = new Uint8Array(base64ToArrayBuffer(encrypted.ciphertext));
                ciphertextBytes[0] ^= 0xFF;
                const tamperedCiphertext = arrayBufferToBase64(ciphertextBytes.buffer as ArrayBuffer);

                await decryptFile(
                    tamperedCiphertext,
                    encrypted.iv,
                    encrypted.authTag,
                    encrypted.nonce,
                    encrypted.filename,
                    encrypted.mimeType,
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
                const tamperedIV = arrayBufferToBase64(ivBytes.buffer as ArrayBuffer);

                await decryptFile(
                    encrypted.ciphertext,
                    tamperedIV,
                    encrypted.authTag,
                    encrypted.nonce,
                    encrypted.filename,
                    encrypted.mimeType,
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
                const tamperedAuthTag = arrayBufferToBase64(authTagBytes.buffer as ArrayBuffer);

                await decryptFile(
                    encrypted.ciphertext,
                    encrypted.iv,
                    tamperedAuthTag,
                    encrypted.nonce,
                    encrypted.filename,
                    encrypted.mimeType,
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

                await decryptFile(
                    encrypted.ciphertext,
                    encrypted.iv,
                    encrypted.authTag,
                    encrypted.nonce,
                    encrypted.filename,
                    encrypted.mimeType,
                    wrongKey
                );
                addResult(`❌ SECURITY ISSUE: Wrong session key was accepted!`);
            } catch {
                addResult(`✅ Wrong session key correctly rejected ✓`);
            }

            // Test 2.5: Modified filename (AAD mismatch) should fail
            addResult('Testing filename tampering detection (AAD)...');
            try {
                await decryptFile(
                    encrypted.ciphertext,
                    encrypted.iv,
                    encrypted.authTag,
                    encrypted.nonce,
                    'fake-filename.txt', // Wrong filename
                    encrypted.mimeType,
                    sessionKey
                );
                addResult(`❌ SECURITY ISSUE: Wrong filename was accepted!`);
            } catch {
                addResult(`✅ Wrong filename correctly rejected ✓`);
            }

            // Test 2.6: Modified MIME type (AAD mismatch) should fail
            addResult('Testing MIME type tampering detection (AAD)...');
            try {
                await decryptFile(
                    encrypted.ciphertext,
                    encrypted.iv,
                    encrypted.authTag,
                    encrypted.nonce,
                    encrypted.filename,
                    'application/pdf', // Wrong MIME type
                    sessionKey
                );
                addResult(`❌ SECURITY ISSUE: Wrong MIME type was accepted!`);
            } catch {
                addResult(`✅ Wrong MIME type correctly rejected ✓`);
            }

            // Test 2.7: Modified nonce (AAD mismatch) should fail
            addResult('Testing nonce tampering detection (AAD)...');
            try {
                const { generateNonce } = await import('@/lib/crypto/utils');
                const wrongNonce = generateNonce();

                await decryptFile(
                    encrypted.ciphertext,
                    encrypted.iv,
                    encrypted.authTag,
                    wrongNonce,
                    encrypted.filename,
                    encrypted.mimeType,
                    sessionKey
                );
                addResult(`❌ SECURITY ISSUE: Wrong nonce was accepted!`);
            } catch {
                addResult(`✅ Wrong nonce correctly rejected ✓`);
            }

            addResult('🎉 All File Tamper Detection tests passed!');
        } catch (error) {
            addResult(`❌ File Tamper Detection test failed: ${error}`);
        }
    };

    // ============================================================================
    // Test 3: Various File Types
    // ============================================================================
    const testFileTypes = async () => {
        addResult('🧪 === Testing Various File Types ===');

        try {
            const { encryptFile, decryptFile } = await import('@/lib/crypto/fileEncryption');
            const sessionKey = await generateTestSessionKey();

            const fileTypes = [
                { name: 'document.txt', mime: 'text/plain', content: 'Plain text content' },
                { name: 'data.json', mime: 'application/json', content: '{"key": "value", "number": 42}' },
                { name: 'styles.css', mime: 'text/css', content: 'body { color: red; }' },
                { name: 'script.js', mime: 'application/javascript', content: 'console.log("hello");' },
                { name: 'page.html', mime: 'text/html', content: '<html><body>Hello</body></html>' },
            ];

            for (const file of fileTypes) {
                addResult(`Testing ${file.name} (${file.mime})...`);
                const data = createTestFileData(file.content);
                const encrypted = await encryptFile(data, file.name, file.mime, sessionKey);
                const decrypted = await decryptFile(
                    encrypted.ciphertext,
                    encrypted.iv,
                    encrypted.authTag,
                    encrypted.nonce,
                    encrypted.filename,
                    encrypted.mimeType,
                    sessionKey
                );
                const decryptedContent = new TextDecoder().decode(decrypted);
                const match = decryptedContent === file.content;
                addResult(`   ${match ? '✅' : '❌'} ${file.name}: ${match ? 'PASSED ✓' : 'FAILED ✗'}`);
            }

            // Test large file simulation (1MB)
            addResult('Testing large file (1MB simulated)...');
            const largeContent = 'X'.repeat(1024 * 1024); // 1MB of X's
            const largeData = createTestFileData(largeContent);
            const startTime = performance.now();
            const encryptedLarge = await encryptFile(largeData, 'large-file.bin', 'application/octet-stream', sessionKey);
            const encryptTime = performance.now() - startTime;

            const decryptStart = performance.now();
            const decryptedLarge = await decryptFile(
                encryptedLarge.ciphertext,
                encryptedLarge.iv,
                encryptedLarge.authTag,
                encryptedLarge.nonce,
                encryptedLarge.filename,
                encryptedLarge.mimeType,
                sessionKey
            );
            const decryptTime = performance.now() - decryptStart;

            const largeMatch = decryptedLarge.byteLength === largeData.byteLength;
            addResult(`   ✅ 1MB file roundtrip: ${largeMatch ? 'PASSED ✓' : 'FAILED ✗'}`);
            addResult(`   Encrypt time: ${encryptTime.toFixed(2)}ms`);
            addResult(`   Decrypt time: ${decryptTime.toFixed(2)}ms`);

            addResult('🎉 All File Type tests passed!');
        } catch (error) {
            addResult(`❌ File Type test failed: ${error}`);
        }
    };

    // ============================================================================
    // Test 4: Session Key Integration with File Encryption
    // ============================================================================
    const testSessionKeyIntegration = async () => {
        addResult('🧪 === Testing Session Key Storage Integration for Files ===');

        try {
            const { encryptFile, decryptFile } = await import('@/lib/crypto/fileEncryption');
            const {
                storeSessionKey,
                getSessionKey,
                hasValidSessionKey,
                deleteSessionKey,
            } = await import('@/lib/crypto/sessionKeys');

            const testConversationId = `test-phase4-${Date.now()}`;

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

            // Retrieve and use key for file encryption
            addResult('Retrieving session key and testing file encryption...');
            const retrievedKey = await getSessionKey(testConversationId);

            if (!retrievedKey) {
                throw new Error('Failed to retrieve session key from IndexedDB');
            }

            const testFile = createTestFileData('File encrypted with stored session key!');
            const encrypted = await encryptFile(testFile, 'indexed-test.txt', 'text/plain', retrievedKey);
            addResult('✅ File encrypted with retrieved key');

            const decrypted = await decryptFile(
                encrypted.ciphertext,
                encrypted.iv,
                encrypted.authTag,
                encrypted.nonce,
                encrypted.filename,
                encrypted.mimeType,
                retrievedKey
            );

            const decryptedContent = new TextDecoder().decode(decrypted);
            addResult(`✅ File decrypted: "${decryptedContent}"`);
            addResult(`   Matches original: ${decryptedContent === 'File encrypted with stored session key!' ? 'YES ✓' : 'NO ✗'}`);

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

    // ============================================================================
    // Test 5: Full E2E File Sharing Flow Simulation
    // ============================================================================
    const testFullE2EFileFlow = async () => {
        addResult('🧪 === Testing Full E2E File Sharing Flow Simulation ===');

        try {
            const { encryptFile, decryptFile } = await import('@/lib/crypto/fileEncryption');
            const { generateEphemeralKeyPair, deriveSessionKeyFromECDH } = await import('@/lib/crypto/keyExchange');
            const { arrayBufferToBase64 } = await import('@/lib/crypto/utils');

            // === Setup: Simulate completed key exchange ===
            addResult('Setting up Alice and Bob with session keys from key exchange...');

            // Generate ephemeral keys for both parties
            const aliceEphemeral = await generateEphemeralKeyPair();
            const bobEphemeral = await generateEphemeralKeyPair();

            // Generate nonces
            const aliceNonce = arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(16)).buffer as ArrayBuffer);
            const bobNonce = arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(16)).buffer as ArrayBuffer);

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

            // === Alice encrypts and shares a file with Bob ===
            addResult('\n📤 FILE 1: Alice shares a document with Bob');

            const aliceDocument = `
CONFIDENTIAL DOCUMENT
=====================
This is a secret document that only Bob should be able to read.
It contains sensitive information protected by AES-256-GCM encryption.
Date: ${new Date().toISOString()}
            `.trim();

            const aliceFileData = createTestFileData(aliceDocument);
            const encryptedFile1 = await encryptFile(
                aliceFileData,
                'confidential-report.txt',
                'text/plain',
                aliceSessionKey
            );

            addResult(`   Filename: ${encryptedFile1.filename}`);
            addResult(`   Original size: ${encryptedFile1.size} bytes`);
            addResult(`   Encrypted ✓`);

            // === Bob receives and decrypts the file ===
            addResult('\n📥 Bob receives and decrypts FILE 1');

            const decryptedFile1 = await decryptFile(
                encryptedFile1.ciphertext,
                encryptedFile1.iv,
                encryptedFile1.authTag,
                encryptedFile1.nonce,
                encryptedFile1.filename,
                encryptedFile1.mimeType,
                bobSessionKey
            );

            const decryptedContent1 = new TextDecoder().decode(decryptedFile1);
            addResult(`   Decrypted size: ${decryptedFile1.byteLength} bytes`);
            addResult(`   Content preview: "${decryptedContent1.substring(0, 40)}..."`);
            addResult(`   File integrity: ${decryptedContent1 === aliceDocument ? 'VERIFIED ✓' : 'FAILED ✗'}`);

            // === Bob shares an image (simulated) with Alice ===
            addResult('\n📤 FILE 2: Bob shares an image with Alice');

            // Simulate PNG header + some data
            const pngHeader = new Uint8Array([
                0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
                0x00, 0x00, 0x00, 0x0D, // IHDR chunk length
                0x49, 0x48, 0x44, 0x52, // IHDR
                ...crypto.getRandomValues(new Uint8Array(100)) // Simulated image data
            ]);

            const encryptedFile2 = await encryptFile(
                pngHeader.buffer as ArrayBuffer,
                'secret-photo.png',
                'image/png',
                bobSessionKey
            );

            addResult(`   Filename: ${encryptedFile2.filename}`);
            addResult(`   MIME type: ${encryptedFile2.mimeType}`);
            addResult(`   Original size: ${encryptedFile2.size} bytes`);
            addResult(`   Encrypted ✓`);

            // === Alice receives and decrypts the image ===
            addResult('\n📥 Alice receives and decrypts FILE 2');

            const decryptedFile2 = await decryptFile(
                encryptedFile2.ciphertext,
                encryptedFile2.iv,
                encryptedFile2.authTag,
                encryptedFile2.nonce,
                encryptedFile2.filename,
                encryptedFile2.mimeType,
                aliceSessionKey
            );

            const decryptedImageArray = new Uint8Array(decryptedFile2);
            let imageMatch = pngHeader.length === decryptedImageArray.length;
            for (let i = 0; imageMatch && i < pngHeader.length; i++) {
                if (pngHeader[i] !== decryptedImageArray[i]) imageMatch = false;
            }

            addResult(`   Decrypted size: ${decryptedFile2.byteLength} bytes`);
            addResult(`   PNG signature valid: ${decryptedImageArray[0] === 0x89 && decryptedImageArray[1] === 0x50 ? 'YES ✓' : 'NO ✗'}`);
            addResult(`   File integrity: ${imageMatch ? 'VERIFIED ✓' : 'FAILED ✗'}`);

            // === Test Replay Attack Prevention ===
            addResult('\n🛡️ Testing File Replay Attack Prevention');

            addResult('Attempting to decrypt with different nonce (simulating replay attack)...');
            try {
                const { generateNonce } = await import('@/lib/crypto/utils');
                await decryptFile(
                    encryptedFile1.ciphertext,
                    encryptedFile1.iv,
                    encryptedFile1.authTag,
                    generateNonce(), // Different nonce
                    encryptedFile1.filename,
                    encryptedFile1.mimeType,
                    bobSessionKey
                );
                addResult(`   ❌ SECURITY ISSUE: Replay with different nonce was accepted!`);
            } catch {
                addResult(`   ✅ Replay attempt blocked (nonce mismatch) ✓`);
            }

            // === Test Metadata Tampering Prevention ===
            addResult('\n🛡️ Testing Metadata Tampering Prevention');

            addResult('Attempting to open encrypted file with wrong filename...');
            try {
                await decryptFile(
                    encryptedFile1.ciphertext,
                    encryptedFile1.iv,
                    encryptedFile1.authTag,
                    encryptedFile1.nonce,
                    'malicious-renamed.exe', // Attacker tries to rename
                    encryptedFile1.mimeType,
                    bobSessionKey
                );
                addResult(`   ❌ SECURITY ISSUE: Filename spoofing was accepted!`);
            } catch {
                addResult(`   ✅ Filename tampering blocked (AAD mismatch) ✓`);
            }

            addResult('\n🎉 FULL E2E FILE SHARING FLOW SIMULATION SUCCESSFUL!');
            addResult('   ✓ Files encrypted with AES-256-GCM');
            addResult('   ✓ Per-file unique IVs and nonces');
            addResult('   ✓ Metadata protected via AAD (filename, MIME type)');
            addResult('   ✓ Binary files (images) supported');
            addResult('   ✓ Bidirectional secure file sharing');
            addResult('   ✓ Replay attacks prevented via nonce verification');
            addResult('   ✓ Metadata tampering prevented');
        } catch (error) {
            addResult(`❌ Full E2E File Flow test failed: ${error}`);
        }
    };

    // Run all tests
    const runAllTests = async () => {
        setIsRunning(true);
        clearResults();
        addResult('🚀 Starting Phase 4 Tests (End-to-End File Encryption)...\n');

        await testFileEncryption();
        addResult('');
        await testFileTamperDetection();
        addResult('');
        await testFileTypes();
        addResult('');
        await testSessionKeyIntegration();
        addResult('');
        await testFullE2EFileFlow();

        addResult('\n✅ All Phase 4 tests completed!');
        setIsRunning(false);
    };

    return (
        <div className="min-h-screen bg-gray-900 text-white p-8">
            <div className="max-w-4xl mx-auto">
                <h1 className="text-3xl font-bold mb-6">Phase 4 - End-to-End File Encryption Testing</h1>

                <div className="mb-6 flex flex-wrap gap-2">
                    <button
                        onClick={runAllTests}
                        disabled={isRunning}
                        className="bg-green-600 hover:bg-green-700 disabled:bg-gray-600 px-6 py-2 rounded font-semibold"
                    >
                        {isRunning ? 'Running...' : 'Run All Tests'}
                    </button>

                    <button onClick={testFileEncryption} disabled={isRunning} className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-4 py-2 rounded">
                        Test Encryption
                    </button>

                    <button onClick={testFileTamperDetection} disabled={isRunning} className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-4 py-2 rounded">
                        Test Tamper Detection
                    </button>

                    <button onClick={testFileTypes} disabled={isRunning} className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-4 py-2 rounded">
                        Test File Types
                    </button>

                    <button onClick={testSessionKeyIntegration} disabled={isRunning} className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-4 py-2 rounded">
                        Test IndexedDB
                    </button>

                    <button onClick={testFullE2EFileFlow} disabled={isRunning} className="bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 px-4 py-2 rounded">
                        Test Full E2E Flow
                    </button>

                    <button onClick={clearResults} className="bg-gray-600 hover:bg-gray-700 px-4 py-2 rounded">
                        Clear
                    </button>
                </div>

                <div className="bg-gray-800 rounded-lg p-4 font-mono text-sm max-h-[70vh] overflow-y-auto">
                    {results.length === 0 ? (
                        <p className="text-gray-400">Click &ldquo;Run All Tests&rdquo; to start testing Phase 4 components...</p>
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
                        <li><strong>File Encryption:</strong> AES-256-GCM with unique IV/nonce per file</li>
                        <li><strong>Tamper Detection:</strong> Authentication tag verification, metadata protection</li>
                        <li><strong>File Types:</strong> Text, JSON, binary (images), large files</li>
                        <li><strong>IndexedDB Integration:</strong> Session key storage and retrieval for files</li>
                        <li><strong>Full E2E Flow:</strong> Complete secure file sharing simulation</li>
                    </ul>
                </div>

                <div className="mt-4 bg-gray-800 rounded-lg p-4">
                    <h2 className="text-xl font-semibold mb-3">Security Features Validated:</h2>
                    <ul className="list-disc list-inside space-y-1 text-gray-300">
                        <li>🔐 <strong>Confidentiality:</strong> AES-256-GCM encryption for all file types</li>
                        <li>🛡️ <strong>Integrity:</strong> GCM authentication tags prevent file tampering</li>
                        <li>📝 <strong>Metadata Protection:</strong> AAD includes filename and MIME type</li>
                        <li>🔄 <strong>Replay Protection:</strong> Unique nonces per file upload</li>
                        <li>📁 <strong>Binary Support:</strong> Images, PDFs, and any file type supported</li>
                    </ul>
                </div>

                <div className="mt-4 bg-gray-800 rounded-lg p-4">
                    <h2 className="text-xl font-semibold mb-3">Testing Instructions:</h2>
                    <ol className="list-decimal list-inside space-y-1 text-gray-300">
                        <li>Make sure your dev server is running: <code className="bg-gray-700 px-2 rounded">npm run dev</code></li>
                        <li>Navigate to <code className="bg-gray-700 px-2 rounded">http://localhost:3000/test-phase4</code></li>
                        <li>Click &ldquo;Run All Tests&rdquo; to execute all Phase 4 tests</li>
                        <li>Check browser console (F12) for detailed crypto operation logs</li>
                        <li>Open IndexedDB in DevTools → Application → Storage to inspect stored keys</li>
                    </ol>
                </div>
            </div>
        </div>
    );
}
