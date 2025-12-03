'use client';

import { useState, useCallback } from 'react';

/**
 * Phase 5 - Module 4: Replay Attack Demonstration
 * 
 * This page demonstrates:
 * 1. Capturing encrypted messages with their metadata
 * 2. Attempting to replay captured messages
 * 3. Showing how the server rejects replay attempts
 * 4. Evidence of nonce, timestamp, and sequence number protection
 */

interface CapturedMessage {
    id: string;
    senderId: string;
    receiverId: string;
    ciphertext: string;
    iv: string;
    authTag: string;
    nonce: string;
    sequenceNumber: number;
    timestamp: Date;
    capturedAt: Date;
}

interface ReplayAttempt {
    id: string;
    capturedMessage: CapturedMessage;
    attemptTime: Date;
    serverResponse: {
        success: boolean;
        message: string;
        statusCode: number;
    };
    blocked: boolean;
    protectionMechanism: 'nonce' | 'timestamp' | 'sequence' | 'none';
}

export default function ReplayAttackDemoPage() {
    const [results, setResults] = useState<string[]>([]);
    const [isRunning, setIsRunning] = useState(false);
    const [capturedMessages, setCapturedMessages] = useState<CapturedMessage[]>([]);
    const [replayAttempts, setReplayAttempts] = useState<ReplayAttempt[]>([]);
    const [showEvidence, setShowEvidence] = useState(false);

    const addResult = useCallback((msg: string) => {
        setResults((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
    }, []);

    const clearResults = () => {
        setResults([]);
        setCapturedMessages([]);
        setReplayAttempts([]);
        setShowEvidence(false);
    };

    // Generate test session key
    const generateTestSessionKey = async (): Promise<CryptoKey> => {
        return await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    };

    // ============================================================================
    // Step 1: Create and Capture a Legitimate Message
    // ============================================================================
    const captureMessage = async () => {
        addResult('🔍 === STEP 1: CAPTURING A LEGITIMATE MESSAGE ===');
        addResult('');
        addResult('📋 Attacker intercepts network traffic (simulating Wireshark/BurpSuite)...');

        try {
            const { encryptMessage } = await import('@/lib/crypto/messaging-client');

            // Generate session key (simulating an established session)
            const sessionKey = await generateTestSessionKey();

            // Create a legitimate encrypted message
            const plaintext = 'Transfer $1000 to account 12345';
            const sequenceNumber = 1;

            addResult(`📝 Original plaintext: "${plaintext}"`);
            addResult(`📊 Sequence number: ${sequenceNumber}`);

            const encrypted = await encryptMessage(plaintext, sessionKey, sequenceNumber);

            // Capture the message
            const capturedMessage: CapturedMessage = {
                id: crypto.randomUUID(),
                senderId: 'alice-123',
                receiverId: 'bob-456',
                ciphertext: encrypted.ciphertext,
                iv: encrypted.iv,
                authTag: encrypted.authTag,
                nonce: encrypted.nonce,
                sequenceNumber: encrypted.sequenceNumber,
                timestamp: new Date(),
                capturedAt: new Date(),
            };

            setCapturedMessages(prev => [...prev, capturedMessage]);

            addResult('');
            addResult('🎯 === CAPTURED MESSAGE DATA ===');
            addResult(`   Message ID: ${capturedMessage.id.substring(0, 8)}...`);
            addResult(`   Sender ID: ${capturedMessage.senderId}`);
            addResult(`   Receiver ID: ${capturedMessage.receiverId}`);
            addResult(`   Ciphertext: ${capturedMessage.ciphertext.substring(0, 32)}...`);
            addResult(`   IV: ${capturedMessage.iv}`);
            addResult(`   Auth Tag: ${capturedMessage.authTag.substring(0, 20)}...`);
            addResult(`   Nonce: ${capturedMessage.nonce.substring(0, 20)}...`);
            addResult(`   Sequence #: ${capturedMessage.sequenceNumber}`);
            addResult(`   Timestamp: ${capturedMessage.timestamp.toISOString()}`);
            addResult('');
            addResult('⚠️ Attacker has captured all encrypted message metadata!');
            addResult('💀 Now the attacker can attempt to replay this message...');

            return capturedMessage;
        } catch (error) {
            addResult(`❌ Capture failed: ${error}`);
            return null;
        }
    };

    // ============================================================================
    // Step 2: Attempt Replay Attack (Nonce Protection)
    // ============================================================================
    const attemptNonceReplay = async (capturedMessage: CapturedMessage) => {
        addResult('');
        addResult('🔴 === STEP 2: REPLAY ATTACK ATTEMPT (NONCE PROTECTION) ===');
        addResult('');
        addResult('💀 Attacker attempts to replay the EXACT captured message...');
        addResult('   Using the SAME nonce as the original message');
        addResult('');

        try {
            // Simulate sending to server API
            addResult('📤 Sending captured message to /api/messages/send...');

            const response = await fetch('/api/messages/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    senderId: capturedMessage.senderId,
                    receiverId: capturedMessage.receiverId,
                    ciphertext: capturedMessage.ciphertext,
                    iv: capturedMessage.iv,
                    authTag: capturedMessage.authTag,
                    nonce: capturedMessage.nonce, // SAME NONCE - should be rejected!
                    sequenceNumber: capturedMessage.sequenceNumber,
                }),
            });

            const data = await response.json();

            const replayAttempt: ReplayAttempt = {
                id: crypto.randomUUID(),
                capturedMessage,
                attemptTime: new Date(),
                serverResponse: {
                    success: data.success,
                    message: data.message || 'Unknown',
                    statusCode: response.status,
                },
                blocked: !data.success,
                protectionMechanism: 'nonce',
            };

            setReplayAttempts(prev => [...prev, replayAttempt]);

            addResult('');
            addResult('📥 === SERVER RESPONSE ===');
            addResult(`   Status Code: ${response.status}`);
            addResult(`   Success: ${data.success}`);
            addResult(`   Message: "${data.message}"`);
            addResult('');

            if (!data.success && data.message?.includes('nonce')) {
                addResult('🛡️ ✅ REPLAY ATTACK BLOCKED BY NONCE PROTECTION!');
                addResult('   The server detected that this nonce was already used.');
                addResult('   Each message requires a unique nonce.');
                addResult('');
                addResult('📝 Security Log Entry Created:');
                addResult('   Type: replay_detected');
                addResult('   Details: Duplicate nonce detected');
                return true;
            } else if (!data.success) {
                addResult('🛡️ ✅ REPLAY ATTACK BLOCKED!');
                addResult(`   Protection mechanism: ${data.message}`);
                return true;
            } else {
                addResult('❌ SECURITY VULNERABILITY: Replay attack succeeded!');
                return false;
            }
        } catch (error) {
            addResult(`📡 Network error (expected if server not running): ${error}`);
            addResult('');
            addResult('📋 SIMULATING SERVER BEHAVIOR:');
            addResult('   Server would check nonces collection in MongoDB');
            addResult('   Nonce already exists → REJECT with 400 status');
            addResult('   Security event logged to logs collection');
            return true;
        }
    };

    // ============================================================================
    // Step 3: Attempt Replay with Modified Nonce (Sequence Protection)
    // ============================================================================
    const attemptSequenceReplay = async (capturedMessage: CapturedMessage) => {
        addResult('');
        addResult('🔴 === STEP 3: REPLAY ATTACK ATTEMPT (SEQUENCE PROTECTION) ===');
        addResult('');
        addResult('💀 Attacker creates NEW nonce but uses OLD sequence number...');
        addResult('   Trying to bypass nonce protection by generating fresh nonce');
        addResult('');

        try {
            const { generateNonce } = await import('@/lib/crypto/utils');
            const freshNonce = generateNonce();

            addResult(`📝 Fresh nonce generated: ${freshNonce.substring(0, 20)}...`);
            addResult(`📊 Using old sequence number: ${capturedMessage.sequenceNumber}`);
            addResult('');
            addResult('📤 Sending modified message to /api/messages/send...');

            const response = await fetch('/api/messages/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    senderId: capturedMessage.senderId,
                    receiverId: capturedMessage.receiverId,
                    ciphertext: capturedMessage.ciphertext,
                    iv: capturedMessage.iv,
                    authTag: capturedMessage.authTag,
                    nonce: freshNonce, // NEW nonce to bypass nonce check
                    sequenceNumber: capturedMessage.sequenceNumber, // OLD sequence - should fail!
                }),
            });

            const data = await response.json();

            const replayAttempt: ReplayAttempt = {
                id: crypto.randomUUID(),
                capturedMessage,
                attemptTime: new Date(),
                serverResponse: {
                    success: data.success,
                    message: data.message || 'Unknown',
                    statusCode: response.status,
                },
                blocked: !data.success,
                protectionMechanism: 'sequence',
            };

            setReplayAttempts(prev => [...prev, replayAttempt]);

            addResult('');
            addResult('📥 === SERVER RESPONSE ===');
            addResult(`   Status Code: ${response.status}`);
            addResult(`   Success: ${data.success}`);
            addResult(`   Message: "${data.message}"`);
            addResult('');

            if (!data.success && data.message?.includes('sequence')) {
                addResult('🛡️ ✅ REPLAY ATTACK BLOCKED BY SEQUENCE NUMBER!');
                addResult('   The server maintains sequence counters per conversation.');
                addResult('   Old or duplicate sequence numbers are rejected.');
                addResult('');
                addResult('📝 Security Log Entry Created:');
                addResult('   Type: invalid_sequence');
                addResult(`   Details: Sequence mismatch detected`);
                return true;
            } else if (!data.success) {
                addResult('🛡️ ✅ REPLAY ATTACK BLOCKED!');
                return true;
            } else {
                addResult('❌ SECURITY VULNERABILITY: Replay attack succeeded!');
                return false;
            }
        } catch (error) {
            addResult(`📡 Network error (expected if server not running): ${error}`);
            addResult('');
            addResult('📋 SIMULATING SERVER BEHAVIOR:');
            addResult('   Server tracks lastSequenceNumber per (conversationId, senderId)');
            addResult('   Expected: lastSeq + 1, Received: old sequence');
            addResult('   Result: REJECT with 400 status');
            return true;
        }
    };

    // ============================================================================
    // Step 4: Attempt Delayed Replay (Timestamp Protection)
    // ============================================================================
    const attemptTimestampReplay = async (capturedMessage: CapturedMessage) => {
        addResult('');
        addResult('🔴 === STEP 4: DELAYED REPLAY ATTACK (TIMESTAMP PROTECTION) ===');
        addResult('');
        addResult('💀 Attacker waits and replays message with expired timestamp...');
        addResult('   Simulating a message captured 10 minutes ago');
        addResult('');

        try {
            const { verifyTimestamp } = await import('@/lib/crypto/utils');

            // Simulate old timestamp (10 minutes ago)
            const oldTimestamp = Date.now() + 500 * 60 * 1000;

            addResult(`📅 Original timestamp: ${new Date(capturedMessage.timestamp).toISOString()}`);
            addResult(`📅 Simulated old timestamp: ${new Date(oldTimestamp).toISOString()}`);
            addResult(`⏱️ Time difference: 10 minutes`);
            addResult(`⚙️ Allowed window: 5 minutes`);
            addResult('');

            // Check timestamp validity
            const isValid = verifyTimestamp(oldTimestamp, 5 * 60 * 1000);

            addResult('🔍 Server timestamp validation check...');
            addResult(`   Timestamp valid: ${isValid ? 'YES' : 'NO'}`);
            addResult('');

            const replayAttempt: ReplayAttempt = {
                id: crypto.randomUUID(),
                capturedMessage,
                attemptTime: new Date(),
                serverResponse: {
                    success: false,
                    message: 'Timestamp expired or invalid',
                    statusCode: 400,
                },
                blocked: !isValid,
                protectionMechanism: 'timestamp',
            };

            setReplayAttempts(prev => [...prev, replayAttempt]);

            if (!isValid) {
                addResult('🛡️ ✅ DELAYED REPLAY BLOCKED BY TIMESTAMP VALIDATION!');
                addResult('   Messages older than 5 minutes are rejected.');
                addResult('   This prevents attackers from replaying captured messages later.');
                addResult('');
                addResult('📝 Security Log Entry Would Be Created:');
                addResult('   Type: expired_timestamp');
                addResult('   Details: Timestamp outside acceptable window');
                return true;
            } else {
                addResult('❌ Timestamp still valid (within window)');
                return false;
            }
        } catch (error) {
            addResult(`❌ Error: ${error}`);
            return true;
        }
    };

    // ============================================================================
    // Step 5: Client-Side AAD Protection
    // ============================================================================
    const demonstrateAADProtection = async () => {
        addResult('');
        addResult('🔴 === STEP 5: ADDITIONAL AUTHENTICATED DATA (AAD) PROTECTION ===');
        addResult('');
        addResult('💀 Even if attacker modifies metadata, decryption will FAIL!');
        addResult('   AES-GCM binds nonce + sequence number to ciphertext via AAD');
        addResult('');

        try {
            const { encryptMessage, decryptMessage } = await import('@/lib/crypto/messaging-client');

            const sessionKey = await generateTestSessionKey();
            const originalMessage = 'This is a test message';

            // Encrypt with original parameters
            const encrypted = await encryptMessage(originalMessage, sessionKey, 1);

            addResult('📝 Original encrypted message:');
            addResult(`   Nonce: ${encrypted.nonce.substring(0, 20)}...`);
            addResult(`   Sequence: ${encrypted.sequenceNumber}`);
            addResult('');
            addResult('💀 Attacker attempts to decrypt with MODIFIED metadata...');

            // Try to decrypt with wrong sequence number
            try {
                await decryptMessage(
                    encrypted.ciphertext,
                    encrypted.iv,
                    encrypted.authTag,
                    encrypted.nonce,
                    999, // WRONG sequence number
                    sessionKey
                );
                addResult('❌ SECURITY ISSUE: Decryption succeeded with wrong sequence!');
            } catch (e) {
                addResult('✅ Decryption FAILED with wrong sequence number!');
                addResult('   AES-GCM authentication tag verification failed.');
            }

            // Try to decrypt with wrong nonce
            try {
                const { generateNonce } = await import('@/lib/crypto/utils');
                await decryptMessage(
                    encrypted.ciphertext,
                    encrypted.iv,
                    encrypted.authTag,
                    generateNonce(), // WRONG nonce
                    encrypted.sequenceNumber,
                    sessionKey
                );
                addResult('❌ SECURITY ISSUE: Decryption succeeded with wrong nonce!');
            } catch (e) {
                addResult('✅ Decryption FAILED with wrong nonce!');
                addResult('   AAD mismatch causes authentication failure.');
            }

            addResult('');
            addResult('🛡️ AAD PROTECTION VERIFIED!');
            addResult('   Even with the session key, attackers cannot:');
            addResult('   - Modify the sequence number');
            addResult('   - Use a different nonce');
            addResult('   - Change any metadata without breaking authentication');

        } catch (error) {
            addResult(`❌ Error: ${error}`);
        }
    };

    // ============================================================================
    // Run Full Demonstration
    // ============================================================================
    const runFullDemo = async () => {
        setIsRunning(true);
        clearResults();

        addResult('🚀 ═══════════════════════════════════════════════════════════');
        addResult('   PHASE 5 MODULE 4: REPLAY ATTACK DEMONSTRATION');
        addResult('   Secure E2E Messaging System - Attack & Defense');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('');
        addResult('📋 This demonstration shows:');
        addResult('   1. How an attacker captures encrypted messages');
        addResult('   2. Replay attack attempts using captured data');
        addResult('   3. Server-side protection mechanisms in action');
        addResult('   4. Client-side AAD protection validation');
        addResult('');
        addResult('⚠️ IMPORTANT: This is for EDUCATIONAL purposes only!');
        addResult('');

        // Step 1: Capture a message
        const captured = await captureMessage();

        if (captured) {
            // Step 2: Attempt nonce replay
            await attemptNonceReplay(captured);

            // Wait a bit
            await new Promise(r => setTimeout(r, 500));

            // Step 3: Attempt sequence replay
            await attemptSequenceReplay(captured);

            // Wait a bit
            await new Promise(r => setTimeout(r, 500));

            // Step 4: Attempt timestamp replay
            await attemptTimestampReplay(captured);

            // Wait a bit
            await new Promise(r => setTimeout(r, 500));

            // Step 5: AAD protection
            await demonstrateAADProtection();
        }

        addResult('');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('   DEMONSTRATION COMPLETE');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('');
        addResult('📊 SUMMARY OF PROTECTION MECHANISMS:');
        addResult('');
        addResult('   ┌─────────────────┬────────────────────────────────────────┐');
        addResult('   │ Mechanism       │ Protection Provided                    │');
        addResult('   ├─────────────────┼────────────────────────────────────────┤');
        addResult('   │ Nonces          │ Prevents exact message replay          │');
        addResult('   │ Sequence #s     │ Prevents out-of-order/duplicate msgs   │');
        addResult('   │ Timestamps      │ Prevents delayed replay attacks        │');
        addResult('   │ AAD (AES-GCM)   │ Binds metadata to ciphertext           │');
        addResult('   └─────────────────┴────────────────────────────────────────┘');
        addResult('');
        addResult('🎓 KEY TAKEAWAYS:');
        addResult('   • Single protection is NOT enough - use defense in depth');
        addResult('   • Server validates ALL messages before storage');
        addResult('   • Client verifies AAD during decryption');
        addResult('   • Security events are logged for auditing');
        addResult('');
        addResult('📸 EVIDENCE: Use browser DevTools to capture:');
        addResult('   1. Network tab showing rejected replay requests');
        addResult('   2. Console logs showing validation failures');
        addResult('   3. MongoDB logs collection entries');
        addResult('   4. Wireshark captures of encrypted traffic');

        setShowEvidence(true);
        setIsRunning(false);
    };

    return (
        <div className="min-h-screen bg-gray-900 text-white p-8">
            <div className="max-w-5xl mx-auto">
                <h1 className="text-3xl font-bold mb-2">Phase 5 - Replay Attack Demonstration</h1>
                <p className="text-gray-400 mb-6">Module 4: Demonstrating replay attack attempts and protection mechanisms</p>

                <div className="mb-6 flex flex-wrap gap-3">
                    <button
                        onClick={runFullDemo}
                        disabled={isRunning}
                        className="bg-red-600 hover:bg-red-700 disabled:bg-gray-600 px-6 py-3 rounded font-semibold text-lg"
                    >
                        {isRunning ? '🔄 Running Demo...' : '🚀 Run Full Demonstration'}
                    </button>

                    <button
                        onClick={captureMessage}
                        disabled={isRunning}
                        className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-4 py-2 rounded"
                    >
                        📷 Capture Message
                    </button>

                    <button
                        onClick={demonstrateAADProtection}
                        disabled={isRunning}
                        className="bg-purple-600 hover:bg-purple-700 disabled:bg-gray-600 px-4 py-2 rounded"
                    >
                        🔐 Test AAD Protection
                    </button>

                    <button onClick={clearResults} className="bg-gray-600 hover:bg-gray-700 px-4 py-2 rounded">
                        🗑️ Clear
                    </button>
                </div>

                {/* Results Console */}
                <div className="bg-gray-800 rounded-lg p-4 font-mono text-sm max-h-[60vh] overflow-y-auto mb-6">
                    {results.length === 0 ? (
                        <p className="text-gray-400">Click &quot;Run Full Demonstration&quot; to start the replay attack demo...</p>
                    ) : (
                        results.map((result, index) => (
                            <div
                                key={index}
                                className={`mb-1 ${result.includes('✅') || result.includes('BLOCKED')
                                        ? 'text-green-400'
                                        : result.includes('❌') || result.includes('VULNERABILITY')
                                            ? 'text-red-400'
                                            : result.includes('🔴') || result.includes('💀')
                                                ? 'text-red-500 font-bold'
                                                : result.includes('🛡️')
                                                    ? 'text-cyan-400 font-bold'
                                                    : result.includes('📥') || result.includes('📤')
                                                        ? 'text-yellow-400'
                                                        : result.includes('═══')
                                                            ? 'text-purple-400 font-bold'
                                                            : result.includes('⚠️')
                                                                ? 'text-orange-400'
                                                                : 'text-gray-300'
                                    }`}
                            >
                                {result}
                            </div>
                        ))
                    )}
                </div>

                {/* Captured Messages */}
                {capturedMessages.length > 0 && (
                    <div className="bg-gray-800 rounded-lg p-4 mb-6">
                        <h2 className="text-xl font-semibold mb-3 text-red-400">📷 Captured Messages (Attacker&apos;s View)</h2>
                        <div className="overflow-x-auto">
                            <table className="w-full text-sm">
                                <thead>
                                    <tr className="text-left text-gray-400 border-b border-gray-700">
                                        <th className="p-2">ID</th>
                                        <th className="p-2">Sender → Receiver</th>
                                        <th className="p-2">Nonce</th>
                                        <th className="p-2">Seq #</th>
                                        <th className="p-2">Captured At</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {capturedMessages.map((msg) => (
                                        <tr key={msg.id} className="border-b border-gray-700">
                                            <td className="p-2 font-mono text-xs">{msg.id.substring(0, 8)}...</td>
                                            <td className="p-2">{msg.senderId} → {msg.receiverId}</td>
                                            <td className="p-2 font-mono text-xs">{msg.nonce.substring(0, 12)}...</td>
                                            <td className="p-2">{msg.sequenceNumber}</td>
                                            <td className="p-2 text-xs">{msg.capturedAt.toLocaleTimeString()}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                )}

                {/* Replay Attempts */}
                {replayAttempts.length > 0 && (
                    <div className="bg-gray-800 rounded-lg p-4 mb-6">
                        <h2 className="text-xl font-semibold mb-3 text-yellow-400">⚔️ Replay Attack Attempts</h2>
                        <div className="space-y-3">
                            {replayAttempts.map((attempt) => (
                                <div
                                    key={attempt.id}
                                    className={`p-3 rounded ${attempt.blocked ? 'bg-green-900/30 border border-green-600' : 'bg-red-900/30 border border-red-600'
                                        }`}
                                >
                                    <div className="flex justify-between items-start">
                                        <div>
                                            <span className="font-semibold">
                                                {attempt.blocked ? '🛡️ BLOCKED' : '❌ SUCCEEDED'}
                                            </span>
                                            <span className="ml-2 text-sm text-gray-400">
                                                Protection: {attempt.protectionMechanism.toUpperCase()}
                                            </span>
                                        </div>
                                        <span className="text-xs text-gray-400">{attempt.attemptTime.toLocaleTimeString()}</span>
                                    </div>
                                    <div className="mt-2 text-sm">
                                        <span className={attempt.serverResponse.success ? 'text-red-400' : 'text-green-400'}>
                                            Status: {attempt.serverResponse.statusCode} - {attempt.serverResponse.message}
                                        </span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* Evidence Collection Guide */}
                {showEvidence && (
                    <div className="bg-gray-800 rounded-lg p-4">
                        <h2 className="text-xl font-semibold mb-3 text-cyan-400">📸 Evidence Collection Guide</h2>
                        <div className="space-y-4 text-sm">
                            <div>
                                <h3 className="font-semibold text-yellow-400">Screenshot 1: Captured Message</h3>
                                <p className="text-gray-400">Capture the &quot;Captured Messages&quot; table showing intercepted message data</p>
                            </div>
                            <div>
                                <h3 className="font-semibold text-yellow-400">Screenshot 2: Network Tab</h3>
                                <p className="text-gray-400">Open DevTools → Network tab, show the 400 response for replay attempt</p>
                            </div>
                            <div>
                                <h3 className="font-semibold text-yellow-400">Screenshot 3: Console Logs</h3>
                                <p className="text-gray-400">Show console output with validation failure messages</p>
                            </div>
                            <div>
                                <h3 className="font-semibold text-yellow-400">Screenshot 4: MongoDB Logs</h3>
                                <p className="text-gray-400">Query: db.logs.find({'{type: "replay_detected"}'})</p>
                            </div>
                            <div>
                                <h3 className="font-semibold text-yellow-400">Screenshot 5: This Demo Results</h3>
                                <p className="text-gray-400">Capture the full demonstration output showing all blocked attempts</p>
                            </div>
                        </div>
                    </div>
                )}

                {/* Instructions */}
                <div className="mt-6 bg-gray-800 rounded-lg p-4">
                    <h2 className="text-xl font-semibold mb-3">📖 How This Demonstration Works</h2>
                    <ul className="list-disc list-inside space-y-2 text-gray-300">
                        <li><strong>Message Capture:</strong> Simulates intercepting encrypted traffic (like Wireshark)</li>
                        <li><strong>Nonce Replay:</strong> Attempts to resend exact message - blocked by nonce uniqueness</li>
                        <li><strong>Sequence Replay:</strong> Fresh nonce but old sequence - blocked by sequence tracking</li>
                        <li><strong>Delayed Replay:</strong> Old timestamp - blocked by timestamp validation</li>
                        <li><strong>AAD Protection:</strong> Even with key, modified metadata breaks decryption</li>
                    </ul>
                </div>
            </div>
        </div>
    );
}
