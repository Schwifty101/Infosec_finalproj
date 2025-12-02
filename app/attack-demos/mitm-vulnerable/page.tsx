'use client';

import { useState, useCallback } from 'react';

/**
 * Phase 5 - Module 5: MITM Attack Demonstration (Vulnerable DH)
 * 
 * This page demonstrates:
 * 1. Unsigned DH key exchange (VULNERABLE to MITM)
 * 2. How an attacker intercepts and modifies key exchange
 * 3. Successful MITM attack allowing message interception
 * 4. Why signatures are CRITICAL for authentication
 */

interface KeyPair {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    publicKeyJwk: string;
}

interface DHMessage {
    from: string;
    to: string;
    publicKey: string;
    type: 'KEY_EXCHANGE_INIT' | 'KEY_EXCHANGE_RESPONSE';
}

interface InterceptedMessage {
    original: DHMessage;
    modified: DHMessage;
    description: string;
}

export default function MITMVulnerableDemoPage() {
    const [results, setResults] = useState<string[]>([]);
    const [isRunning, setIsRunning] = useState(false);
    const [attackPhase, setAttackPhase] = useState<'none' | 'setup' | 'intercept' | 'complete'>('none');
    const [interceptedMessages, setInterceptedMessages] = useState<InterceptedMessage[]>([]);

    const addResult = useCallback((msg: string) => {
        setResults((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
    }, []);

    const clearResults = () => {
        setResults([]);
        setInterceptedMessages([]);
        setAttackPhase('none');
    };

    // ============================================================================
    // Generate ECDH Key Pair (for DH simulation)
    // ============================================================================
    const generateKeyPair = async (owner: string): Promise<KeyPair> => {
        const keyPair = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveKey', 'deriveBits']
        );

        const publicKeyJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', keyPair.publicKey));

        addResult(`🔑 ${owner} generated ECDH key pair`);
        addResult(`   Public key: ${publicKeyJwk.substring(0, 40)}...`);

        return {
            privateKey: keyPair.privateKey,
            publicKey: keyPair.publicKey,
            publicKeyJwk,
        };
    };

    // ============================================================================
    // Derive Session Key from ECDH
    // ============================================================================
    const deriveSessionKey = async (
        privateKey: CryptoKey,
        peerPublicKeyJwk: string,
        label: string
    ): Promise<CryptoKey> => {
        const peerPublicKey = await crypto.subtle.importKey(
            'jwk',
            JSON.parse(peerPublicKeyJwk),
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            []
        );

        const sharedSecret = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: peerPublicKey },
            privateKey,
            256
        );

        const sessionKey = await crypto.subtle.importKey(
            'raw',
            sharedSecret,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );

        addResult(`🔐 ${label} derived session key`);
        return sessionKey;
    };

    // ============================================================================
    // Encrypt Message
    // ============================================================================
    const encryptMessage = async (
        message: string,
        sessionKey: CryptoKey
    ): Promise<{ ciphertext: string; iv: string }> => {
        const encoder = new TextEncoder();
        const iv = crypto.getRandomValues(new Uint8Array(12));

        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            sessionKey,
            encoder.encode(message)
        );

        return {
            ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
            iv: btoa(String.fromCharCode(...iv)),
        };
    };

    // ============================================================================
    // Decrypt Message
    // ============================================================================
    const decryptMessage = async (
        ciphertext: string,
        iv: string,
        sessionKey: CryptoKey
    ): Promise<string> => {
        const decoder = new TextDecoder();
        const ciphertextBytes = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
        const ivBytes = Uint8Array.from(atob(iv), c => c.charCodeAt(0));

        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: ivBytes },
            sessionKey,
            ciphertextBytes
        );

        return decoder.decode(plaintext);
    };

    // ============================================================================
    // Normal DH Exchange (Without MITM)
    // ============================================================================
    const demonstrateNormalDH = async () => {
        addResult('');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('   SCENARIO 1: NORMAL DH KEY EXCHANGE (No Attacker)');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('');

        // Alice generates key pair
        addResult('👩 ALICE: Initiating key exchange with Bob...');
        const aliceKeys = await generateKeyPair('Alice');

        addResult('');
        addResult('📤 Alice → Bob: Sending public key (KEY_EXCHANGE_INIT)');
        addResult(`   Public Key: ${aliceKeys.publicKeyJwk.substring(0, 50)}...`);
        addResult('');

        // Bob generates key pair
        addResult('👨 BOB: Received Alice\'s public key, responding...');
        const bobKeys = await generateKeyPair('Bob');

        addResult('');
        addResult('📤 Bob → Alice: Sending public key (KEY_EXCHANGE_RESPONSE)');
        addResult(`   Public Key: ${bobKeys.publicKeyJwk.substring(0, 50)}...`);
        addResult('');

        // Both derive session keys
        addResult('🔄 Both parties computing session keys...');
        const aliceSessionKey = await deriveSessionKey(aliceKeys.privateKey, bobKeys.publicKeyJwk, 'Alice');
        const bobSessionKey = await deriveSessionKey(bobKeys.privateKey, aliceKeys.publicKeyJwk, 'Bob');

        // Verify keys match by encrypting/decrypting
        addResult('');
        addResult('🧪 Testing secure communication...');
        const testMessage = 'Hello Bob! This is a secret message.';
        addResult(`   Alice encrypts: "${testMessage}"`);

        const encrypted = await encryptMessage(testMessage, aliceSessionKey);
        addResult(`   Ciphertext: ${encrypted.ciphertext.substring(0, 30)}...`);

        const decrypted = await decryptMessage(encrypted.ciphertext, encrypted.iv, bobSessionKey);
        addResult(`   Bob decrypts: "${decrypted}"`);

        addResult('');
        addResult('✅ SUCCESS: Secure communication established!');
        addResult('   Both parties share the same session key.');
        addResult('   Messages are encrypted end-to-end.');
        addResult('');
        addResult('⚠️ BUT WAIT... This exchange had NO AUTHENTICATION!');
        addResult('   How does Alice know she\'s really talking to Bob?');
        addResult('   How does Bob know he\'s really talking to Alice?');
        addResult('');
    };

    // ============================================================================
    // MITM Attack Demonstration
    // ============================================================================
    const demonstrateMITMAttack = async () => {
        setAttackPhase('setup');
        addResult('');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('   SCENARIO 2: MAN-IN-THE-MIDDLE ATTACK');
        addResult('   ⚠️ CRITICAL VULNERABILITY: Unsigned DH Key Exchange');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('');
        addResult('🦹 MALLORY (Attacker) positions herself between Alice and Bob');
        addResult('   She can intercept and modify all network traffic');
        addResult('');

        // Step 1: Alice initiates
        addResult('═══ PHASE 1: KEY EXCHANGE INTERCEPTION ═══');
        addResult('');
        addResult('👩 ALICE: Initiating key exchange with "Bob"...');
        const aliceKeys = await generateKeyPair('Alice');

        addResult('');
        addResult('📤 Alice → [Network] → Bob');
        addResult('   Message: KEY_EXCHANGE_INIT with Alice\'s public key');
        addResult('');

        setAttackPhase('intercept');

        // Mallory intercepts
        addResult('🦹 MALLORY INTERCEPTS THE MESSAGE!');
        addResult('   ├─ Received Alice\'s public key');
        addResult('   ├─ Generating her OWN key pair...');

        const malloryKeysForAlice = await generateKeyPair('Mallory (for Alice)');
        const malloryKeysForBob = await generateKeyPair('Mallory (for Bob)');

        addResult('   └─ Substituting HER public key for Alice\'s!');
        addResult('');

        setInterceptedMessages(prev => [...prev, {
            original: {
                from: 'Alice',
                to: 'Bob',
                publicKey: aliceKeys.publicKeyJwk.substring(0, 40) + '...',
                type: 'KEY_EXCHANGE_INIT',
            },
            modified: {
                from: 'Alice (spoofed)',
                to: 'Bob',
                publicKey: malloryKeysForBob.publicKeyJwk.substring(0, 40) + '...',
                type: 'KEY_EXCHANGE_INIT',
            },
            description: 'Mallory replaced Alice\'s public key with her own',
        }]);

        addResult('📤 [Mallory] → Bob');
        addResult('   Message: KEY_EXCHANGE_INIT with MALLORY\'s public key');
        addResult('   (Bob thinks this is from Alice!)');
        addResult('');

        // Bob responds
        addResult('👨 BOB: Received "Alice\'s" public key, responding...');
        const bobKeys = await generateKeyPair('Bob');

        addResult('');
        addResult('📤 Bob → [Network] → Alice');
        addResult('   Message: KEY_EXCHANGE_RESPONSE with Bob\'s public key');
        addResult('');

        // Mallory intercepts response
        addResult('🦹 MALLORY INTERCEPTS BOB\'S RESPONSE!');
        addResult('   ├─ Received Bob\'s public key');
        addResult('   └─ Substituting HER public key for Bob\'s!');
        addResult('');

        setInterceptedMessages(prev => [...prev, {
            original: {
                from: 'Bob',
                to: 'Alice',
                publicKey: bobKeys.publicKeyJwk.substring(0, 40) + '...',
                type: 'KEY_EXCHANGE_RESPONSE',
            },
            modified: {
                from: 'Bob (spoofed)',
                to: 'Alice',
                publicKey: malloryKeysForAlice.publicKeyJwk.substring(0, 40) + '...',
                type: 'KEY_EXCHANGE_RESPONSE',
            },
            description: 'Mallory replaced Bob\'s public key with her own',
        }]);

        addResult('📤 [Mallory] → Alice');
        addResult('   Message: KEY_EXCHANGE_RESPONSE with MALLORY\'s public key');
        addResult('   (Alice thinks this is from Bob!)');
        addResult('');

        // Session key derivation
        addResult('═══ PHASE 2: SESSION KEY DERIVATION ═══');
        addResult('');
        addResult('🔄 All parties computing session keys...');
        addResult('');

        // Alice derives key with Mallory's key (thinking it's Bob)
        const aliceSessionKey = await deriveSessionKey(
            aliceKeys.privateKey,
            malloryKeysForAlice.publicKeyJwk,
            'Alice (with Mallory\'s key)'
        );

        // Mallory derives key for Alice
        const malloryAliceSessionKey = await deriveSessionKey(
            malloryKeysForAlice.privateKey,
            aliceKeys.publicKeyJwk,
            'Mallory (for Alice channel)'
        );

        // Mallory derives key for Bob
        const malloryBobSessionKey = await deriveSessionKey(
            malloryKeysForBob.privateKey,
            bobKeys.publicKeyJwk,
            'Mallory (for Bob channel)'
        );

        // Bob derives key with Mallory's key (thinking it's Alice)
        const bobSessionKey = await deriveSessionKey(
            bobKeys.privateKey,
            malloryKeysForBob.publicKeyJwk,
            'Bob (with Mallory\'s key)'
        );

        addResult('');
        addResult('⚠️ KEY SITUATION:');
        addResult('   Alice ↔ Mallory: Shared session key A-M');
        addResult('   Mallory ↔ Bob: Shared session key M-B');
        addResult('   Alice and Bob do NOT share a key!');
        addResult('');

        // Attack demonstration
        addResult('═══ PHASE 3: MESSAGE INTERCEPTION ═══');
        addResult('');
        addResult('👩 ALICE sends a secret message to "Bob":');
        const aliceMessage = 'Bob, please transfer $10,000 to account 12345';
        addResult(`   Original: "${aliceMessage}"`);

        const aliceEncrypted = await encryptMessage(aliceMessage, aliceSessionKey);
        addResult(`   Encrypted: ${aliceEncrypted.ciphertext.substring(0, 30)}...`);
        addResult('');

        addResult('🦹 MALLORY intercepts and decrypts:');
        const malloryDecrypted = await decryptMessage(
            aliceEncrypted.ciphertext,
            aliceEncrypted.iv,
            malloryAliceSessionKey
        );
        addResult(`   Decrypted: "${malloryDecrypted}"`);
        addResult('');

        addResult('🦹 MALLORY modifies the message:');
        const modifiedMessage = 'Bob, please transfer $10,000 to account 99999';
        addResult(`   Modified: "${modifiedMessage}"`);

        const malloryReEncrypted = await encryptMessage(modifiedMessage, malloryBobSessionKey);
        addResult(`   Re-encrypted for Bob: ${malloryReEncrypted.ciphertext.substring(0, 30)}...`);
        addResult('');

        addResult('👨 BOB receives and decrypts:');
        const bobDecrypted = await decryptMessage(
            malloryReEncrypted.ciphertext,
            malloryReEncrypted.iv,
            bobSessionKey
        );
        addResult(`   Decrypted: "${bobDecrypted}"`);
        addResult('');

        setAttackPhase('complete');

        addResult('💀 ═══════════════════════════════════════════════════════════════');
        addResult('   ATTACK SUCCESSFUL!');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('');
        addResult('📊 ATTACK SUMMARY:');
        addResult('   ├─ Alice thinks she\'s talking to Bob ❌');
        addResult('   ├─ Bob thinks he\'s talking to Alice ❌');
        addResult('   ├─ Mallory reads ALL messages');
        addResult('   ├─ Mallory can MODIFY any message');
        addResult('   └─ Neither Alice nor Bob can detect this!');
        addResult('');
        addResult('🔑 ROOT CAUSE:');
        addResult('   The DH key exchange has NO AUTHENTICATION!');
        addResult('   There\'s no way to verify who you\'re exchanging keys with.');
        addResult('');
        addResult('💡 SOLUTION:');
        addResult('   Use DIGITAL SIGNATURES to authenticate public keys!');
        addResult('   Each party signs their ephemeral public key with their');
        addResult('   long-term identity key. This proves key ownership.');
        addResult('');
        addResult('➡️ See Module 6 to see how AECDH-ECDSA prevents this attack!');
    };

    // ============================================================================
    // Run Full Demonstration
    // ============================================================================
    const runFullDemo = async () => {
        setIsRunning(true);
        clearResults();

        addResult('🚀 ═══════════════════════════════════════════════════════════════');
        addResult('   PHASE 5 MODULE 5: MITM ATTACK ON UNSIGNED DH');
        addResult('   Demonstrating the VULNERABILITY of unauthenticated key exchange');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('');
        addResult('📋 This demonstration shows:');
        addResult('   1. Normal DH key exchange (without attacker)');
        addResult('   2. MITM attack on the same protocol');
        addResult('   3. How attackers can read and modify all messages');
        addResult('   4. Why authentication (signatures) is CRITICAL');
        addResult('');

        await demonstrateNormalDH();

        await new Promise(r => setTimeout(r, 1000));

        await demonstrateMITMAttack();

        addResult('');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('   DEMONSTRATION COMPLETE');
        addResult('═══════════════════════════════════════════════════════════════');

        setIsRunning(false);
    };

    return (
        <div className="min-h-screen bg-gray-900 text-white p-8">
            <div className="max-w-5xl mx-auto">
                <h1 className="text-3xl font-bold mb-2 text-red-500">⚠️ MITM Attack Demo (Vulnerable DH)</h1>
                <p className="text-gray-400 mb-6">Module 5: Demonstrating MITM attack on unsigned Diffie-Hellman key exchange</p>

                <div className="mb-6 flex flex-wrap gap-3">
                    <button
                        onClick={runFullDemo}
                        disabled={isRunning}
                        className="bg-red-600 hover:bg-red-700 disabled:bg-gray-600 px-6 py-3 rounded font-semibold text-lg"
                    >
                        {isRunning ? '🔄 Running Demo...' : '💀 Run MITM Attack Demo'}
                    </button>

                    <button
                        onClick={demonstrateNormalDH}
                        disabled={isRunning}
                        className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-4 py-2 rounded"
                    >
                        ✅ Show Normal DH
                    </button>

                    <button
                        onClick={demonstrateMITMAttack}
                        disabled={isRunning}
                        className="bg-red-600 hover:bg-red-700 disabled:bg-gray-600 px-4 py-2 rounded"
                    >
                        💀 Show MITM Attack
                    </button>

                    <button onClick={clearResults} className="bg-gray-600 hover:bg-gray-700 px-4 py-2 rounded">
                        🗑️ Clear
                    </button>
                </div>

                {/* Attack Phase Indicator */}
                {attackPhase !== 'none' && (
                    <div className="mb-4 p-4 bg-gray-800 rounded-lg">
                        <h3 className="text-lg font-semibold mb-2">Attack Progress</h3>
                        <div className="flex gap-2">
                            <span className={`px-3 py-1 rounded ${attackPhase === 'setup' ? 'bg-yellow-600' : (attackPhase === 'intercept' || attackPhase === 'complete') ? 'bg-green-600' : 'bg-gray-600'}`}>
                                1. Setup
                            </span>
                            <span className={`px-3 py-1 rounded ${attackPhase === 'intercept' ? 'bg-yellow-600' : attackPhase === 'complete' ? 'bg-green-600' : 'bg-gray-600'}`}>
                                2. Intercept
                            </span>
                            <span className={`px-3 py-1 rounded ${attackPhase === 'complete' ? 'bg-red-600' : 'bg-gray-600'}`}>
                                3. Attack Complete
                            </span>
                        </div>
                    </div>
                )}

                {/* Results Console */}
                <div className="bg-gray-800 rounded-lg p-4 font-mono text-sm max-h-[50vh] overflow-y-auto mb-6">
                    {results.length === 0 ? (
                        <p className="text-gray-400">Click &quot;Run MITM Attack Demo&quot; to start the demonstration...</p>
                    ) : (
                        results.map((result, index) => (
                            <div
                                key={index}
                                className={`mb-1 ${result.includes('✅') || result.includes('SUCCESS')
                                        ? 'text-green-400'
                                        : result.includes('❌') || result.includes('💀') || result.includes('ATTACK')
                                            ? 'text-red-400'
                                            : result.includes('🦹') || result.includes('MALLORY')
                                                ? 'text-red-500 font-bold'
                                                : result.includes('👩') || result.includes('ALICE')
                                                    ? 'text-pink-400'
                                                    : result.includes('👨') || result.includes('BOB')
                                                        ? 'text-blue-400'
                                                        : result.includes('═══')
                                                            ? 'text-purple-400 font-bold'
                                                            : result.includes('⚠️')
                                                                ? 'text-yellow-400'
                                                                : result.includes('📤')
                                                                    ? 'text-cyan-400'
                                                                    : result.includes('💡')
                                                                        ? 'text-green-400 font-bold'
                                                                        : 'text-gray-300'
                                    }`}
                            >
                                {result}
                            </div>
                        ))
                    )}
                </div>

                {/* Intercepted Messages */}
                {interceptedMessages.length > 0 && (
                    <div className="bg-gray-800 rounded-lg p-4 mb-6">
                        <h2 className="text-xl font-semibold mb-3 text-red-400">🦹 Intercepted & Modified Messages</h2>
                        <div className="space-y-4">
                            {interceptedMessages.map((msg, i) => (
                                <div key={i} className="grid grid-cols-2 gap-4">
                                    <div className="bg-gray-700 p-3 rounded border border-green-600">
                                        <h4 className="text-green-400 font-semibold mb-2">Original Message</h4>
                                        <p className="text-sm"><strong>From:</strong> {msg.original.from}</p>
                                        <p className="text-sm"><strong>To:</strong> {msg.original.to}</p>
                                        <p className="text-sm"><strong>Type:</strong> {msg.original.type}</p>
                                        <p className="text-sm font-mono text-xs mt-2">{msg.original.publicKey}</p>
                                    </div>
                                    <div className="bg-gray-700 p-3 rounded border border-red-600">
                                        <h4 className="text-red-400 font-semibold mb-2">Modified by Mallory</h4>
                                        <p className="text-sm"><strong>From:</strong> {msg.modified.from}</p>
                                        <p className="text-sm"><strong>To:</strong> {msg.modified.to}</p>
                                        <p className="text-sm"><strong>Type:</strong> {msg.modified.type}</p>
                                        <p className="text-sm font-mono text-xs mt-2">{msg.modified.publicKey}</p>
                                        <p className="text-xs text-red-400 mt-2">{msg.description}</p>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* Visual Attack Diagram */}
                <div className="bg-gray-800 rounded-lg p-4 mb-6">
                    <h2 className="text-xl font-semibold mb-3">🖼️ MITM Attack Diagram</h2>
                    <div className="font-mono text-sm bg-gray-900 p-4 rounded">
                        <pre className="text-gray-300">
                            {`
┌─────────────────────────────────────────────────────────────────────┐
│                    NORMAL DH KEY EXCHANGE                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   👩 Alice                                              👨 Bob       │
│      │                                                    │          │
│      │─── PK_A (Alice's public key) ─────────────────────>│          │
│      │                                                    │          │
│      │<── PK_B (Bob's public key) ────────────────────────│          │
│      │                                                    │          │
│      │  SharedKey = DH(SK_A, PK_B) = DH(SK_B, PK_A)      │          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                    MITM ATTACK ON DH                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   👩 Alice            🦹 Mallory              👨 Bob                 │
│      │                    │                      │                   │
│      │─── PK_A ──────────>│ (intercept)          │                   │
│      │                    │──── PK_M1 ──────────>│  (send Mallory's) │
│      │                    │                      │                   │
│      │                    │<─── PK_B ────────────│  (intercept)      │
│      │<── PK_M2 ──────────│                      │  (send Mallory's) │
│      │                    │                      │                   │
│      │                    │                      │                   │
│      │  Key_AM            │  Key_AM + Key_MB     │  Key_MB          │
│      │  (thinks it's Bob) │  (has BOTH keys!)    │  (thinks Alice)  │
│                                                                      │
│   Result: Mallory can decrypt, read, and modify ALL messages!       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
`}
                        </pre>
                    </div>
                </div>

                {/* Why This Works */}
                <div className="bg-gray-800 rounded-lg p-4 mb-6">
                    <h2 className="text-xl font-semibold mb-3 text-yellow-400">⚠️ Why Does This Attack Work?</h2>
                    <ul className="list-disc list-inside space-y-2 text-gray-300">
                        <li><strong>No Authentication:</strong> DH alone does not verify WHO you are exchanging keys with</li>
                        <li><strong>Public Keys Are Not Signed:</strong> Anyone can generate and send a public key</li>
                        <li><strong>No Identity Binding:</strong> Nothing ties the key to the sender&apos;s identity</li>
                        <li><strong>Network Position:</strong> Attacker just needs to be on the network path</li>
                    </ul>
                </div>

                {/* The Solution */}
                <div className="bg-gray-800 rounded-lg p-4">
                    <h2 className="text-xl font-semibold mb-3 text-green-400">💡 The Solution: Digital Signatures</h2>
                    <ul className="list-disc list-inside space-y-2 text-gray-300">
                        <li><strong>ECDSA Signatures:</strong> Sign ephemeral public keys with long-term identity keys</li>
                        <li><strong>Verification:</strong> Recipients verify signatures using known public keys</li>
                        <li><strong>Result:</strong> Mallory cannot substitute keys - signature verification would fail!</li>
                        <li><strong>Our Protocol:</strong> AECDH-ECDSA uses signatures on every key exchange message</li>
                    </ul>
                    <div className="mt-4">
                        <a href="/attack-demos/mitm-protected" className="text-cyan-400 hover:underline">
                            ➡️ See Module 6: How our AECDH-ECDSA protocol prevents this attack
                        </a>
                    </div>
                </div>
            </div>
        </div>
    );
}
