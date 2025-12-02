'use client';

import { useState, useCallback } from 'react';

/**
 * Phase 5 - Module 6: MITM Attack Prevention (AECDH-ECDSA Protected)
 * 
 * This page demonstrates:
 * 1. How digital signatures prevent MITM attacks
 * 2. Signature verification detecting key substitution
 * 3. Comparison with vulnerable unsigned DH
 * 4. Complete AECDH-ECDSA protocol security
 */

interface PartyKeys {
    ecdhKeyPair: CryptoKeyPair;
    ecdsaKeyPair: CryptoKeyPair;
    ecdhPublicJwk: string;
    ecdsaPublicJwk: string;
}

export default function MITMProtectedDemoPage() {
    const [results, setResults] = useState<string[]>([]);
    const [isRunning, setIsRunning] = useState(false);
    const [attackBlocked, setAttackBlocked] = useState(false);

    const addResult = useCallback((msg: string) => {
        setResults((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
    }, []);

    const clearResults = () => {
        setResults([]);
        setAttackBlocked(false);
    };

    // ============================================================================
    // Generate ECDH Key Pair
    // ============================================================================
    const generateECDHKeyPair = async (): Promise<CryptoKeyPair> => {
        return await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveKey', 'deriveBits']
        );
    };

    // ============================================================================
    // Generate ECDSA Key Pair (Identity Key)
    // ============================================================================
    const generateECDSAKeyPair = async (): Promise<CryptoKeyPair> => {
        return await crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['sign', 'verify']
        );
    };

    // ============================================================================
    // Generate All Keys for a Party
    // ============================================================================
    const generatePartyKeys = async (name: string): Promise<PartyKeys> => {
        const ecdhKeyPair = await generateECDHKeyPair();
        const ecdsaKeyPair = await generateECDSAKeyPair();

        const ecdhPublicJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', ecdhKeyPair.publicKey));
        const ecdsaPublicJwk = JSON.stringify(await crypto.subtle.exportKey('jwk', ecdsaKeyPair.publicKey));

        addResult(`🔑 ${name} generated keys:`);
        addResult(`   ECDH (ephemeral): ${ecdhPublicJwk.substring(0, 40)}...`);
        addResult(`   ECDSA (identity): ${ecdsaPublicJwk.substring(0, 40)}...`);

        return { ecdhKeyPair, ecdsaKeyPair, ecdhPublicJwk, ecdsaPublicJwk };
    };

    // ============================================================================
    // Sign Data with ECDSA
    // ============================================================================
    const signData = async (privateKey: CryptoKey, data: string): Promise<string> => {
        const encoder = new TextEncoder();
        const signature = await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            privateKey,
            encoder.encode(data)
        );
        return btoa(String.fromCharCode(...new Uint8Array(signature)));
    };

    // ============================================================================
    // Verify Signature with ECDSA
    // ============================================================================
    const verifySignature = async (
        publicKey: CryptoKey,
        signature: string,
        data: string
    ): Promise<boolean> => {
        const encoder = new TextEncoder();
        const signatureBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));

        return await crypto.subtle.verify(
            { name: 'ECDSA', hash: 'SHA-256' },
            publicKey,
            signatureBytes,
            encoder.encode(data)
        );
    };

    // ============================================================================
    // Import ECDSA Public Key
    // ============================================================================
    const importECDSAPublicKey = async (jwkString: string): Promise<CryptoKey> => {
        return await crypto.subtle.importKey(
            'jwk',
            JSON.parse(jwkString),
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['verify']
        );
    };

    // ============================================================================
    // Demonstrate Normal AECDH-ECDSA Exchange
    // ============================================================================
    const demonstrateSecureExchange = async () => {
        addResult('');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('   SCENARIO 1: NORMAL AECDH-ECDSA KEY EXCHANGE');
        addResult('   Using Digital Signatures for Authentication');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('');

        // Both parties have pre-registered identity keys (ECDSA)
        addResult('📋 PREREQUISITE: Both parties have registered identity keys');
        addResult('   (ECDSA public keys are stored on the server)');
        addResult('');

        // Alice generates keys
        addResult('👩 ALICE: Generating ephemeral ECDH key pair...');
        const aliceKeys = await generatePartyKeys('Alice');

        // Create signed init message
        const nonce = crypto.randomUUID();
        const timestamp = Date.now();
        const initPayload = `${aliceKeys.ecdhPublicJwk}||${nonce}||${timestamp}||bob`;

        addResult('');
        addResult('✍️ ALICE signs her ephemeral public key with her identity key:');
        const aliceSignature = await signData(aliceKeys.ecdsaKeyPair.privateKey, initPayload);
        addResult(`   Signature: ${aliceSignature.substring(0, 40)}...`);
        addResult('');

        addResult('📤 Alice → Bob: KEY_EXCHANGE_INIT');
        addResult('   ├─ ephemeralPublicKey: [ECDH public key]');
        addResult('   ├─ nonce: ' + nonce.substring(0, 8) + '...');
        addResult('   ├─ timestamp: ' + new Date(timestamp).toISOString());
        addResult('   └─ signature: [ECDSA signature over above data]');
        addResult('');

        // Bob receives and verifies
        addResult('👨 BOB receives init message...');
        addResult('');
        addResult('🔍 BOB verifies Alice\'s signature:');
        addResult('   1. Fetches Alice\'s ECDSA public key from server');
        addResult('   2. Verifies signature over (ephemeralPK || nonce || timestamp || bob)');

        const bobVerifiesAlice = await verifySignature(
            aliceKeys.ecdsaKeyPair.publicKey,
            aliceSignature,
            initPayload
        );

        addResult(`   Result: ${bobVerifiesAlice ? '✅ VALID' : '❌ INVALID'}`);
        addResult('');

        if (!bobVerifiesAlice) {
            addResult('❌ Signature verification failed! Aborting key exchange.');
            return;
        }

        // Bob generates keys and responds
        addResult('👨 BOB: Generating ephemeral ECDH key pair...');
        const bobKeys = await generatePartyKeys('Bob');

        const bobNonce = crypto.randomUUID();
        const bobTimestamp = Date.now();
        const responsePayload = `${bobKeys.ecdhPublicJwk}||${bobNonce}||${bobTimestamp}||alice||${nonce}`;

        addResult('');
        addResult('✍️ BOB signs his ephemeral public key with his identity key:');
        const bobSignature = await signData(bobKeys.ecdsaKeyPair.privateKey, responsePayload);
        addResult(`   Signature: ${bobSignature.substring(0, 40)}...`);
        addResult('');

        addResult('📤 Bob → Alice: KEY_EXCHANGE_RESPONSE');
        addResult('   ├─ ephemeralPublicKey: [ECDH public key]');
        addResult('   ├─ nonce: ' + bobNonce.substring(0, 8) + '...');
        addResult('   ├─ initiatorNonce: ' + nonce.substring(0, 8) + '... (echoed)');
        addResult('   └─ signature: [ECDSA signature]');
        addResult('');

        // Alice verifies Bob's response
        addResult('👩 ALICE receives response...');
        addResult('');
        addResult('🔍 ALICE verifies Bob\'s signature:');

        const aliceVerifiesBob = await verifySignature(
            bobKeys.ecdsaKeyPair.publicKey,
            bobSignature,
            responsePayload
        );

        addResult(`   Result: ${aliceVerifiesBob ? '✅ VALID' : '❌ INVALID'}`);
        addResult('');

        if (aliceVerifiesBob) {
            addResult('🔐 Both parties verified! Deriving session key...');
            addResult('');
            addResult('✅ SECURE KEY EXCHANGE COMPLETE!');
            addResult('   ├─ Alice authenticated Bob via his ECDSA signature');
            addResult('   ├─ Bob authenticated Alice via her ECDSA signature');
            addResult('   ├─ Ephemeral keys provide forward secrecy');
            addResult('   └─ Session key derived from verified ECDH');
        }
    };

    // ============================================================================
    // Demonstrate MITM Attack Failure
    // ============================================================================
    const demonstrateMITMFailure = async () => {
        addResult('');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('   SCENARIO 2: MITM ATTACK ATTEMPT ON AECDH-ECDSA');
        addResult('   🛡️ PROTECTED: Digital Signatures Prevent Key Substitution');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('');

        addResult('🦹 MALLORY positions herself between Alice and Bob');
        addResult('   She will try the same attack that worked on unsigned DH');
        addResult('');

        // Alice generates keys
        addResult('👩 ALICE: Generating keys and creating init message...');
        const aliceKeys = await generatePartyKeys('Alice');

        const nonce = crypto.randomUUID();
        const timestamp = Date.now();
        const initPayload = `${aliceKeys.ecdhPublicJwk}||${nonce}||${timestamp}||bob`;

        const aliceSignature = await signData(aliceKeys.ecdsaKeyPair.privateKey, initPayload);
        addResult(`✍️ Alice signs with her identity key: ${aliceSignature.substring(0, 30)}...`);
        addResult('');

        addResult('📤 Alice → [Network] → Bob');
        addResult('   Init message with Alice\'s ephemeral key + signature');
        addResult('');

        // Mallory intercepts
        addResult('🦹 MALLORY INTERCEPTS THE MESSAGE!');
        addResult('');

        addResult('💭 Mallory thinks: "I\'ll substitute my own ephemeral key!"');
        addResult('');

        // Mallory generates her own ECDH key
        addResult('🦹 MALLORY generates her own ephemeral ECDH key pair...');
        const malloryKeys = await generatePartyKeys('Mallory');

        // Mallory tries to substitute
        addResult('');
        addResult('🦹 MALLORY\'s ATTACK STRATEGY:');
        addResult('   Option 1: Send Alice\'s signature with Mallory\'s key');
        addResult('   Option 2: Create new signature for Mallory\'s key');
        addResult('');

        // Option 1: Use Alice's signature with Mallory's key
        addResult('═══ ATTACK ATTEMPT 1: Reuse Alice\'s Signature ═══');
        addResult('');
        addResult('🦹 Mallory forwards to Bob:');
        addResult('   ├─ ephemeralPublicKey: [MALLORY\'s key]');
        addResult('   └─ signature: [Alice\'s original signature]');
        addResult('');

        addResult('👨 BOB receives message and verifies...');
        addResult('');

        // Bob tries to verify - will fail because key doesn't match signature
        const malloryPayload = `${malloryKeys.ecdhPublicJwk}||${nonce}||${timestamp}||bob`;

        addResult('🔍 BOB verifies signature against received ephemeral key:');
        addResult('   Signature was created over: Alice\'s ephemeral key');
        addResult('   Signature verified against: Mallory\'s ephemeral key');

        const verifyAttempt1 = await verifySignature(
            aliceKeys.ecdsaKeyPair.publicKey,
            aliceSignature,
            malloryPayload  // Different key!
        );

        addResult('');
        addResult(`   ❌ SIGNATURE VERIFICATION: ${verifyAttempt1 ? 'VALID' : 'FAILED!'}`);
        addResult('');

        if (!verifyAttempt1) {
            addResult('🛡️ ATTACK BLOCKED!');
            addResult('   The signature was created over Alice\'s key,');
            addResult('   but Mallory substituted her own key.');
            addResult('   The signature doesn\'t match!');
        }

        // Option 2: Create new signature
        addResult('');
        addResult('═══ ATTACK ATTEMPT 2: Create New Signature ═══');
        addResult('');
        addResult('🦹 Mallory thinks: "I\'ll sign my key with MY identity key!"');
        addResult('');

        const mallorySignature = await signData(malloryKeys.ecdsaKeyPair.privateKey, malloryPayload);
        addResult(`🦹 Mallory signs her key: ${mallorySignature.substring(0, 30)}...`);
        addResult('');

        addResult('🦹 Mallory forwards to Bob:');
        addResult('   ├─ ephemeralPublicKey: [MALLORY\'s key]');
        addResult('   └─ signature: [MALLORY\'s signature]');
        addResult('');

        addResult('👨 BOB receives message and verifies...');
        addResult('');
        addResult('🔍 BOB fetches ALICE\'s ECDSA public key from server');
        addResult('   (Bob expects a message FROM ALICE)');
        addResult('');

        // Bob verifies with Alice's public key (what he expects)
        const verifyAttempt2 = await verifySignature(
            aliceKeys.ecdsaKeyPair.publicKey,  // Alice's key
            mallorySignature,                   // Mallory's signature
            malloryPayload
        );

        addResult('   BOB verifies Mallory\'s signature with Alice\'s public key:');
        addResult(`   ❌ SIGNATURE VERIFICATION: ${verifyAttempt2 ? 'VALID' : 'FAILED!'}`);
        addResult('');

        if (!verifyAttempt2) {
            addResult('🛡️ ATTACK BLOCKED!');
            addResult('   Mallory can sign with HER key,');
            addResult('   but she doesn\'t have Alice\'s private key!');
            addResult('   Bob expects a signature from Alice\'s key.');
            addResult('');
            addResult('💡 KEY INSIGHT:');
            addResult('   Mallory would need Alice\'s ECDSA private key');
            addResult('   to create a valid signature. But private keys');
            addResult('   never leave the client device!');
            setAttackBlocked(true);
        }

        addResult('');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('   🛡️ MITM ATTACK PREVENTION SUMMARY');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('');
        addResult('   The attack FAILS because:');
        addResult('');
        addResult('   ┌─────────────────────────────────────────────────────────┐');
        addResult('   │ 1. Signatures bind ephemeral keys to identity         │');
        addResult('   │ 2. Only the real owner can sign with their key        │');
        addResult('   │ 3. Recipients verify using known public keys          │');
        addResult('   │ 4. Key substitution breaks signature verification     │');
        addResult('   └─────────────────────────────────────────────────────────┘');
        addResult('');
        addResult('   Without Alice\'s private ECDSA key, Mallory CANNOT:');
        addResult('   • Create valid signatures for her substituted keys');
        addResult('   • Impersonate Alice to Bob');
        addResult('   • Impersonate Bob to Alice');
        addResult('   • Execute a successful MITM attack');
    };

    // ============================================================================
    // Run Full Demonstration
    // ============================================================================
    const runFullDemo = async () => {
        setIsRunning(true);
        clearResults();

        addResult('🚀 ═══════════════════════════════════════════════════════════════');
        addResult('   PHASE 5 MODULE 6: MITM ATTACK PREVENTION');
        addResult('   Demonstrating AECDH-ECDSA Protocol Security');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('');
        addResult('📋 Our AECDH-ECDSA Protocol Features:');
        addResult('   ├─ ECDH P-256 ephemeral keys (forward secrecy)');
        addResult('   ├─ ECDSA P-256 signatures (authentication)');
        addResult('   ├─ Nonces (replay protection)');
        addResult('   ├─ Timestamps (freshness)');
        addResult('   └─ HKDF-SHA256 (key derivation)');
        addResult('');

        await demonstrateSecureExchange();

        await new Promise(r => setTimeout(r, 1000));

        await demonstrateMITMFailure();

        addResult('');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('   DEMONSTRATION COMPLETE');
        addResult('═══════════════════════════════════════════════════════════════');
        addResult('');
        addResult('📊 COMPARISON: Unsigned DH vs AECDH-ECDSA');
        addResult('');
        addResult('   ┌──────────────────┬────────────────┬────────────────────┐');
        addResult('   │ Property         │ Unsigned DH    │ AECDH-ECDSA        │');
        addResult('   ├──────────────────┼────────────────┼────────────────────┤');
        addResult('   │ Authentication   │ ❌ None        │ ✅ ECDSA Signatures│');
        addResult('   │ MITM Resistant   │ ❌ Vulnerable  │ ✅ Protected       │');
        addResult('   │ Forward Secrecy  │ ✅ Yes         │ ✅ Yes             │');
        addResult('   │ Key Confirmation │ ❌ None        │ ✅ HMAC Tag        │');
        addResult('   │ Replay Protected │ ❌ None        │ ✅ Nonces+Timestamps│');
        addResult('   └──────────────────┴────────────────┴────────────────────┘');
        addResult('');
        addResult('🎓 KEY TAKEAWAY:');
        addResult('   Diffie-Hellman provides shared secret computation,');
        addResult('   but AUTHENTICATION must be added separately via signatures.');
        addResult('   Our protocol combines ECDH + ECDSA for complete security.');

        setIsRunning(false);
    };

    return (
        <div className="min-h-screen bg-gray-900 text-white p-8">
            <div className="max-w-5xl mx-auto">
                <h1 className="text-3xl font-bold mb-2 text-green-500">🛡️ MITM Attack Prevention (AECDH-ECDSA)</h1>
                <p className="text-gray-400 mb-6">Module 6: Demonstrating how digital signatures prevent MITM attacks</p>

                <div className="mb-6 flex flex-wrap gap-3">
                    <button
                        onClick={runFullDemo}
                        disabled={isRunning}
                        className="bg-green-600 hover:bg-green-700 disabled:bg-gray-600 px-6 py-3 rounded font-semibold text-lg"
                    >
                        {isRunning ? '🔄 Running Demo...' : '🛡️ Run Protection Demo'}
                    </button>

                    <button
                        onClick={demonstrateSecureExchange}
                        disabled={isRunning}
                        className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-4 py-2 rounded"
                    >
                        ✅ Show Secure Exchange
                    </button>

                    <button
                        onClick={demonstrateMITMFailure}
                        disabled={isRunning}
                        className="bg-orange-600 hover:bg-orange-700 disabled:bg-gray-600 px-4 py-2 rounded"
                    >
                        🛡️ Show MITM Blocked
                    </button>

                    <button onClick={clearResults} className="bg-gray-600 hover:bg-gray-700 px-4 py-2 rounded">
                        🗑️ Clear
                    </button>
                </div>

                {/* Attack Blocked Indicator */}
                {attackBlocked && (
                    <div className="mb-4 p-4 bg-green-900/50 border border-green-500 rounded-lg">
                        <div className="flex items-center gap-2">
                            <span className="text-3xl">🛡️</span>
                            <div>
                                <h3 className="text-xl font-bold text-green-400">MITM Attack Blocked!</h3>
                                <p className="text-green-300">Digital signatures prevented key substitution</p>
                            </div>
                        </div>
                    </div>
                )}

                {/* Results Console */}
                <div className="bg-gray-800 rounded-lg p-4 font-mono text-sm max-h-[55vh] overflow-y-auto mb-6">
                    {results.length === 0 ? (
                        <p className="text-gray-400">Click &quot;Run Protection Demo&quot; to see how AECDH-ECDSA prevents MITM attacks...</p>
                    ) : (
                        results.map((result, index) => (
                            <div
                                key={index}
                                className={`mb-1 ${result.includes('✅') || result.includes('COMPLETE') || result.includes('VALID')
                                        ? 'text-green-400'
                                        : result.includes('❌') || result.includes('FAILED')
                                            ? 'text-red-400'
                                            : result.includes('🛡️') || result.includes('BLOCKED')
                                                ? 'text-cyan-400 font-bold'
                                                : result.includes('🦹') || result.includes('MALLORY')
                                                    ? 'text-red-500'
                                                    : result.includes('👩') || result.includes('ALICE')
                                                        ? 'text-pink-400'
                                                        : result.includes('👨') || result.includes('BOB')
                                                            ? 'text-blue-400'
                                                            : result.includes('═══')
                                                                ? 'text-purple-400 font-bold'
                                                                : result.includes('💡')
                                                                    ? 'text-yellow-400 font-bold'
                                                                    : result.includes('✍️')
                                                                        ? 'text-cyan-400'
                                                                        : 'text-gray-300'
                                    }`}
                            >
                                {result}
                            </div>
                        ))
                    )}
                </div>

                {/* Protocol Diagram */}
                <div className="bg-gray-800 rounded-lg p-4 mb-6">
                    <h2 className="text-xl font-semibold mb-3">📊 AECDH-ECDSA Protocol Flow</h2>
                    <div className="font-mono text-sm bg-gray-900 p-4 rounded overflow-x-auto">
                        <pre className="text-gray-300">
                            {`
┌─────────────────────────────────────────────────────────────────────────────┐
│                      AECDH-ECDSA KEY EXCHANGE PROTOCOL                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   👩 Alice                                                      👨 Bob       │
│      │                                                            │          │
│      │  MESSAGE 1: KEY_EXCHANGE_INIT                              │          │
│      │──────────────────────────────────────────────────────────>│          │
│      │  {                                                         │          │
│      │    ephemeralPublicKey: PK_A,                              │          │
│      │    nonce: nonce_A,                                         │          │
│      │    timestamp: ts_A,                                        │          │
│      │    signature: SIGN(SK_alice, PK_A || nonce_A || ts_A)     │          │
│      │  }                                                         │          │
│      │                                                            │          │
│      │                     Bob verifies signature using           │          │
│      │                     Alice's ECDSA public key               │          │
│      │                                                            │          │
│      │  MESSAGE 2: KEY_EXCHANGE_RESPONSE                          │          │
│      │<──────────────────────────────────────────────────────────│          │
│      │  {                                                         │          │
│      │    ephemeralPublicKey: PK_B,                              │          │
│      │    nonce: nonce_B,                                         │          │
│      │    initiatorNonce: nonce_A,                                │          │
│      │    signature: SIGN(SK_bob, PK_B || nonce_B || nonce_A)    │          │
│      │  }                                                         │          │
│      │                                                            │          │
│      │  Alice verifies signature using                            │          │
│      │  Bob's ECDSA public key                                   │          │
│      │                                                            │          │
│      │  MESSAGE 3: KEY_EXCHANGE_CONFIRM                           │          │
│      │──────────────────────────────────────────────────────────>│          │
│      │  {                                                         │          │
│      │    confirmationTag: HMAC(sessionKey, transcript)          │          │
│      │  }                                                         │          │
│      │                                                            │          │
│      │           Both compute: sessionKey = HKDF(                 │          │
│      │             ECDH(SK_A, PK_B), salt, info)                 │          │
│      │                                                            │          │
└─────────────────────────────────────────────────────────────────────────────┘
`}
                        </pre>
                    </div>
                </div>

                {/* Security Properties */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                    <div className="bg-gray-800 rounded-lg p-4">
                        <h3 className="text-lg font-semibold mb-2 text-green-400">✅ What AECDH-ECDSA Provides</h3>
                        <ul className="list-disc list-inside space-y-1 text-gray-300 text-sm">
                            <li><strong>Mutual Authentication:</strong> Both parties verify identity via signatures</li>
                            <li><strong>Forward Secrecy:</strong> Ephemeral ECDH keys protect past sessions</li>
                            <li><strong>Key Confirmation:</strong> HMAC proves mutual key agreement</li>
                            <li><strong>Replay Protection:</strong> Nonces and timestamps prevent reuse</li>
                            <li><strong>MITM Prevention:</strong> Signature verification blocks substitution</li>
                        </ul>
                    </div>
                    <div className="bg-gray-800 rounded-lg p-4">
                        <h3 className="text-lg font-semibold mb-2 text-red-400">❌ Why MITM Fails</h3>
                        <ul className="list-disc list-inside space-y-1 text-gray-300 text-sm">
                            <li><strong>No Private Key Access:</strong> Mallory cannot forge valid signatures</li>
                            <li><strong>Key Binding:</strong> Signatures bind ephemeral keys to identity</li>
                            <li><strong>Trusted Public Keys:</strong> Recipients verify with known keys</li>
                            <li><strong>Cannot Substitute:</strong> Changing key breaks signature</li>
                            <li><strong>Cannot Re-sign:</strong> Wrong private key means wrong signature</li>
                        </ul>
                    </div>
                </div>

                {/* Navigation */}
                <div className="bg-gray-800 rounded-lg p-4">
                    <h2 className="text-xl font-semibold mb-3">🔗 Related Demonstrations</h2>
                    <div className="flex flex-wrap gap-4">
                        <a href="/attack-demos/replay" className="text-cyan-400 hover:underline">
                            📼 Module 4: Replay Attack Demo
                        </a>
                        <a href="/attack-demos/mitm-vulnerable" className="text-red-400 hover:underline">
                            💀 Module 5: MITM on Unsigned DH
                        </a>
                        <a href="/test-phase2" className="text-green-400 hover:underline">
                            🧪 Phase 2: Key Exchange Tests
                        </a>
                    </div>
                </div>
            </div>
        </div>
    );
}
