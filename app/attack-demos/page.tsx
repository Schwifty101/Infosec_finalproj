'use client';

import Link from 'next/link';

/**
 * Attack Demonstrations Index Page
 * 
 * Phase 5: Security Attack Demonstrations
 * Provides navigation to all attack demonstration modules
 */

export default function AttackDemosPage() {
    return (
        <div className="min-h-screen bg-gray-900 text-white p-8">
            <div className="max-w-4xl mx-auto">
                <h1 className="text-4xl font-bold mb-2">🔐 Security Attack Demonstrations</h1>
                <p className="text-gray-400 mb-8">Phase 5: Demonstrating attacks and defenses in our E2E encrypted messaging system</p>

                <div className="grid gap-6">
                    {/* Module 4: Replay Attack */}
                    <Link href="/attack-demos/replay" className="block">
                        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700 hover:border-cyan-500 transition-colors">
                            <div className="flex items-start gap-4">
                                <span className="text-4xl">📼</span>
                                <div>
                                    <h2 className="text-xl font-semibold text-cyan-400 mb-2">Module 4: Replay Attack Demonstration</h2>
                                    <p className="text-gray-300 mb-4">
                                        Shows how attackers capture and attempt to replay encrypted messages,
                                        and how our system blocks these attempts using nonces, timestamps, and sequence numbers.
                                    </p>
                                    <div className="flex flex-wrap gap-2">
                                        <span className="px-2 py-1 bg-green-900 text-green-300 rounded text-sm">Nonce Protection</span>
                                        <span className="px-2 py-1 bg-green-900 text-green-300 rounded text-sm">Sequence Numbers</span>
                                        <span className="px-2 py-1 bg-green-900 text-green-300 rounded text-sm">Timestamp Validation</span>
                                        <span className="px-2 py-1 bg-green-900 text-green-300 rounded text-sm">AAD Protection</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </Link>

                    {/* Module 5: MITM Vulnerable */}
                    <Link href="/attack-demos/mitm-vulnerable" className="block">
                        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700 hover:border-red-500 transition-colors">
                            <div className="flex items-start gap-4">
                                <span className="text-4xl">💀</span>
                                <div>
                                    <h2 className="text-xl font-semibold text-red-400 mb-2">Module 5: MITM Attack (Vulnerable DH)</h2>
                                    <p className="text-gray-300 mb-4">
                                        Demonstrates a successful Man-in-the-Middle attack on unsigned Diffie-Hellman
                                        key exchange. Shows how attackers can intercept, read, and modify all messages.
                                    </p>
                                    <div className="flex flex-wrap gap-2">
                                        <span className="px-2 py-1 bg-red-900 text-red-300 rounded text-sm">⚠️ Vulnerable</span>
                                        <span className="px-2 py-1 bg-gray-700 text-gray-300 rounded text-sm">No Authentication</span>
                                        <span className="px-2 py-1 bg-gray-700 text-gray-300 rounded text-sm">Key Substitution</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </Link>

                    {/* Module 6: MITM Protected */}
                    <Link href="/attack-demos/mitm-protected" className="block">
                        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700 hover:border-green-500 transition-colors">
                            <div className="flex items-start gap-4">
                                <span className="text-4xl">🛡️</span>
                                <div>
                                    <h2 className="text-xl font-semibold text-green-400 mb-2">Module 6: MITM Prevention (AECDH-ECDSA)</h2>
                                    <p className="text-gray-300 mb-4">
                                        Shows how our AECDH-ECDSA protocol with digital signatures prevents MITM attacks.
                                        Demonstrates signature verification blocking key substitution attempts.
                                    </p>
                                    <div className="flex flex-wrap gap-2">
                                        <span className="px-2 py-1 bg-green-900 text-green-300 rounded text-sm">✅ Protected</span>
                                        <span className="px-2 py-1 bg-green-900 text-green-300 rounded text-sm">ECDSA Signatures</span>
                                        <span className="px-2 py-1 bg-green-900 text-green-300 rounded text-sm">Mutual Authentication</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </Link>
                </div>

                {/* Summary Table */}
                <div className="mt-8 bg-gray-800 rounded-lg p-6">
                    <h2 className="text-xl font-semibold mb-4">📊 Attack & Defense Summary</h2>
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="text-left text-gray-400 border-b border-gray-700">
                                    <th className="p-3">Attack Type</th>
                                    <th className="p-3">Description</th>
                                    <th className="p-3">Protection</th>
                                    <th className="p-3">Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr className="border-b border-gray-700">
                                    <td className="p-3 font-semibold">Replay Attack</td>
                                    <td className="p-3 text-gray-300">Resending captured messages</td>
                                    <td className="p-3 text-gray-300">Nonces, Timestamps, Sequences</td>
                                    <td className="p-3 text-green-400">✅ Blocked</td>
                                </tr>
                                <tr className="border-b border-gray-700">
                                    <td className="p-3 font-semibold">MITM (Unsigned DH)</td>
                                    <td className="p-3 text-gray-300">Key substitution attack</td>
                                    <td className="p-3 text-gray-300">None (vulnerable)</td>
                                    <td className="p-3 text-red-400">❌ Succeeds</td>
                                </tr>
                                <tr className="border-b border-gray-700">
                                    <td className="p-3 font-semibold">MITM (AECDH-ECDSA)</td>
                                    <td className="p-3 text-gray-300">Key substitution attempt</td>
                                    <td className="p-3 text-gray-300">ECDSA Signatures</td>
                                    <td className="p-3 text-green-400">✅ Blocked</td>
                                </tr>
                                <tr>
                                    <td className="p-3 font-semibold">Message Tampering</td>
                                    <td className="p-3 text-gray-300">Modifying encrypted messages</td>
                                    <td className="p-3 text-gray-300">AES-GCM Authentication Tag</td>
                                    <td className="p-3 text-green-400">✅ Detected</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                {/* Evidence Collection */}
                <div className="mt-8 bg-gray-800 rounded-lg p-6">
                    <h2 className="text-xl font-semibold mb-4">📸 Evidence Collection Checklist</h2>
                    <div className="grid md:grid-cols-2 gap-4">
                        <div>
                            <h3 className="font-semibold text-cyan-400 mb-2">Replay Attack Evidence:</h3>
                            <ul className="list-disc list-inside text-gray-300 text-sm space-y-1">
                                <li>Screenshot of captured message data</li>
                                <li>Network tab showing 400 rejection</li>
                                <li>Server console with replay detection logs</li>
                                <li>MongoDB logs collection query results</li>
                                <li>Wireshark capture of encrypted traffic</li>
                            </ul>
                        </div>
                        <div>
                            <h3 className="font-semibold text-red-400 mb-2">MITM Attack Evidence:</h3>
                            <ul className="list-disc list-inside text-gray-300 text-sm space-y-1">
                                <li>Vulnerable DH: Successful message interception</li>
                                <li>Vulnerable DH: Modified message received</li>
                                <li>Protected: Signature verification failure</li>
                                <li>Protected: Attack blocked notification</li>
                                <li>Console logs showing verification steps</li>
                            </ul>
                        </div>
                    </div>
                </div>

                {/* Navigation */}
                <div className="mt-8 flex flex-wrap gap-4">
                    <Link href="/dashboard" className="text-cyan-400 hover:underline">
                        ← Back to Dashboard
                    </Link>
                    <Link href="/logs" className="text-cyan-400 hover:underline">
                        📋 View Security Logs
                    </Link>
                    <Link href="/test-phase2" className="text-cyan-400 hover:underline">
                        🧪 Phase 2 Tests
                    </Link>
                    <Link href="/test-phase3" className="text-cyan-400 hover:underline">
                        🧪 Phase 3 Tests
                    </Link>
                </div>
            </div>
        </div>
    );
}
