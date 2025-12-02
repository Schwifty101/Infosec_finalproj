'use client';

/**
 * UserSearch Component
 *
 * Instagram-style user search for discovering users and initiating key exchanges.
 * Reusable component for both Key Exchange page and Messaging page.
 *
 * Features:
 * - Debounced search (300ms)
 * - Session key status indicators
 * - Key exchange initiation
 * - Status polling for pending exchanges
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { initiateKeyExchange, handleKeyExchangeResponse, getConversationId } from '@/lib/crypto/protocol';
import { getSessionKeyStatus, getEphemeralKey } from '@/lib/crypto/sessionKeys';

interface SearchUser {
    _id: string;
    username: string;
    hasPublicKey: boolean;
}

interface UserSearchProps {
    currentUserId: string;
    currentUsername: string;
    onKeyExchangeInitiated?: (peerUserId: string, peerUsername: string) => void;
    onViewChat?: (peerUserId: string, peerUsername: string) => void;
}

type SessionStatus = 'exists' | 'expired' | 'none' | 'pending' | 'loading';

interface UserWithStatus extends SearchUser {
    sessionStatus: SessionStatus;
}

/**
 * Debounce hook
 */
function useDebounce<T>(value: T, delay: number): T {
    const [debouncedValue, setDebouncedValue] = useState<T>(value);

    useEffect(() => {
        const handler = setTimeout(() => {
            setDebouncedValue(value);
        }, delay);

        return () => {
            clearTimeout(handler);
        };
    }, [value, delay]);

    return debouncedValue;
}

export default function UserSearch({
    currentUserId,
    currentUsername,
    onKeyExchangeInitiated,
    onViewChat,
}: UserSearchProps) {
    const router = useRouter();
    const [searchQuery, setSearchQuery] = useState('');
    const [searchResults, setSearchResults] = useState<UserWithStatus[]>([]);
    const [isSearching, setIsSearching] = useState(false);
    const [searchError, setSearchError] = useState<string | null>(null);
    const [initiatingExchange, setInitiatingExchange] = useState<string | null>(null);
    const [exchangeError, setExchangeError] = useState<string | null>(null);
    const [pendingExchanges, setPendingExchanges] = useState<Set<string>>(new Set());
    const pollingRef = useRef<NodeJS.Timeout | null>(null);

    const debouncedQuery = useDebounce(searchQuery, 300);

    /**
     * Check session key status for a user
     */
    const checkSessionStatus = useCallback(
        async (userId: string): Promise<SessionStatus> => {
            try {
                // Check if there's a pending key exchange
                if (pendingExchanges.has(userId)) {
                    return 'pending';
                }
                return await getSessionKeyStatus(currentUserId, userId);
            } catch (error) {
                console.error('Failed to check session status:', error);
                return 'none';
            }
        },
        [currentUserId, pendingExchanges]
    );

    /**
     * Search for users
     */
    const searchUsers = useCallback(async (query: string) => {
        if (!query.trim()) {
            setSearchResults([]);
            return;
        }

        setIsSearching(true);
        setSearchError(null);

        try {
            const response = await fetch(
                `/api/users/search?q=${encodeURIComponent(query)}&currentUserId=${encodeURIComponent(currentUserId)}`
            );

            if (!response.ok) {
                throw new Error('Search failed');
            }

            const data = await response.json();

            if (!data.success) {
                throw new Error(data.error || 'Search failed');
            }

            // Add session status to each user
            const usersWithStatus: UserWithStatus[] = await Promise.all(
                data.users.map(async (user: SearchUser) => ({
                    ...user,
                    sessionStatus: await checkSessionStatus(user._id),
                }))
            );

            setSearchResults(usersWithStatus);
        } catch (error) {
            console.error('Search error:', error);
            setSearchError('Failed to search users. Please try again.');
            setSearchResults([]);
        } finally {
            setIsSearching(false);
        }
    }, [currentUserId, checkSessionStatus]);

    /**
     * Effect: Trigger search when debounced query changes
     */
    useEffect(() => {
        searchUsers(debouncedQuery);
    }, [debouncedQuery, searchUsers]);

    /**
     * Poll for key exchange status
     */
    const pollExchangeStatus = useCallback(
        async (sessionId: string, peerUserId: string, peerUsername: string, myNonce: string) => {
            try {
                const response = await fetch(`/api/key-exchange/status/${sessionId}`);

                if (!response.ok) {
                    console.error('Failed to get exchange status');
                    return false;
                }

                const data = await response.json();

                // Handle 'responded' status - initiator needs to complete the exchange
                if (data.status === 'responded' && data.responseMessage) {
                    console.log('📥 Received key exchange response, completing exchange...');
                    
                    try {
                        // Fetch responder's public key
                        const keyResponse = await fetch(`/api/keys/${peerUserId}`);
                        const keyData = await keyResponse.json();
                        
                        if (!keyData.success || !keyData.publicKey) {
                            throw new Error('Failed to retrieve responder public key');
                        }

                        // TOFU: Validate public key
                        const { validatePublicKey, storeKeyFingerprint, formatFingerprint } =
                            await import('@/lib/crypto/keyValidation');

                        const validation = await validatePublicKey(peerUserId, keyData.publicKey);

                        if (!validation.valid) {
                            const confirmChange = confirm(
                                `⚠️ WARNING: This user's public key has changed!\n\n` +
                                `${validation.reason}\n\n` +
                                `New Fingerprint: ${formatFingerprint(validation.fingerprint)}\n\n` +
                                `This could indicate a Man-in-the-Middle attack.\n\n` +
                                `Proceed anyway?`
                            );

                            if (!confirmChange) {
                                throw new Error('Key exchange cancelled due to key change');
                            }

                            await storeKeyFingerprint(peerUserId, keyData.publicKey, validation.fingerprint);
                        }

                        if (validation.isFirstSeen) {
                            console.log('First exchange - storing fingerprint:',
                                formatFingerprint(validation.fingerprint));
                            await storeKeyFingerprint(peerUserId, keyData.publicKey, validation.fingerprint);
                        }

                        // Complete the key exchange (derive session key + create confirmation)
                        const confirmMessage = await handleKeyExchangeResponse(
                            data.responseMessage,
                            currentUserId,
                            keyData.publicKey,
                            myNonce
                        );

                        // Send confirmation to server
                        const confirmResponse = await fetch('/api/key-exchange/confirm', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ message: confirmMessage }),
                        });

                        if (!confirmResponse.ok) {
                            console.error('Failed to send confirmation');
                            return false;
                        }

                        console.log('✅ Key exchange completed successfully!');
                        
                        // Exchange completed!
                        setPendingExchanges((prev) => {
                            const next = new Set(prev);
                            next.delete(peerUserId);
                            return next;
                        });

                        // Update user status in results
                        setSearchResults((prev) =>
                            prev.map((user) =>
                                user._id === peerUserId ? { ...user, sessionStatus: 'exists' } : user
                            )
                        );

                        // Trigger callback
                        if (onKeyExchangeInitiated) {
                            onKeyExchangeInitiated(peerUserId, peerUsername);
                        }

                        return true; // Stop polling
                    } catch (error) {
                        console.error('Failed to complete key exchange:', error);
                        setExchangeError(`Failed to complete key exchange with ${peerUsername}`);
                        return true; // Stop polling on error
                    }
                }

                if (data.status === 'confirmed') {
                    // Exchange completed!
                    setPendingExchanges((prev) => {
                        const next = new Set(prev);
                        next.delete(peerUserId);
                        return next;
                    });

                    // Update user status in results
                    setSearchResults((prev) =>
                        prev.map((user) =>
                            user._id === peerUserId ? { ...user, sessionStatus: 'exists' } : user
                        )
                    );

                    // Trigger callback
                    if (onKeyExchangeInitiated) {
                        onKeyExchangeInitiated(peerUserId, peerUsername);
                    }

                    return true; // Stop polling
                }

                if (data.status === 'failed' || data.status === 'rejected') {
                    setPendingExchanges((prev) => {
                        const next = new Set(prev);
                        next.delete(peerUserId);
                        return next;
                    });

                    setSearchResults((prev) =>
                        prev.map((user) =>
                            user._id === peerUserId ? { ...user, sessionStatus: 'none' } : user
                        )
                    );

                    setExchangeError(`Key exchange with ${peerUsername} failed or was rejected`);
                    return true; // Stop polling
                }

                return false; // Continue polling
            } catch (error) {
                console.error('Polling error:', error);
                return false;
            }
        },
        [currentUserId, onKeyExchangeInitiated]
    );

    /**
     * Initiate key exchange with a user
     */
    const handleStartExchange = async (user: UserWithStatus) => {
        if (!user.hasPublicKey) {
            setExchangeError(`${user.username} has not registered their public key yet.`);
            return;
        }

        setInitiatingExchange(user._id);
        setExchangeError(null);

        try {
            // Step 1: Initiate key exchange (creates MESSAGE 1)
            const initMessage = await initiateKeyExchange(currentUserId, user._id);

            // Step 2: Send to server (API expects { message: initMessage })
            const response = await fetch('/api/key-exchange/initiate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: initMessage }),
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || errorData.error || 'Failed to initiate key exchange');
            }

            const data = await response.json();
            console.log('✅ Key exchange initiated:', data);

            // Step 3: Mark as pending
            setPendingExchanges((prev) => new Set(prev).add(user._id));

            // Step 4: Update UI
            setSearchResults((prev) =>
                prev.map((u) => (u._id === user._id ? { ...u, sessionStatus: 'pending' } : u))
            );

            // Step 5: Start polling for status (pass the nonce for completing exchange)
            const sessionId = initMessage.sessionId;
            const myNonce = initMessage.nonce;
            const pollInterval = setInterval(async () => {
                const completed = await pollExchangeStatus(sessionId, user._id, user.username, myNonce);
                if (completed) {
                    clearInterval(pollInterval);
                }
            }, 2000);

            // Store polling reference for cleanup
            pollingRef.current = pollInterval;

            // Stop polling after 5 minutes
            setTimeout(() => {
                clearInterval(pollInterval);
                // Check if still pending
                setPendingExchanges((prev) => {
                    if (prev.has(user._id)) {
                        setExchangeError(`Key exchange with ${user.username} timed out. They may need to accept.`);
                        const next = new Set(prev);
                        next.delete(user._id);
                        return next;
                    }
                    return prev;
                });
            }, 5 * 60 * 1000);
        } catch (error) {
            console.error('Key exchange initiation error:', error);
            setExchangeError(
                error instanceof Error ? error.message : 'Failed to initiate key exchange'
            );
        } finally {
            setInitiatingExchange(null);
        }
    };

    /**
     * Navigate to chat with user
     */
    const handleViewChat = (user: UserWithStatus) => {
        if (onViewChat) {
            onViewChat(user._id, user.username);
        } else {
            // Default: navigate to messaging page
            router.push(`/messaging?peer=${user._id}`);
        }
    };

    /**
     * Cleanup polling on unmount
     */
    useEffect(() => {
        return () => {
            if (pollingRef.current) {
                clearInterval(pollingRef.current);
            }
        };
    }, []);

    /**
     * Get status icon and text
     */
    const getStatusDisplay = (status: SessionStatus) => {
        switch (status) {
            case 'exists':
                return { icon: '🔒', text: 'Secure session active', color: 'text-green-600' };
            case 'expired':
                return { icon: '⏰', text: 'Session expired', color: 'text-yellow-600' };
            case 'pending':
                return { icon: '⏳', text: 'Exchange pending...', color: 'text-blue-600' };
            case 'loading':
                return { icon: '⌛', text: 'Checking...', color: 'text-gray-500' };
            case 'none':
            default:
                return { icon: '○', text: 'No session key', color: 'text-gray-500' };
        }
    };

    /**
     * Get action button based on status
     */
    const renderActionButton = (user: UserWithStatus) => {
        const isInitiating = initiatingExchange === user._id;

        switch (user.sessionStatus) {
            case 'exists':
                return (
                    <button
                        onClick={() => handleViewChat(user)}
                        className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors text-sm font-medium"
                    >
                        View Chat
                    </button>
                );

            case 'pending':
                return (
                    <button
                        disabled
                        className="px-4 py-2 bg-gray-400 text-white rounded-lg cursor-not-allowed text-sm font-medium"
                    >
                        Pending...
                    </button>
                );

            case 'expired':
                return (
                    <button
                        onClick={() => handleStartExchange(user)}
                        disabled={isInitiating}
                        className="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 transition-colors text-sm font-medium disabled:opacity-50"
                    >
                        {isInitiating ? 'Initiating...' : 'Renew Exchange'}
                    </button>
                );

            case 'none':
            default:
                return (
                    <button
                        onClick={() => handleStartExchange(user)}
                        disabled={isInitiating || !user.hasPublicKey}
                        className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                        title={!user.hasPublicKey ? 'User has not registered their public key' : ''}
                    >
                        {isInitiating ? 'Initiating...' : 'Start Exchange'}
                    </button>
                );
        }
    };

    return (
        <div className="w-full">
            {/* Search Input */}
            <div className="relative mb-4">
                <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="🔍 Search users by username..."
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all"
                />
                {isSearching && (
                    <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                        <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-600"></div>
                    </div>
                )}
            </div>

            {/* Error Messages */}
            {searchError && (
                <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
                    {searchError}
                </div>
            )}

            {exchangeError && (
                <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg text-yellow-700 text-sm">
                    {exchangeError}
                    <button
                        onClick={() => setExchangeError(null)}
                        className="ml-2 text-yellow-800 hover:text-yellow-900 font-medium"
                    >
                        ✕
                    </button>
                </div>
            )}

            {/* Search Results */}
            {searchResults.length > 0 ? (
                <div className="border border-gray-200 rounded-lg overflow-hidden">
                    {searchResults.map((user, index) => {
                        const status = getStatusDisplay(user.sessionStatus);
                        return (
                            <div
                                key={user._id}
                                className={`flex items-center justify-between p-4 ${index !== searchResults.length - 1 ? 'border-b border-gray-100' : ''
                                    } hover:bg-gray-50 transition-colors`}
                            >
                                <div className="flex-1">
                                    <div className="flex items-center gap-2">
                                        <span className="font-medium text-gray-900">{user.username}</span>
                                        {!user.hasPublicKey && (
                                            <span className="text-xs px-2 py-0.5 bg-gray-100 text-gray-600 rounded">
                                                No public key
                                            </span>
                                        )}
                                    </div>
                                    <div className={`text-sm ${status.color} flex items-center gap-1 mt-1`}>
                                        <span>{status.icon}</span>
                                        <span>{status.text}</span>
                                    </div>
                                </div>
                                <div>{renderActionButton(user)}</div>
                            </div>
                        );
                    })}
                </div>
            ) : debouncedQuery.trim() && !isSearching ? (
                <div className="text-center py-8 text-gray-500">
                    No users found matching &quot;{debouncedQuery}&quot;
                </div>
            ) : !debouncedQuery.trim() ? (
                <div className="text-center py-8 text-gray-400">
                    Start typing to search for users
                </div>
            ) : null}

            {/* Pending Exchanges Info */}
            {pendingExchanges.size > 0 && (
                <div className="mt-4 p-3 bg-blue-50 border border-blue-200 rounded-lg text-blue-700 text-sm">
                    <span className="font-medium">⏳ {pendingExchanges.size} key exchange(s) pending</span>
                    <p className="text-xs mt-1">
                        Waiting for the other user(s) to accept the key exchange request.
                    </p>
                </div>
            )}
        </div>
    );
}
