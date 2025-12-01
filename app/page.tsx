export default function Home() {
  return (
    <main style={{ minHeight: '100vh', padding: '2rem' }}>
      <div style={{ maxWidth: '600px', margin: '0 auto', textAlign: 'center' }}>
        <h1 style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>
          Secure E2E Encrypted Messaging System
        </h1>
        <p style={{ fontSize: '1.2rem', color: '#666', marginBottom: '2rem' }}>
          End-to-End Encrypted Messaging & File Sharing
        </p>

        <div style={{ backgroundColor: '#f8f9fa', padding: '2rem', borderRadius: '8px', marginBottom: '2rem' }}>
          <h2 style={{ fontSize: '1.5rem', marginTop: 0 }}>Features</h2>
          <ul style={{ textAlign: 'left', lineHeight: '1.8' }}>
            <li>Client-side ECC P-256 key generation</li>
            <li>End-to-end encrypted messaging</li>
            <li>Secure file sharing with encryption</li>
            <li>Custom ECDH key exchange protocol</li>
            <li>Replay attack prevention</li>
            <li>Forward secrecy with key rotation</li>
          </ul>
        </div>

        <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center' }}>
          <a
            href="/register"
            style={{
              padding: '0.75rem 2rem',
              fontSize: '1.1rem',
              backgroundColor: '#007bff',
              color: 'white',
              textDecoration: 'none',
              borderRadius: '4px',
              display: 'inline-block',
            }}
          >
            Register
          </a>
          <a
            href="/login"
            style={{
              padding: '0.75rem 2rem',
              fontSize: '1.1rem',
              backgroundColor: '#28a745',
              color: 'white',
              textDecoration: 'none',
              borderRadius: '4px',
              display: 'inline-block',
            }}
          >
            Login
          </a>
        </div>

        <div style={{ marginTop: '3rem', fontSize: '0.9rem', color: '#666' }}>
          <p>
            <strong>Information Security Project</strong>
            <br />
            Built with Next.js, MongoDB, and Web Crypto API
          </p>
        </div>
      </div>
    </main>
  );
}
