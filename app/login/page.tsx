import LoginForm from '@/app/components/LoginForm';

/**
 * Login Page
 * Wraps the LoginForm component
 */
export default function LoginPage() {
  return (
    <main style={{ minHeight: '100vh', padding: '2rem' }}>
      <LoginForm />
    </main>
  );
}
