import RegisterForm from '@/app/components/RegisterForm';

/**
 * Registration Page
 * Wraps the RegisterForm component
 */
export default function RegisterPage() {
  return (
    <main style={{ minHeight: '100vh', padding: '2rem' }}>
      <RegisterForm />
    </main>
  );
}
