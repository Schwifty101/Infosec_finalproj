import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Secure E2E Messaging",
  description: "End-to-End Encrypted Messaging & File Sharing System",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body suppressHydrationWarning={true}>{children}</body>
    </html>
  );
}
