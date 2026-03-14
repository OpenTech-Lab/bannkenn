import type { Metadata } from 'next';
import Link from 'next/link';
import { Toaster } from '@/components/ui/sonner';
import './globals.css';

export const metadata: Metadata = {
  title: 'BannKenn — Dashboard',
  description: 'Self-hosted IPS monitor',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-gray-950 text-gray-100 min-h-screen font-mono antialiased">
        <div className="max-w-6xl mx-auto px-4 pt-6">
          <nav className="flex items-center gap-4 text-sm text-gray-400 border-b border-gray-800 pb-4">
            <Link href="/" className="hover:text-white transition-colors">
              Home
            </Link>
            <Link href="/incidents" className="hover:text-white transition-colors">
              Incidents
            </Link>
            <Link href="/lookup" className="hover:text-white transition-colors">
              IP Lookup
            </Link>
            <Link href="/community" className="hover:text-white transition-colors">
              Community IPs
            </Link>
            <Link href="/whitelist" className="hover:text-white transition-colors">
              Whitelist
            </Link>
          </nav>
        </div>
        {children}
        <Toaster />
      </body>
    </html>
  );
}
