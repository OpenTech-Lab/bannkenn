import type { Metadata } from 'next';
import { MainNav } from '@/components/main-nav';
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
        <MainNav />
        {children}
        <Toaster />
      </body>
    </html>
  );
}
