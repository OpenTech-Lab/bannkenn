'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';

const navItems = [
  { href: '/', label: 'Home', match: (p: string) => p === '/' },
  { href: '/ip-monitor', label: 'IP Monitor', match: (p: string) => p.startsWith('/ip-monitor') },
  { href: '/behavior', label: 'Behavior Monitor', match: (p: string) => p.startsWith('/behavior') },
];

export function MainNav() {
  const pathname = usePathname();

  return (
    <header className="border-b border-gray-800">
      <div className="max-w-screen-xl mx-auto px-6 flex items-center h-14">
        <Link href="/" className="font-bold text-white text-sm tracking-wide mr-8">
          BannKenn
        </Link>
        <nav className="flex items-center gap-1 text-sm">
          {navItems.map((item) => {
            const active = item.match(pathname);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  'px-3 py-1.5 rounded-md transition-colors',
                  active
                    ? 'bg-gray-800 text-white'
                    : 'text-gray-400 hover:text-white hover:bg-gray-900'
                )}
              >
                {item.label}
              </Link>
            );
          })}
        </nav>
      </div>
    </header>
  );
}
