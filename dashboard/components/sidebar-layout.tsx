'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';
import { type ReactNode } from 'react';

export type SidebarLink = {
  href: string;
  label: string;
  icon?: ReactNode;
};

type SidebarLayoutProps = {
  title: string;
  links: SidebarLink[];
  children: ReactNode;
};

export function SidebarLayout({ title, links, children }: SidebarLayoutProps) {
  const pathname = usePathname();

  return (
    <div className="flex min-h-[calc(100vh-3.5rem)]">
      <aside className="w-56 shrink-0 border-r border-gray-800 px-3 py-6 hidden md:block">
        <p className="px-3 mb-4 text-xs font-semibold uppercase tracking-[0.25em] text-muted-foreground">
          {title}
        </p>
        <nav className="space-y-0.5">
          {links.map((link) => {
            const active = pathname === link.href;
            return (
              <Link
                key={link.href}
                href={link.href}
                className={cn(
                  'flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors',
                  active
                    ? 'bg-gray-800 text-white font-medium'
                    : 'text-gray-400 hover:text-white hover:bg-gray-900/60'
                )}
              >
                {link.icon}
                {link.label}
              </Link>
            );
          })}
        </nav>
      </aside>

      {/* Mobile nav */}
      <div className="md:hidden fixed bottom-0 left-0 right-0 z-50 border-t border-gray-800 bg-gray-950 px-2 py-2">
        <nav className="flex items-center justify-around gap-1">
          {links.map((link) => {
            const active = pathname === link.href;
            return (
              <Link
                key={link.href}
                href={link.href}
                className={cn(
                  'flex-1 text-center rounded-md px-2 py-1.5 text-xs transition-colors',
                  active
                    ? 'bg-gray-800 text-white font-medium'
                    : 'text-gray-400 hover:text-white'
                )}
              >
                {link.label}
              </Link>
            );
          })}
        </nav>
      </div>

      <main className="flex-1 overflow-auto pb-16 md:pb-0">{children}</main>
    </div>
  );
}
