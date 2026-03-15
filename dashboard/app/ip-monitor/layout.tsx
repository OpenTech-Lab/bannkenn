import { SidebarLayout, type SidebarLink } from '@/components/sidebar-layout';

const links: SidebarLink[] = [
  { href: '/ip-monitor', label: 'Overview' },
  { href: '/ip-monitor/lookup', label: 'IP Lookup' },
  { href: '/ip-monitor/community', label: 'Community IPs' },
  { href: '/ip-monitor/whitelist', label: 'Whitelist' },
];

export default function IpMonitorLayout({ children }: { children: React.ReactNode }) {
  return (
    <SidebarLayout title="IP Monitor" links={links}>
      {children}
    </SidebarLayout>
  );
}
