import { SidebarLayout, type SidebarLink } from '@/components/sidebar-layout';

const links: SidebarLink[] = [
  { href: '/behavior', label: 'Overview' },
  { href: '/behavior/fleet', label: 'Fleet & Containment' },
  { href: '/behavior/incidents', label: 'Incidents' },
];

export default function BehaviorLayout({ children }: { children: React.ReactNode }) {
  return (
    <SidebarLayout title="Behavior Monitor" links={links}>
      {children}
    </SidebarLayout>
  );
}
