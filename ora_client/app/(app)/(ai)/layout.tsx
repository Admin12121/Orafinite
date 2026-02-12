import { AppSidebar } from "@/components/layout/base/app-sidebar";
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";
import { getRequiredSession } from "@/lib/session";
import { getOrCreateOrganization } from "@/lib/actions/organization";

export default async function Layout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  // Fetch session (required for dashboard pages)
  const session = await getRequiredSession();

  // Ensure user has an organization (creates one if not exists)
  // This is called once when user first accesses dashboard
  try {
    await getOrCreateOrganization();
  } catch (e) {
    // Log error but don't block - user might not have Rust API running yet
    console.error("Failed to initialize organization:", e);
  }

  // Map session to user prop format
  const user = {
    name: session.user.name || session.user.email.split("@")[0],
    email: session.user.email,
    avatar: session.user.image || "",
  };

  return (
    <main className="container-wrapper section-soft flex-1">
      <SidebarProvider
        style={
          {
            "--sidebar-width": "calc(var(--spacing) * 72)",
            "--header-height": "calc(var(--spacing) * 12)",
          } as React.CSSProperties
        }
      >
        <AppSidebar user={user} />
        <SidebarInset className="overflow-auto max-h-dvh">
          {/*<SiteHeader />*/}
          {children}
        </SidebarInset>
      </SidebarProvider>
    </main>
  );
}
