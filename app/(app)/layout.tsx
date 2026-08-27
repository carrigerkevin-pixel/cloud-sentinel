/**
 * CloudSentinel — layout for the authenticated dashboard.
 *
 * Wraps every page that requires a session: the overview, the findings list and
 * detail pages, and the scan history. The login page deliberately sits outside
 * this group so it can render without a session.
 *
 * Where it sits in the architecture:
 *
 *   app/layout.tsx
 *     +--> [ this file ]  session guard + navigation
 *            +--> app/(app)/page.tsx           overview
 *            +--> app/(app)/findings/...       findings
 *            +--> app/(app)/scans/page.tsx     scan history
 *
 * `(app)` is a route group: the parentheses mean the folder name does not
 * appear in any URL. So `app/(app)/page.tsx` serves `/`, not `/app/`. The group
 * exists purely so that one layout can guard several routes.
 *
 * ## The guard
 *
 * `currentUser()` runs here, on the server, before any child page renders. It
 * does the full check — token signature, expiry, and a database lookup
 * confirming the account still exists, the session has not been revoked, and
 * the role has not changed.
 *
 * SECURITY: a layout is a real access control in the App Router, because a
 * child page cannot render until its parent layouts have. The redirect below
 * therefore happens before any page in the group runs a query. What a layout is
 * *not* is a substitute for checking in the API routes: pages and routes are
 * separate entry points, and `/api/findings` is reachable directly with `curl`
 * whatever this file does. Every route guards itself as well — see
 * lib/api/http.ts.
 *
 * Because the session is re-verified on every request, revoking a user's
 * sessions with `npm run user:revoke` takes effect on their next page load
 * rather than whenever their token happens to expire.
 */

import Link from "next/link";
import { redirect } from "next/navigation";

import { currentUser } from "../../lib/auth/session.ts";
import LogoutButton from "../components/LogoutButton.tsx";

/** The dashboard's top-level sections. */
const NAV = [
  { href: "/", label: "Overview" },
  { href: "/findings", label: "Findings" },
  // Behavioural detections from the ML layer. Deliberately a sibling of
  // Findings rather than a tab inside it: the two answer different questions —
  // "what is configured wrongly" versus "who is behaving strangely" — and an
  // intrusion using stolen but legitimate credentials shows up only in the
  // second. Nesting it would imply anomalies are a kind of finding, which would
  // invite the expectation that they can be resolved. They cannot.
  { href: "/anomalies", label: "Anomalies" },
  { href: "/scans", label: "Scans" },
] as const;

export default async function AppLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const user = await currentUser();

  // No valid session: straight to the login page, before any child renders.
  if (!user) redirect("/login");

  return (
    <div className="min-h-screen">
      <header className="border-b border-zinc-800/80 bg-zinc-900/30">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-3 px-6 py-3">
          <Link
            href="/"
            className="text-sm font-semibold tracking-tight text-zinc-100"
          >
            CloudSentinel
          </Link>

          <nav className="flex items-center gap-1">
            {NAV.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className="rounded-md px-2.5 py-1 text-sm text-zinc-400 transition-colors hover:bg-zinc-800/60 hover:text-zinc-100"
              >
                {item.label}
              </Link>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-3">
            <span className="text-xs text-zinc-500">
              {user.email}
              {/* The role is shown because it changes what the user can do —
                  a viewer who cannot find the triage controls should be able to
                  see why without having to ask. */}
              <span className="ml-1.5 rounded border border-zinc-700/60 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-zinc-500">
                {user.role}
              </span>
            </span>
            <LogoutButton />
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-8">{children}</main>
    </div>
  );
}
