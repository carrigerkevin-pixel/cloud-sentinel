/**
 * CloudSentinel — root layout.
 *
 * The outermost HTML shell every page renders inside. Deliberately minimal: it
 * sets fonts, the page background, and the document metadata, and nothing else.
 * The navigation, the authentication guard, and everything that assumes a
 * signed-in user live in app/(app)/layout.tsx instead — because the login page
 * sits outside that group and must render without any of it.
 *
 * Where it sits in the architecture:
 *
 *   [ this file ]
 *     +--> app/login/page.tsx      unauthenticated
 *     +--> app/(app)/layout.tsx    everything behind the session guard
 */

import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";

import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

// A monospace face is not decoration here: ARNs, security group ids, policy
// fragments, and finding ids are all strings a reader compares character by
// character, and a proportional font makes that genuinely harder.
const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

/**
 * Render every page on request rather than prerendering any at build time.
 *
 * This exists to make the Content-Security-Policy in proxy.ts work, and the
 * incompatibility is worth stating plainly because the failure is silent.
 *
 * The policy permits scripts only if they carry a nonce minted for that
 * response. A statically prerendered page has its HTML — including Next's
 * inline bootstrap script — generated once at build time, long before any nonce
 * exists, so those scripts go out unmarked and a conforming browser refuses to
 * run them. The result is a page that returns 200, looks correct in `curl`, and
 * renders blank in a browser. Two routes were affected: `/login` and the
 * not-found page.
 *
 * Forcing dynamic rendering costs this application essentially nothing. Every
 * other route is already dynamic because it reads Postgres per request, and the
 * login page is a small form with no data to cache. There is no page here whose
 * content is the same for every visitor, which is the only situation static
 * generation is for.
 *
 * Declared on the root layout so it applies to every route beneath it. A page
 * added later inherits it and cannot silently reintroduce the problem.
 */
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "CloudSentinel",
  description:
    "Cloud security posture findings, risk score, and scan history for a simulated AWS environment.",
  // The dashboard shows live security weaknesses. Asking search engines and
  // link previewers to stay away costs nothing and is the right default for a
  // tool whose pages list exactly where an environment is soft.
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full bg-zinc-950 text-zinc-100 font-sans">
        {children}
      </body>
    </html>
  );
}
