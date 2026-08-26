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
