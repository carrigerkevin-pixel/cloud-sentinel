/**
 * CloudSentinel — the sign-out control.
 *
 * A client component because signing out is a POST followed by a navigation,
 * and neither can happen from a plain link.
 *
 * Where it sits in the architecture:
 *
 *   app/(app)/layout.tsx header --> [ this component ] --POST--> /api/auth/logout
 *
 * It is a `<button>` inside a form-less POST rather than an `<a href>` on
 * purpose. A GET that changes state can be triggered by anything that makes the
 * browser fetch a URL — an image tag on another site, a chat client generating
 * a link preview, a prefetching extension — which would log people out without
 * their involvement. The reasoning is recorded in full in the route handler at
 * app/api/auth/logout/route.ts.
 */

"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

export default function LogoutButton() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);

  async function signOut() {
    setBusy(true);
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } catch {
      // Deliberately ignored. If the request failed the cookie may still be
      // set, but the redirect below sends the user to the login page either
      // way — and the authenticated layout re-checks the session on every
      // render, so a still-valid cookie simply lands them back inside rather
      // than leaving them in a broken half-signed-out state.
    } finally {
      // refresh() first so the server components drop their cached
      // authenticated render before the navigation happens.
      router.refresh();
      router.push("/login");
    }
  }

  return (
    <button
      type="button"
      onClick={signOut}
      disabled={busy}
      className="rounded-md border border-zinc-800 px-2.5 py-1 text-xs text-zinc-400 transition-colors hover:border-zinc-700 hover:text-zinc-200 disabled:opacity-50"
    >
      {busy ? "Signing out…" : "Sign out"}
    </button>
  );
}
