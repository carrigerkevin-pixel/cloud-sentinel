/**
 * CloudSentinel — the sign-in page.
 *
 * The only page outside the authenticated area, which is why it lives at
 * `app/login` rather than inside the `(app)` route group whose layout enforces
 * a session.
 *
 * Where it sits in the architecture:
 *
 *   [ this page ] --POST--> /api/auth/login --> Set-Cookie --> /
 *
 * A client component, because it holds form state and needs to react to a
 * failed attempt without a full page reload. It is the only interactive part of
 * the dashboard that an unauthenticated visitor can reach, so it does as little
 * as possible: no data fetching, no session reading, one POST.
 *
 * ## What this page deliberately does not do
 *
 * **It does not tell the visitor whether an email exists.** The API returns one
 * message for a wrong password and an unknown address, and this page shows that
 * message verbatim rather than trying to be more helpful. Being more helpful
 * here means confirming which addresses hold accounts.
 *
 * **It does not offer a sign-up link, or password recovery.** Accounts exist
 * only via `npm run user:create`, and a reset flow would be a second
 * authentication path to secure — the one part of a login system most often
 * left weaker than the login itself. For a locally-run tool, the operator has
 * shell access and can run `npm run user:passwd`.
 */

"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

export default function LoginPage() {
  const router = useRouter();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);

    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        const body = await response.json().catch(() => null);
        setError(
          body?.error?.message ?? "Could not sign in. Please try again.",
        );
        // The password field is cleared but the email is kept. Clearing both
        // punishes a typo; clearing neither leaves a password sitting in the
        // DOM of a page that just failed to authenticate.
        setPassword("");
        return;
      }

      // `refresh()` before `push()` so the server components in the
      // authenticated layout re-render with the new cookie. Without it Next may
      // serve a cached render produced while the user was still signed out, and
      // the dashboard flashes its signed-out state before correcting itself.
      router.refresh();
      router.push("/");
    } catch {
      // A network failure, not a rejected credential. Worth distinguishing:
      // "check your connection" and "check your password" send the user to
      // completely different places.
      setError("Could not reach the server. Is it still running?");
      setPassword("");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-6 py-16">
      <div className="w-full max-w-sm">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-50">
            CloudSentinel
          </h1>
          <p className="mt-1 text-sm text-zinc-500">
            Cloud security posture management
          </p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-6"
        >
          <div className="space-y-4">
            <div>
              <label
                htmlFor="email"
                className="block text-sm font-medium text-zinc-300"
              >
                Email
              </label>
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="username"
                required
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                className="mt-1.5 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 outline-none placeholder:text-zinc-600 focus:border-sky-600"
                placeholder="you@example.com"
              />
            </div>

            <div>
              <label
                htmlFor="password"
                className="block text-sm font-medium text-zinc-300"
              >
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className="mt-1.5 w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-sky-600"
              />
            </div>
          </div>

          {error ? (
            // role="alert" so a screen reader announces the failure rather than
            // leaving the user to discover that nothing happened.
            <p
              role="alert"
              className="mt-4 rounded-md border border-red-900/50 bg-red-950/40 px-3 py-2 text-sm text-red-300"
            >
              {error}
            </p>
          ) : null}

          <button
            type="submit"
            disabled={submitting}
            className="mt-6 w-full rounded-md bg-sky-600 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {submitting ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <p className="mt-4 text-center text-xs text-zinc-600">
          Accounts are created from the command line with{" "}
          <code className="font-mono text-zinc-500">npm run user:create</code>.
        </p>
      </div>
    </main>
  );
}
