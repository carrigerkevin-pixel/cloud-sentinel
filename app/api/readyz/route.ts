/**
 * CloudSentinel — GET /api/readyz  (readiness probe)
 *
 * Answers a different question from /api/healthz: not "is this process alive?"
 * but "can it actually serve a useful request right now?" For the dashboard,
 * every page and every API route reads Postgres, so a pod that cannot reach the
 * database can serve nothing but errors and should not receive traffic.
 *
 * Where it sits in the architecture:
 *
 *   kubelet --> [ this route ] --> lib/db/client.ts --> Postgres
 *                     |
 *                     +--> 200 ready   -> pod joins the Service's endpoints
 *                     +--> 503 unready -> pod is removed from them
 *
 * Failing readiness does NOT restart the container — it only takes the pod out
 * of load balancing until it recovers. That is why the database check lives
 * here and not in the liveness probe: a database outage should quietly park the
 * pods, not restart them in a loop. The reasoning is written out in full in
 * app/api/healthz/route.ts.
 *
 * This is also what makes a rolling deployment safe. A new pod is not sent
 * traffic until it has proved it can query the database, so a release that
 * cannot reach Postgres — a wrong Secret, an unapplied migration — stalls with
 * the previous version still serving, instead of replacing a working dashboard
 * with a broken one.
 *
 * SECURITY: unauthenticated, like the liveness probe, and therefore written to
 * disclose nothing. Two rules follow, and both are load-bearing:
 *
 *   - The failure body is the fixed string `{"status":"unready"}`. The caught
 *     error is never included. A driver error names the host, port, user and
 *     the reason — `password authentication failed for user "cloudsentinel"`
 *     versus `no pg_hba.conf entry` versus a TLS handshake failure — which
 *     hands an unauthenticated caller a map of the internal network and a
 *     credential oracle. It is logged server-side, where an operator can read
 *     it, and never returned.
 *   - The query is `SELECT 1`, which reads no data and needs no table. A probe
 *     that returned a row count would leak how much the environment has been
 *     scanned; one that read a table would fail during a migration that locks
 *     it, marking healthy pods unready for an unrelated reason.
 */

import { query } from "../../../lib/db/client.ts";

/** Never prerendered — a probe baked at build time would report nothing real. */
export const dynamic = "force-dynamic";

/**
 * How long to wait for the database before calling the pod unready.
 *
 * Shorter than the pod's `timeoutSeconds: 5` in k8s/40-app.yaml, on purpose:
 * this route must answer *before* the kubelet gives up, so the result is a
 * deliberate 503 rather than a timeout the probe has to interpret. The pool's
 * own `connectionTimeoutMillis` is 5s, which is too long to be the only guard
 * here — hence the explicit race below.
 */
const PROBE_TIMEOUT_MS = 3_000;

function unready(): Response {
  return new Response(JSON.stringify({ status: "unready" }), {
    status: 503,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
    },
  });
}

export async function GET(): Promise<Response> {
  let timer: NodeJS.Timeout | undefined;

  try {
    // `Promise.race` leaves the losing promise running, so the timer is cleared
    // in `finally`. Without that, a probe every 10 seconds would leave a
    // pending timer behind each time and hold the event loop busy for no
    // reason — a slow leak that only shows up after the pod has been up a while.
    await Promise.race([
      query("SELECT 1"),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("database probe timed out")),
          PROBE_TIMEOUT_MS,
        );
      }),
    ]);
  } catch (error) {
    // Logged, not returned. See the SECURITY note in the file header: this text
    // names the host, the user and the precise authentication failure.
    console.error(
      `Readiness probe failed: ${error instanceof Error ? error.message : String(error)}`,
    );
    return unready();
  } finally {
    if (timer) clearTimeout(timer);
  }

  return new Response(JSON.stringify({ status: "ready" }), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
    },
  });
}
