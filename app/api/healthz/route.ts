/**
 * CloudSentinel — GET /api/healthz  (liveness probe)
 *
 * Answers one question: is this Node process still able to serve a request?
 *
 * Where it sits in the architecture: this is the container's *liveness* probe,
 * read by Kubernetes (k8s/40-app.yaml) and by the Compose healthcheck. It is
 * the shallowest possible check by design and deliberately touches nothing —
 * no database, no filesystem, no downstream service.
 *
 *   kubelet --> [ this route ] --> 200, or restart the container
 *
 * Why it must stay shallow, which is the whole point of the file:
 *
 * Failing a liveness probe gets the container *killed and restarted*. So a
 * liveness check must only fail for conditions a restart can actually fix — a
 * deadlocked event loop, a wedged process. If this route queried Postgres, then
 * a database outage would fail every replica's liveness probe at once, and
 * Kubernetes would respond by restarting every dashboard pod in a loop. That
 * turns a recoverable dependency outage into a self-inflicted crash loop that
 * keeps restarting healthy processes and, on recovery, hits the database with a
 * thundering herd of cold starts. The dependency check belongs in
 * /api/readyz, whose failure merely removes the pod from the Service.
 *
 * SECURITY: this endpoint is unauthenticated, because a probe has no session
 * and Kubernetes cannot log in. It is therefore treated as public, and returns
 * a fixed constant. No version string, no uptime, no hostname, no build id:
 * an unauthenticated endpoint that reports the running version tells anyone who
 * finds it exactly which published CVEs to try. `Cache-Control: no-store` keeps
 * a proxy from answering the probe on a dead process's behalf.
 */

/**
 * Never prerendered. Without this Next would evaluate the route at build time
 * and serve a static copy, which would report a build-time result forever and
 * make the probe meaningless.
 */
export const dynamic = "force-dynamic";

export function GET(): Response {
  return new Response(JSON.stringify({ status: "ok" }), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
    },
  });
}
