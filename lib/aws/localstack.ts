/**
 * LocalStack-aware AWS client factory.
 *
 * Every client this module hands out is pinned to a loopback endpoint and to
 * throwaway credentials. That is deliberate: CloudSentinel's seed script
 * provisions *intentionally vulnerable* resources (world-readable buckets,
 * management ports open to 0.0.0.0/0, wildcard IAM policies). Pointing that
 * script at a real AWS account would be a genuine security incident, so the
 * guard below is a hard failure rather than a warning.
 *
 * Shared by the seed script and, later, the collector service.
 */

import { S3Client } from "@aws-sdk/client-s3";
import { EC2Client } from "@aws-sdk/client-ec2";
import { IAMClient } from "@aws-sdk/client-iam";

export const LOCALSTACK_ENDPOINT =
  process.env.LOCALSTACK_ENDPOINT ?? "http://localhost:4566";

export const AWS_REGION = process.env.AWS_REGION ?? "us-east-1";

/**
 * Hostnames we accept as "definitely not real AWS". `localstack` and
 * `host.docker.internal` are included so this still works from inside a
 * container on the same Docker network.
 */
const LOOPBACK_HOSTS = new Set([
  "localhost",
  "127.0.0.1",
  "[::1]",
  "::1",
  "0.0.0.0",
  "localstack",
  "host.docker.internal",
]);

/**
 * Throws unless `endpoint` points somewhere that cannot be real AWS.
 * Exported so tests and other entry points can assert the same invariant.
 */
export function assertLocalEndpoint(endpoint: string): URL {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new Error(
      `LOCALSTACK_ENDPOINT is not a valid URL: ${JSON.stringify(endpoint)}`,
    );
  }

  if (!LOOPBACK_HOSTS.has(url.hostname)) {
    throw new Error(
      `Refusing to run against "${url.hostname}".\n` +
        `This tooling provisions intentionally-insecure resources and must only ` +
        `ever talk to LocalStack. Allowed hosts: ${[...LOOPBACK_HOSTS].join(", ")}.`,
    );
  }

  if (url.hostname.endsWith(".amazonaws.com")) {
    throw new Error("Refusing to run against a real AWS endpoint.");
  }

  return url;
}

/**
 * Verifies LocalStack is actually listening before we start issuing API calls,
 * so a stopped container produces one clear message instead of a pile of
 * socket errors. Also a second line of defence: real AWS has no such endpoint.
 */
export async function assertLocalStackReachable(
  endpoint: string = LOCALSTACK_ENDPOINT,
): Promise<void> {
  assertLocalEndpoint(endpoint);
  const healthUrl = new URL("/_localstack/health", endpoint);

  let response: Response;
  try {
    response = await fetch(healthUrl, {
      signal: AbortSignal.timeout(10_000),
    });
  } catch (cause) {
    throw new Error(
      `Could not reach LocalStack at ${endpoint}.\n` +
        `Start it with Docker, then re-run. Underlying error: ${
          cause instanceof Error ? cause.message : String(cause)
        }`,
      { cause },
    );
  }

  if (!response.ok) {
    throw new Error(
      `LocalStack health check at ${healthUrl} returned HTTP ${response.status}.`,
    );
  }
}

/**
 * Dummy credentials. LocalStack does not validate these, but setting them
 * explicitly stops the SDK from silently falling back to a real credential
 * chain (~/.aws/credentials, SSO, instance metadata, AWS_PROFILE).
 */
const LOCALSTACK_CREDENTIALS = {
  accessKeyId: "test",
  secretAccessKey: "test",
} as const;

function baseConfig() {
  const endpoint = LOCALSTACK_ENDPOINT;
  assertLocalEndpoint(endpoint);
  return {
    endpoint,
    region: AWS_REGION,
    credentials: LOCALSTACK_CREDENTIALS,
  };
}

/** S3 needs path-style addressing; LocalStack does not do vhost-style buckets. */
export function createS3Client(): S3Client {
  return new S3Client({ ...baseConfig(), forcePathStyle: true });
}

export function createEC2Client(): EC2Client {
  return new EC2Client(baseConfig());
}

export function createIAMClient(): IAMClient {
  return new IAMClient(baseConfig());
}
