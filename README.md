This is a [Next.js](https://nextjs.org) project bootstrapped with [`create-next-app`](https://nextjs.org/docs/app/api-reference/cli/create-next-app).

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Local AWS fixtures (LocalStack)

CloudSentinel scans a simulated AWS account. `scripts/seed-localstack.ts` provisions
that account in LocalStack: a set of **intentionally misconfigured** resources for the
rule engine to flag, plus a compliant control group it should leave alone.

```bash
npm run seed        # provision fixtures (idempotent, safe to re-run)
npm run seed:down   # tear them back down
npm run seed:list   # print the fixture plan without touching LocalStack
```

Requires LocalStack running on `http://localhost:4566` (override with `LOCALSTACK_ENDPOINT`).

| Fixture | Posture |
| --- | --- |
| `cloudsentinel-public-assets` (S3) | Block Public Access off, public-read policy + ACL, no versioning |
| `cloudsentinel-open-mgmt` (SG) | tcp/22 and tcp/3389 open to `0.0.0.0/0`, tcp/22 open to `::/0` |
| `cloudsentinel-admin-svc` (IAM) | `*:*` managed policy, unrestricted `iam:PassRole`, console access, no MFA |
| `cloudsentinel-private-logs` (S3) | Control — PAB on, versioning on |
| `cloudsentinel-restricted-app` (SG) | Control — tcp/443 from `10.0.0.0/16` only |
| `cloudsentinel-readonly-svc` (IAM) | Control — least privilege, no console, no access keys |

> **Safety.** These fixtures are deliberately vulnerable. `lib/aws/localstack.ts` hard-fails
> on any endpoint that is not loopback and pins credentials to LocalStack dummies, so the
> seeder cannot reach a real AWS account even if the ambient AWS profile points at one.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
