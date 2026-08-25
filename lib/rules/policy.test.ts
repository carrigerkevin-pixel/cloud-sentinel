/**
 * CloudSentinel — tests for the policy analysis helpers.
 *
 * Run with `npm test`. Uses Node's built-in test runner (`node:test`), so the
 * project needs no test framework dependency and the suite runs anywhere Node
 * runs — including a GitHub Actions job with no Docker, no LocalStack, and no
 * AWS credentials.
 *
 * What is worth testing here, and why: lib/rules/policy.ts is the layer where
 * every S3 and IAM rule ultimately decides whether a policy is dangerous, and
 * the AWS policy grammar has several shapes that mean the same thing. A helper
 * that handles `Principal: "*"` but not `Principal: { AWS: ["*"] }` produces a
 * *false negative* — a public bucket reported as clean — which is the failure
 * mode this whole project is organised around avoiding. The tests below
 * therefore lean hard on the alternative spellings and on the boundary cases
 * (conditions, inverted elements, regex-special characters in ARNs) rather than
 * on the happy path.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import type {
  PolicyDocument,
  PolicyPrincipal,
  PolicyStatement,
} from "../types/resource.ts";
import {
  describeStatement,
  findAdminStatements,
  findPublicStatements,
  findUnevaluatableStatements,
  findUnrestrictedActionStatements,
  hasCondition,
  isAdminStatement,
  isFullWildcard,
  principalIdentifiers,
  statementCoversAllResources,
  statementGrantsAction,
  statementHasPublicPrincipal,
  statementKey,
  toArray,
  usesInvertedElement,
  wildcardMatches,
} from "./policy.ts";

/** Wraps statements in a document, so tests read as policies rather than arrays. */
function doc(...statements: PolicyStatement[]): PolicyDocument {
  return { Version: "2012-10-17", Statement: statements };
}

// ---------------------------------------------------------------------------
// Shape normalization
// ---------------------------------------------------------------------------

describe("toArray", () => {
  test("accepts both the single and array spellings of a policy element", () => {
    assert.deepEqual(toArray("s3:GetObject"), ["s3:GetObject"]);
    assert.deepEqual(toArray(["s3:GetObject", "s3:PutObject"]), [
      "s3:GetObject",
      "s3:PutObject",
    ]);
  });

  test("returns an empty array for absent elements rather than undefined", () => {
    // Callers iterate the result directly; returning undefined here would push
    // a null check into every rule and one of them would eventually forget it.
    assert.deepEqual(toArray(undefined), []);
    assert.deepEqual(toArray(null), []);
  });
});

describe("principalIdentifiers", () => {
  test("flattens every spelling AWS accepts for a public principal", () => {
    // All three of these mean "anyone on the internet". A check that only
    // recognises the first would silently miss the other two.
    assert.deepEqual(principalIdentifiers("*"), ["*"]);
    assert.deepEqual(principalIdentifiers({ AWS: "*" }), ["*"]);
    assert.deepEqual(principalIdentifiers({ AWS: ["*"] }), ["*"]);
  });

  test("flattens multi-category principals", () => {
    assert.deepEqual(
      principalIdentifiers({
        AWS: ["arn:aws:iam::111122223333:root"],
        Service: "lambda.amazonaws.com",
      }),
      ["arn:aws:iam::111122223333:root", "lambda.amazonaws.com"],
    );
  });

  test("returns nothing for an identity-based policy", () => {
    assert.deepEqual(principalIdentifiers(undefined), []);
  });
});

// ---------------------------------------------------------------------------
// Wildcard matching
// ---------------------------------------------------------------------------

describe("wildcardMatches", () => {
  test("expands * and ? the way AWS does", () => {
    assert.equal(wildcardMatches("s3:Get*", "s3:GetObject"), true);
    assert.equal(wildcardMatches("s3:*", "s3:GetObject"), true);
    assert.equal(wildcardMatches("*", "iam:PassRole"), true);
    assert.equal(wildcardMatches("s3:GetObjec?", "s3:GetObject"), true);
    assert.equal(wildcardMatches("s3:Put*", "s3:GetObject"), false);
  });

  test("matches case-insensitively", () => {
    // AWS treats action names case-insensitively, so a policy written as
    // "s3:getobject" grants the same thing. A case-sensitive comparison here
    // would let that spelling slip past every rule.
    assert.equal(wildcardMatches("s3:getobject", "s3:GetObject"), true);
    assert.equal(wildcardMatches("S3:GETOBJECT", "s3:GetObject"), true);
  });

  test("treats regex metacharacters in ARNs as literals", () => {
    // ARNs are full of characters that are special in a regular expression.
    // Without escaping, "arn:aws:s3:::my.bucket/*" would match
    // "arn:aws:s3:::myXbucket/x" because the dot would be a wildcard.
    assert.equal(
      wildcardMatches("arn:aws:s3:::my.bucket/*", "arn:aws:s3:::myXbucket/x"),
      false,
    );
    assert.equal(
      wildcardMatches("arn:aws:s3:::my.bucket/*", "arn:aws:s3:::my.bucket/x"),
      true,
    );
  });

  test("anchors the pattern at both ends", () => {
    // An unanchored match would make "s3:Get" match "s3:GetObject", quietly
    // widening every pattern in every policy.
    assert.equal(wildcardMatches("s3:Get", "s3:GetObject"), false);
    assert.equal(wildcardMatches("Object", "s3:GetObject"), false);
  });
});

describe("isFullWildcard", () => {
  test("recognises both spellings of unrestricted access", () => {
    assert.equal(isFullWildcard("*"), true);
    assert.equal(isFullWildcard("*:*"), true);
    assert.equal(isFullWildcard(" * "), true);
  });

  test("does not treat a service-scoped wildcard as unrestricted", () => {
    // "iam:*" is dangerous but it is not the same finding as "*", and
    // conflating them would report an over-broad service policy under the
    // headline reserved for full account administrators.
    assert.equal(isFullWildcard("iam:*"), false);
    assert.equal(isFullWildcard("s3:GetObject"), false);
  });
});

// ---------------------------------------------------------------------------
// Statement predicates
// ---------------------------------------------------------------------------

describe("hasCondition", () => {
  test("ignores an empty condition block", () => {
    // An empty object restricts nothing, so treating it as a guard would let a
    // wildcard statement hide behind a condition that does not exist.
    assert.equal(hasCondition({ Effect: "Allow", Condition: {} }), false);
  });

  test("detects a real condition", () => {
    assert.equal(
      hasCondition({
        Effect: "Allow",
        Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } },
      }),
      true,
    );
  });
});

describe("usesInvertedElement", () => {
  test("flags NotAction, NotResource, and NotPrincipal", () => {
    assert.equal(usesInvertedElement({ Effect: "Allow", NotAction: "iam:*" }), true);
    assert.equal(usesInvertedElement({ Effect: "Allow", NotResource: "*" }), true);
    assert.equal(usesInvertedElement({ Effect: "Allow", NotPrincipal: "*" }), true);
    assert.equal(usesInvertedElement({ Effect: "Allow", Action: "*" }), false);
  });
});

describe("statementGrantsAction", () => {
  test("matches through a wildcard", () => {
    assert.equal(
      statementGrantsAction({ Effect: "Allow", Action: "iam:*" }, "iam:PassRole"),
      true,
    );
  });

  test("ignores Deny statements", () => {
    assert.equal(
      statementGrantsAction({ Effect: "Deny", Action: "*" }, "iam:PassRole"),
      false,
    );
  });

  test("can skip a bare wildcard so two rules do not report the same policy", () => {
    const statement: PolicyStatement = { Effect: "Allow", Action: "*" };
    assert.equal(statementGrantsAction(statement, "iam:PassRole"), true);
    assert.equal(
      statementGrantsAction(statement, "iam:PassRole", {
        ignoreBareWildcard: true,
      }),
      false,
    );
    // A narrower wildcard is still a genuine, targeted grant of the action and
    // must survive the filter.
    assert.equal(
      statementGrantsAction({ Effect: "Allow", Action: "iam:*" }, "iam:PassRole", {
        ignoreBareWildcard: true,
      }),
      true,
    );
  });
});

describe("statementCoversAllResources", () => {
  test("treats a missing Resource element as unrestricted", () => {
    // Erring the other way would read an omitted restriction as a restriction,
    // which is the wrong direction for a security tool.
    assert.equal(statementCoversAllResources({ Effect: "Allow", Action: "*" }), true);
  });

  test("recognises a wildcard among several resources", () => {
    assert.equal(
      statementCoversAllResources({
        Effect: "Allow",
        Resource: ["arn:aws:s3:::a", "*"],
      }),
      true,
    );
    assert.equal(
      statementCoversAllResources({
        Effect: "Allow",
        Resource: ["arn:aws:s3:::a"],
      }),
      false,
    );
  });
});

describe("isAdminStatement", () => {
  test("detects the Action '*' on Resource '*' shape", () => {
    assert.equal(
      isAdminStatement({ Effect: "Allow", Action: "*", Resource: "*" }),
      true,
    );
    assert.equal(
      isAdminStatement({ Effect: "Allow", Action: ["*"], Resource: ["*"] }),
      true,
    );
  });

  test("does not flag a statement guarded by a condition", () => {
    // A break-glass policy scoped to an MFA-authenticated session is a
    // legitimate pattern. Flagging it would train the reader to ignore this
    // rule, which is a worse outcome than missing the rare cosmetic condition.
    assert.equal(
      isAdminStatement({
        Effect: "Allow",
        Action: "*",
        Resource: "*",
        Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } },
      }),
      false,
    );
  });

  test("does not flag a Deny, or a service-scoped wildcard", () => {
    assert.equal(
      isAdminStatement({ Effect: "Deny", Action: "*", Resource: "*" }),
      false,
    );
    assert.equal(
      isAdminStatement({ Effect: "Allow", Action: "iam:*", Resource: "*" }),
      false,
    );
  });
});

describe("statementHasPublicPrincipal", () => {
  test("recognises every public spelling", () => {
    const spellings: PolicyPrincipal[] = ["*", { AWS: "*" }, { AWS: ["*"] }];
    for (const principal of spellings) {
      assert.equal(
        statementHasPublicPrincipal({ Effect: "Allow", Principal: principal }),
        true,
        `expected ${JSON.stringify(principal)} to read as public`,
      );
    }
  });

  test("does not flag a named account or service principal", () => {
    assert.equal(
      statementHasPublicPrincipal({
        Effect: "Allow",
        Principal: { AWS: "arn:aws:iam::111122223333:root" },
      }),
      false,
    );
    assert.equal(
      statementHasPublicPrincipal({
        Effect: "Allow",
        Principal: { Service: "cloudtrail.amazonaws.com" },
      }),
      false,
    );
  });
});

// ---------------------------------------------------------------------------
// Document-level queries
// ---------------------------------------------------------------------------

describe("findAdminStatements", () => {
  test("returns an empty array for a null document", () => {
    // Callers must not read this as "safe" — see the doc comment. The test
    // pins the behaviour so the contract stays visible.
    assert.deepEqual(findAdminStatements(null), []);
  });

  test("finds the admin statement among ordinary ones", () => {
    const found = findAdminStatements(
      doc(
        { Effect: "Allow", Action: "s3:GetObject", Resource: "arn:aws:s3:::a/*" },
        { Sid: "Admin", Effect: "Allow", Action: "*", Resource: "*" },
      ),
    );
    assert.equal(found.length, 1);
    assert.equal(found[0]?.Sid, "Admin");
  });
});

describe("findUnrestrictedActionStatements", () => {
  test("requires the action, a wildcard resource, and no condition together", () => {
    const scoped = doc({
      Effect: "Allow",
      Action: "iam:PassRole",
      Resource: "arn:aws:iam::111122223333:role/app",
    });
    // Scoped PassRole is ordinary and necessary; flagging it would bury the
    // unscoped case that actually matters.
    assert.deepEqual(
      findUnrestrictedActionStatements(scoped, "iam:PassRole"),
      [],
    );

    const conditioned = doc({
      Effect: "Allow",
      Action: "iam:PassRole",
      Resource: "*",
      Condition: { StringEquals: { "iam:PassedToService": "ec2.amazonaws.com" } },
    });
    assert.deepEqual(
      findUnrestrictedActionStatements(conditioned, "iam:PassRole"),
      [],
    );

    const unrestricted = doc({
      Sid: "PassAnything",
      Effect: "Allow",
      Action: ["iam:PassRole", "iam:AttachUserPolicy"],
      Resource: "*",
    });
    const found = findUnrestrictedActionStatements(unrestricted, "iam:PassRole");
    assert.equal(found.length, 1);
    assert.equal(found[0]?.Sid, "PassAnything");
  });
});

describe("findPublicStatements", () => {
  test("finds an anonymous grant of the requested action", () => {
    const found = findPublicStatements(
      doc({
        Sid: "PublicRead",
        Effect: "Allow",
        Principal: "*",
        Action: "s3:GetObject",
        Resource: "arn:aws:s3:::bucket/*",
      }),
      "s3:GetObject",
    );
    assert.equal(found.length, 1);
    assert.equal(found[0]?.Sid, "PublicRead");
  });

  test("does not flag a public grant of a different action", () => {
    assert.deepEqual(
      findPublicStatements(
        doc({
          Effect: "Allow",
          Principal: "*",
          Action: "s3:ListBucket",
          Resource: "arn:aws:s3:::bucket",
        }),
        "s3:GetObject",
      ),
      [],
    );
  });

  test("does not flag a grant to a named account", () => {
    assert.deepEqual(
      findPublicStatements(
        doc({
          Effect: "Allow",
          Principal: { AWS: "arn:aws:iam::111122223333:root" },
          Action: "s3:GetObject",
          Resource: "arn:aws:s3:::bucket/*",
        }),
        "s3:GetObject",
      ),
      [],
    );
  });
});

describe("findUnevaluatableStatements", () => {
  test("surfaces statements CloudSentinel cannot reason about", () => {
    const found = findUnevaluatableStatements(
      doc(
        { Effect: "Allow", Action: "s3:GetObject", Resource: "*" },
        { Sid: "Inverted", Effect: "Allow", NotAction: "iam:*", Resource: "*" },
      ),
    );
    assert.equal(found.length, 1);
    assert.equal(found[0]?.Sid, "Inverted");
  });
});

// ---------------------------------------------------------------------------
// Keys and rendering
// ---------------------------------------------------------------------------

describe("statementKey", () => {
  test("prefers the author-supplied Sid", () => {
    assert.equal(statementKey({ Sid: "AllowEverything", Effect: "Allow" }), "AllowEverything");
  });

  test("is stable for identical statements and differs for different ones", () => {
    // Stability is what lets a finding keep its id across scans, so this is
    // load-bearing rather than cosmetic: an unstable key would make every scan
    // look like the old findings were resolved and new ones appeared.
    const a: PolicyStatement = { Effect: "Allow", Action: "*", Resource: "*" };
    const b: PolicyStatement = { Effect: "Allow", Action: "*", Resource: "*" };
    const c: PolicyStatement = { Effect: "Allow", Action: "iam:*", Resource: "*" };

    assert.equal(statementKey(a), statementKey(b));
    assert.notEqual(statementKey(a), statementKey(c));
    assert.match(statementKey(a), /^[0-9a-f]{8}$/);
  });
});

describe("describeStatement", () => {
  test("quotes the actual values so a finding can be checked at a glance", () => {
    const rendered = describeStatement({
      Sid: "PublicRead",
      Effect: "Allow",
      Principal: "*",
      Action: "s3:GetObject",
      Resource: "arn:aws:s3:::bucket/*",
    });
    assert.match(rendered, /Sid "PublicRead"/);
    assert.match(rendered, /Allow Action="s3:GetObject"/);
    assert.match(rendered, /Principal="\*"/);
  });

  test("truncates long lists instead of filling the terminal", () => {
    const rendered = describeStatement({
      Effect: "Allow",
      Action: ["a", "b", "c", "d", "e"],
      Resource: "*",
    });
    assert.match(rendered, /\+2 more/);
  });

  test("names inverted elements rather than silently rendering them as normal", () => {
    // If a NotAction statement rendered as `Action=`, a reader would draw the
    // exact opposite conclusion from the evidence.
    const rendered = describeStatement({
      Effect: "Allow",
      NotAction: "iam:*",
      Resource: "*",
    });
    assert.match(rendered, /NotAction="iam:\*"/);
  });

  test("names the condition keys that guard a statement", () => {
    const rendered = describeStatement({
      Effect: "Allow",
      Action: "*",
      Resource: "*",
      Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } },
    });
    assert.match(rendered, /Condition=Bool/);
  });
});
