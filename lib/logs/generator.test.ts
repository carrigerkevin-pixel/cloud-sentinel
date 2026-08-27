/**
 * CloudSentinel — tests for the synthetic activity generator.
 *
 * Run with `npm test`. Pure computation: no network, no filesystem, no Docker,
 * no Python.
 *
 * These tests fall into three groups, and the middle group is the one that
 * matters most.
 *
 * 1. **Reproducibility.** The same seed must produce byte-identical output.
 *    Every threshold in the ML layer is tuned against this data, so a generator
 *    that drifted would invalidate them silently.
 *
 * 2. **Dataset properties the detector's correctness depends on.** These are
 *    assertions about the *shape* of the generated world, not about the code
 *    that generated it. If `alice-analyst` ever acquires a routine IAM habit,
 *    the privilege-escalation scenario stops being anomalous and the evaluation
 *    quietly reports a miss that looks like a model failure but is actually a
 *    data-generation change. Pinning these properties here means the failure
 *    surfaces as a clear assertion in this file instead — which is the whole
 *    reason to test a fixture generator at all.
 *
 * 3. **Answer-key hygiene.** The events file must contain nothing that reveals
 *    which events were injected, because a detector that could tell attack
 *    records apart structurally would be cheating rather than detecting.
 *
 * The suite deliberately does *not* assert that the detector catches anything —
 * that belongs to ml/evaluate.py, which runs the actual models. This file only
 * guarantees the data is what the models are entitled to assume.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import type { CloudTrailEvent } from "../types/cloudtrail.ts";
import {
  DEFAULT_PRINCIPALS,
  generateActivity,
  type PrincipalProfile,
} from "./generator.ts";

/**
 * One shared full-size run, generated once for the whole file.
 *
 * Generating the default 30-day window costs about 200ms, which is fine once
 * and wasteful thirty times. The tests below only read from it, so sharing is
 * safe.
 */
const DEFAULT_RUN = generateActivity();

/** Looks up a profile by the tail of its ARN. */
function profileFor(name: string): PrincipalProfile {
  const profile = DEFAULT_PRINCIPALS.find((candidate) =>
    candidate.arn.endsWith(name),
  );
  assert.ok(profile, `no principal profile named ${name}`);
  return profile;
}

/** All events belonging to one principal, by the tail of its ARN. */
function eventsFor(name: string): CloudTrailEvent[] {
  const arn = profileFor(name).arn;
  return DEFAULT_RUN.log.events.filter(
    (event) => event.userIdentity.arn === arn,
  );
}

/** The set of event ids that belong to any injected attack. */
function attackEventIds(): Set<string> {
  return new Set(DEFAULT_RUN.labels.labels.flatMap((label) => label.eventIds));
}

// ---------------------------------------------------------------------------
// Reproducibility
// ---------------------------------------------------------------------------

describe("generateActivity — reproducibility", () => {
  test("the same seed produces identical output", () => {
    const a = generateActivity({ days: 5, seed: "repeat" });
    const b = generateActivity({ days: 5, seed: "repeat" });

    assert.deepEqual(a.log, b.log);
    assert.deepEqual(a.labels, b.labels);
  });

  test("a different seed produces different events", () => {
    const a = generateActivity({ days: 5, seed: "seed-a" });
    const b = generateActivity({ days: 5, seed: "seed-b" });

    assert.notDeepEqual(a.log.events, b.log.events);
  });

  test("metadata records everything needed to regenerate the run", () => {
    const { metadata } = generateActivity({ days: 3, seed: "meta" }).log;

    assert.equal(metadata.seed, "meta");
    assert.equal(metadata.days, 3);
    assert.equal(metadata.principalCount, DEFAULT_PRINCIPALS.length);
    assert.equal(metadata.eventCount, generateActivity({ days: 3, seed: "meta" }).log.events.length);
  });

  test("generatedAt is derived from the window, not the wall clock", () => {
    // If this were `new Date()` the metadata would differ between two runs of
    // the same seed, so the "regenerating changes nothing" property — which is
    // what justifies not committing the fixture — would be false.
    const a = generateActivity({ days: 3, seed: "clock" }).log.metadata;
    const b = generateActivity({ days: 3, seed: "clock" }).log.metadata;

    assert.equal(a.generatedAt, b.generatedAt);
  });

  test("changing one principal does not perturb the others", () => {
    // Each principal draws from a generator seeded with its own ARN, so
    // dropping one must leave every other principal's stream untouched. Without
    // this, adding a persona would rewrite the entire log and make the diff —
    // and any threshold tuned against the old data — worthless.
    const full = generateActivity({ days: 4, seed: "isolate", injectAttacks: false });

    const withoutCarol = generateActivity({
      days: 4,
      seed: "isolate",
      injectAttacks: false,
      principals: DEFAULT_PRINCIPALS.filter(
        (profile) => !profile.arn.endsWith("carol-finance"),
      ),
    });

    const bobArn = profileFor("bob-devops").arn;
    const bobFromFull = full.log.events.filter((e) => e.userIdentity.arn === bobArn);
    const bobFromReduced = withoutCarol.log.events.filter(
      (e) => e.userIdentity.arn === bobArn,
    );

    assert.deepEqual(bobFromReduced, bobFromFull);
  });
});

// ---------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------

describe("generateActivity — structure", () => {
  test("events are sorted by time", () => {
    const times = DEFAULT_RUN.log.events.map((event) => event.eventTime);
    const sorted = [...times].sort();

    assert.deepEqual(times, sorted);
  });

  test("every event falls inside the requested window", () => {
    const run = generateActivity({ days: 6, seed: "window" });
    const start = new Date(run.log.metadata.startTime).getTime();
    const end = start + 6 * 24 * 60 * 60 * 1000;

    for (const event of run.log.events) {
      const at = new Date(event.eventTime).getTime();
      assert.ok(at >= start && at < end, `event outside window: ${event.eventTime}`);
    }
  });

  test("every event has the fields the Python layer parses", () => {
    // This is the cross-language contract from lib/types/cloudtrail.ts. Python
    // cannot type-check against TypeScript, so a rename here would surface as a
    // KeyError deep inside feature extraction. Asserting the field names in the
    // language that produces them is the cheapest guard available.
    for (const event of DEFAULT_RUN.log.events) {
      assert.equal(typeof event.eventID, "string");
      assert.equal(typeof event.eventTime, "string");
      assert.equal(typeof event.eventName, "string");
      assert.equal(typeof event.eventSource, "string");
      assert.equal(typeof event.awsRegion, "string");
      assert.equal(typeof event.sourceIPAddress, "string");
      assert.equal(typeof event.readOnly, "boolean");
      assert.equal(typeof event.userIdentity.arn, "string");
      assert.ok(event.eventTime.endsWith("Z"), "eventTime must be UTC");
    }
  });

  test("event ids are unique", () => {
    const ids = new Set(DEFAULT_RUN.log.events.map((event) => event.eventID));

    assert.equal(ids.size, DEFAULT_RUN.log.events.length);
  });

  test("every source address is in an RFC 5737 documentation range", () => {
    // SECURITY: a committed or published fixture must never appear to accuse a
    // real address of anything. These three /24s are reserved for examples and
    // route nowhere, so nothing generated here can be mistaken for a genuine
    // host or wrongly attributed to somebody.
    const allowed = ["192.0.2.", "198.51.100.", "203.0.113."];

    for (const event of DEFAULT_RUN.log.events) {
      assert.ok(
        allowed.some((prefix) => event.sourceIPAddress.startsWith(prefix)),
        `address outside the documentation ranges: ${event.sourceIPAddress}`,
      );
    }
  });

  test("every event belongs to the documentation account", () => {
    for (const event of DEFAULT_RUN.log.events) {
      assert.equal(event.userIdentity.accountId, "123456789012");
    }
  });
});

// ---------------------------------------------------------------------------
// Answer-key hygiene
// ---------------------------------------------------------------------------

describe("generateActivity — answer-key hygiene", () => {
  test("the log carries no labels of any kind", () => {
    // The events file is everything the detector may read. If it contained the
    // labels — or a marker field on attack events — the evaluation would be
    // measuring nothing.
    assert.deepEqual(Object.keys(DEFAULT_RUN.log).sort(), ["events", "metadata"]);
  });

  test("attack events are structurally indistinguishable from normal ones", () => {
    // Attack and baseline events must have the same field vocabulary. A
    // detector able to separate them by shape rather than by behaviour would
    // score perfectly while proving nothing.
    const attacks = attackEventIds();
    const shapeOf = (event: CloudTrailEvent) => Object.keys(event).sort().join(",");

    const attackShapes = new Set<string>();
    const normalShapes = new Set<string>();

    for (const event of DEFAULT_RUN.log.events) {
      (attacks.has(event.eventID) ? attackShapes : normalShapes).add(shapeOf(event));
    }

    // Every shape an attack event takes must also occur in ordinary traffic.
    for (const shape of attackShapes) {
      assert.ok(
        normalShapes.has(shape),
        `attack events have a field shape no normal event has: ${shape}`,
      );
    }
  });

  test("attack events are interleaved with normal traffic, not appended", () => {
    // If injected events all landed at the end of the file, their position
    // alone would give them away to anything reading the log in order.
    const attacks = attackEventIds();
    const indices = DEFAULT_RUN.log.events
      .map((event, index) => (attacks.has(event.eventID) ? index : -1))
      .filter((index) => index >= 0);

    const last = DEFAULT_RUN.log.events.length - 1;
    assert.ok(Math.min(...indices) > 0, "an attack event is the very first record");
    assert.ok(Math.max(...indices) < last, "an attack event is the very last record");
  });

  test("every labelled event id actually exists in the log", () => {
    const present = new Set(DEFAULT_RUN.log.events.map((event) => event.eventID));

    for (const label of DEFAULT_RUN.labels.labels) {
      for (const id of label.eventIds) {
        assert.ok(present.has(id), `label references a missing event: ${id}`);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// The injected attacks
// ---------------------------------------------------------------------------

describe("generateActivity — injected attacks", () => {
  test("all five scenarios are present exactly once", () => {
    const scenarios = DEFAULT_RUN.labels.labels.map((label) => label.scenario).sort();

    assert.deepEqual(scenarios, [
      "credential_abuse",
      "data_exfiltration",
      "new_geo_login",
      "off_hours_access",
      "privilege_escalation",
    ]);
  });

  test("no scenario generates an empty event list", () => {
    // A scenario that silently produced nothing would appear in the evaluation
    // as an unexplained recall miss, which is a confusing way to discover a
    // generator bug.
    for (const label of DEFAULT_RUN.labels.labels) {
      assert.ok(label.eventIds.length > 0, `${label.scenario} produced no events`);
    }
  });

  test("--no-attacks produces a clean log with no labels", () => {
    // This mode is how the false-positive rate gets measured: a month of
    // ordinary work in which the correct number of detections is zero.
    const clean = generateActivity({ days: 8, seed: "clean", injectAttacks: false });

    assert.equal(clean.labels.labels.length, 0);
    assert.ok(clean.log.events.length > 0);
  });

  test("attacks are scheduled in the second half of the window", () => {
    // The detector baselines each principal against its own history, so an
    // attack near the start would be judged against almost no history and would
    // be unfairly hard to catch. Every injection must have weeks behind it.
    const start = new Date(DEFAULT_RUN.log.metadata.startTime).getTime();
    const span = DEFAULT_RUN.log.metadata.days * 24 * 60 * 60 * 1000;

    for (const label of DEFAULT_RUN.labels.labels) {
      const offset = (new Date(label.startTime).getTime() - start) / span;
      assert.ok(
        offset >= 0.35,
        `${label.scenario} starts only ${(offset * 100).toFixed(0)}% into the window`,
      );
    }
  });

  test("privilege escalation ends in a real escalation, by a non-admin", () => {
    const label = DEFAULT_RUN.labels.labels.find(
      (candidate) => candidate.scenario === "privilege_escalation",
    );
    assert.ok(label);

    const ids = new Set(label.eventIds);
    const events = DEFAULT_RUN.log.events.filter((event) => ids.has(event.eventID));
    const names = events.map((event) => event.eventName);

    assert.equal(label.principalArn, profileFor("alice-analyst").arn);
    assert.ok(names.includes("AttachUserPolicy"));
    assert.ok(names.includes("CreateAccessKey"));
    assert.ok(events.every((event) => event.userIdentity.arn === label.principalArn));
  });

  test("credential abuse is mostly denials across many services", () => {
    const label = DEFAULT_RUN.labels.labels.find(
      (candidate) => candidate.scenario === "credential_abuse",
    );
    assert.ok(label);

    const ids = new Set(label.eventIds);
    const events = DEFAULT_RUN.log.events.filter((event) => ids.has(event.eventID));
    const denied = events.filter((event) => event.errorCode === "AccessDenied");
    const services = new Set(events.map((event) => event.eventSource));

    assert.ok(
      denied.length / events.length > 0.6,
      `expected a majority of denials, got ${denied.length}/${events.length}`,
    );
    assert.ok(services.size >= 5, `expected a broad sweep, got ${services.size} services`);
  });

  test("the new-geo login uses a region the principal never otherwise uses", () => {
    const label = DEFAULT_RUN.labels.labels.find(
      (candidate) => candidate.scenario === "new_geo_login",
    );
    assert.ok(label);

    const ids = new Set(label.eventIds);
    const bobEvents = eventsFor("bob-devops");

    const foreignRegions = new Set(
      bobEvents.filter((e) => ids.has(e.eventID)).map((e) => e.awsRegion),
    );
    const normalRegions = new Set(
      bobEvents.filter((e) => !ids.has(e.eventID)).map((e) => e.awsRegion),
    );

    assert.deepEqual([...foreignRegions], ["eu-west-1"]);
    assert.ok(
      !normalRegions.has("eu-west-1"),
      "the 'new' region appears in this principal's normal traffic too",
    );
  });

  test("exfiltration touches a distinct object every time", () => {
    // Distinct keys are what separate a bucket sweep from a retry loop. If the
    // generator reused keys, the exfiltration scenario would be
    // indistinguishable from a misbehaving client.
    const label = DEFAULT_RUN.labels.labels.find(
      (candidate) => candidate.scenario === "data_exfiltration",
    );
    assert.ok(label);

    const ids = new Set(label.eventIds);
    const keys = DEFAULT_RUN.log.events
      .filter((event) => ids.has(event.eventID))
      .map((event) => event.requestParameters?.key);

    assert.equal(new Set(keys).size, keys.length);
    assert.ok(keys.length > 200, `expected a large sweep, got ${keys.length}`);
  });

  test("off-hours access is unremarkable except for the clock", () => {
    // The deliberately weak scenario. Same actions, same address range, same
    // region as this principal's normal work — only the hour is wrong. It is
    // here to test whether the model can act on a single weak signal.
    const label = DEFAULT_RUN.labels.labels.find(
      (candidate) => candidate.scenario === "off_hours_access",
    );
    assert.ok(label);

    const carol = profileFor("carol-finance");
    const ids = new Set(label.eventIds);
    const events = DEFAULT_RUN.log.events.filter((event) => ids.has(event.eventID));

    for (const event of events) {
      assert.ok(event.sourceIPAddress.startsWith(carol.homeIpPrefix));
      assert.equal(event.awsRegion, carol.homeRegion);
    }

    // And the hour really is outside her working day.
    const localHour =
      (new Date(label.startTime).getUTCHours() + carol.utcOffsetHours + 24) % 24;
    assert.ok(
      localHour < carol.workStartHourLocal || localHour > carol.workEndHourLocal,
      `expected an off-hours start, got ${localHour}:00 local`,
    );
  });
});

// ---------------------------------------------------------------------------
// Dataset properties the detection story depends on
// ---------------------------------------------------------------------------

describe("generateActivity — baseline behaviour", () => {
  test("alice has no IAM history outside her attack window", () => {
    // THE load-bearing property of the privilege-escalation scenario. It is
    // anomalous only because this principal has never touched IAM. If a future
    // edit gives her a routine IAM action, the scenario stops being detectable
    // and the evaluation reports what looks like a model failure but is really
    // a change to the data. Failing here instead makes that unmistakable.
    const attacks = attackEventIds();

    const iamOutsideAttack = eventsFor("alice-analyst").filter(
      (event) =>
        event.eventSource === "iam.amazonaws.com" && !attacks.has(event.eventID),
    );

    assert.deepEqual(iamOutsideAttack, []);
  });

  test("CONTROL: dave performs IAM writes as routine work", () => {
    // The false-positive baseline for the sensitive-action feature. Dave does
    // exactly what the escalation scenario does, all month, legitimately — so a
    // detector that keys on the action name alone flags him constantly and gets
    // switched off long before it sees a real escalation.
    const writes = eventsFor("dave-admin").filter(
      (event) => event.eventSource === "iam.amazonaws.com" && !event.readOnly,
    );

    assert.ok(
      writes.length > 100,
      `expected routine IAM writes from the admin control, got ${writes.length}`,
    );
    // And they must be spread across the month, not clustered like an attack.
    const days = new Set(writes.map((event) => event.eventTime.slice(0, 10)));
    assert.ok(days.size >= 15, `IAM writes only on ${days.size} days — too clustered`);
  });

  test("CONTROL: the backup role is active at every hour of the day", () => {
    // The false-positive baseline for the off-hours feature. Automation at 3am
    // is normal, and a detector that has learned "night-time equals suspicious"
    // reports this role every single night.
    const hours = new Set(
      eventsFor("cloudsentinel-backup-service").map((event) =>
        new Date(event.eventTime).getUTCHours(),
      ),
    );

    assert.equal(hours.size, 24);
  });

  test("CONTROL: the backup role's nightly batch recurs every night", () => {
    // The false-positive baseline for the volume feature. This spike is large,
    // but it is *predictable* — the same hour every night — which is exactly
    // what distinguishes it from the exfiltration burst.
    const batchDays = new Set(
      eventsFor("cloudsentinel-backup-service")
        .filter((event) => new Date(event.eventTime).getUTCHours() === 2)
        .map((event) => event.eventTime.slice(0, 10)),
    );

    assert.ok(
      batchDays.size >= 28,
      `the nightly batch ran on only ${batchDays.size} of 30 nights`,
    );
  });

  test("humans are far less active outside their working hours", () => {
    const carol = profileFor("carol-finance");
    const attacks = attackEventIds();

    let inHours = 0;
    let outOfHours = 0;

    for (const event of eventsFor("carol-finance")) {
      if (attacks.has(event.eventID)) continue;
      const localHour =
        (new Date(event.eventTime).getUTCHours() + carol.utcOffsetHours + 24) % 24;
      if (
        localHour >= carol.workStartHourLocal &&
        localHour <= carol.workEndHourLocal
      ) {
        inHours += 1;
      } else {
        outOfHours += 1;
      }
    }

    assert.ok(inHours > outOfHours * 5, `too much off-hours noise: ${inHours} vs ${outOfHours}`);
    // But not zero — a perfectly clean baseline would flatter the detector.
    assert.ok(outOfHours > 0, "the baseline has no off-hours noise at all");
  });

  test("there is a low but non-zero background error rate", () => {
    // Same reasoning: if normal traffic never failed, the credential-abuse
    // scenario would be detectable with a single `if` and the model would be
    // taking credit for a one-line rule.
    const attacks = attackEventIds();
    const normal = DEFAULT_RUN.log.events.filter((e) => !attacks.has(e.eventID));
    const failed = normal.filter((event) => event.errorCode).length;
    const rate = failed / normal.length;

    assert.ok(rate > 0.002, `background error rate too low: ${rate}`);
    assert.ok(rate < 0.05, `background error rate too high: ${rate}`);
  });

  test("failed events carry both an error code and a message", () => {
    for (const event of DEFAULT_RUN.log.events) {
      if (event.errorCode !== undefined) {
        assert.equal(typeof event.errorMessage, "string");
      } else {
        assert.equal(event.errorMessage, undefined);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

describe("generateActivity — validation", () => {
  test("rejects a window shorter than one day", () => {
    assert.throws(() => generateActivity({ days: 0 }), RangeError);
  });

  test("rejects an empty principal list", () => {
    assert.throws(() => generateActivity({ principals: [] }), RangeError);
  });

  test("rejects an unparseable start time", () => {
    assert.throws(() => generateActivity({ startTime: "not-a-date" }), RangeError);
  });

  test("explains itself when a custom roster omits an attack victim", () => {
    // Silently skipping the scenario would be worse: the evaluation would
    // report a recall miss with no indication that the attack was never
    // injected in the first place.
    assert.throws(
      () =>
        generateActivity({
          principals: DEFAULT_PRINCIPALS.filter((p) => !p.arn.endsWith("alice-analyst")),
        }),
      /alice-analyst/,
    );
  });

  test("a custom roster works when attacks are disabled", () => {
    const run = generateActivity({
      days: 3,
      injectAttacks: false,
      principals: [profileFor("dave-admin")],
    });

    assert.equal(run.log.metadata.principalCount, 1);
    assert.ok(run.log.events.length > 0);
  });
});
