/**
 * CloudSentinel — tests for the dashboard formatting helpers.
 *
 * Run with `npm test`. Pure functions, no DOM and no database.
 *
 * Most of this file is about `formatAge`, because it is the one helper with
 * real branching and because the number it produces is load-bearing: "open 23
 * days" beside a critical finding is the sentence that makes someone act. An
 * off-by-one in a boundary would misreport that, and nothing else in the suite
 * would notice.
 *
 * The timestamp helpers are asserted against fixed dates rather than `Date.now()`
 * so the suite cannot pass or fail depending on when it runs.
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  formatAbsolute,
  formatAge,
  formatDate,
  resourceTypeLabel,
  riskScoreColour,
  severityBadge,
  severityFill,
} from "./format.ts";

/** Fixed reference point for every age assertion. */
const NOW = new Date("2026-08-26T12:00:00.000Z");

/** Builds a date a given number of seconds before {@link NOW}. */
function ago(seconds: number): Date {
  return new Date(NOW.getTime() - seconds * 1000);
}

describe("formatAbsolute", () => {
  test("renders UTC to the minute", () => {
    // UTC and labelled as such: a findings report is evidence about when
    // something was observed, and a timestamp that shifts with the reader's
    // timezone is a poor basis for "public from the 4th to the 11th".
    assert.equal(
      formatAbsolute(new Date("2026-08-04T09:07:33.000Z")),
      "2026-08-04 09:07 UTC",
    );
  });

  test("accepts an ISO string as well as a Date", () => {
    assert.equal(
      formatAbsolute("2026-08-04T09:07:33.000Z"),
      "2026-08-04 09:07 UTC",
    );
  });
});

describe("formatDate", () => {
  test("renders the date only", () => {
    assert.equal(formatDate(new Date("2026-08-04T23:59:00.000Z")), "2026-08-04");
  });
});

describe("formatAge", () => {
  test("handles the sub-minute case", () => {
    assert.equal(formatAge(ago(0), NOW), "just now");
    assert.equal(formatAge(ago(59), NOW), "just now");
  });

  test("crosses each boundary correctly", () => {
    assert.equal(formatAge(ago(60), NOW), "1 min");
    assert.equal(formatAge(ago(59 * 60), NOW), "59 min");
    assert.equal(formatAge(ago(60 * 60), NOW), "1 hr");
    assert.equal(formatAge(ago(2 * 60 * 60), NOW), "2 hrs");
    assert.equal(formatAge(ago(23 * 60 * 60), NOW), "23 hrs");
    assert.equal(formatAge(ago(24 * 60 * 60), NOW), "1 day");
    assert.equal(formatAge(ago(2 * 24 * 60 * 60), NOW), "2 days");
    assert.equal(formatAge(ago(30 * 24 * 60 * 60), NOW), "30 days");
  });

  test("switches to months and years for long-standing findings", () => {
    assert.equal(formatAge(ago(31 * 24 * 60 * 60), NOW), "1 mo");
    assert.equal(formatAge(ago(200 * 24 * 60 * 60), NOW), "6 mo");
    assert.equal(formatAge(ago(400 * 24 * 60 * 60), NOW), "1 yr");
  });

  test("singularises correctly", () => {
    assert.equal(formatAge(ago(60 * 60), NOW), "1 hr");
    assert.equal(formatAge(ago(24 * 60 * 60), NOW), "1 day");
  });

  test("clamps a future date to 'just now' rather than going negative", () => {
    // Clock skew between the database and the web process is possible, and
    // "open -3 days" is worse than a harmless rounding to the present.
    assert.equal(formatAge(new Date(NOW.getTime() + 60_000), NOW), "just now");
  });
});

describe("severity styling", () => {
  test("gives each severity a distinct badge and fill", () => {
    // Distinctness is the requirement: severity is judged at a glance across a
    // long list, and two severities sharing a colour makes that impossible.
    const badges = ["critical", "high", "medium", "low"].map(severityBadge);
    assert.equal(new Set(badges).size, 4);

    const fills = ["critical", "high", "medium", "low"].map(severityFill);
    assert.equal(new Set(fills).size, 4);
  });

  test("falls back rather than returning undefined for an unknown severity", () => {
    // A severity that somehow reaches the UI unrecognised must still render.
    assert.equal(severityBadge("nonsense"), severityBadge("low"));
    assert.equal(severityFill("nonsense"), severityFill("low"));
  });
});

describe("riskScoreColour", () => {
  test("is red at and above 70", () => {
    // One critical finding contributes 40 points, so a scale that only turned
    // red near 90 would show a comfortable colour for an account with a
    // world-readable bucket in it.
    assert.match(riskScoreColour(100), /red/);
    assert.match(riskScoreColour(87), /red/);
    assert.match(riskScoreColour(70), /red/);
  });

  test("steps down through the bands", () => {
    assert.match(riskScoreColour(69), /orange/);
    assert.match(riskScoreColour(40), /orange/);
    assert.match(riskScoreColour(39), /yellow/);
    assert.match(riskScoreColour(15), /yellow/);
    assert.match(riskScoreColour(14), /emerald/);
    assert.match(riskScoreColour(0), /emerald/);
  });
});

describe("resourceTypeLabel", () => {
  test("renders the three collected types readably", () => {
    assert.equal(resourceTypeLabel("s3_bucket"), "S3 bucket");
    assert.equal(resourceTypeLabel("security_group"), "Security group");
    assert.equal(resourceTypeLabel("iam_user"), "IAM user");
  });

  test("falls back to the raw value for anything else", () => {
    // A new collector should show something imperfect rather than nothing.
    assert.equal(resourceTypeLabel("rds_instance"), "rds_instance");
  });
});
