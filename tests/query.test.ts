import assert from "node:assert/strict";
import test from "node:test";
import {
	compareErrors,
	filterErrors,
	normalizeExclusions,
	parseSince,
	recoveryHint,
	selectFingerprint,
	selectNewErrors,
	validateFingerprint,
} from "../src/query.ts";
import type { SessionError } from "../src/scanner.ts";

function error(overrides: Partial<SessionError> = {}): SessionError {
	return {
		fingerprint: "aaaaaaaaaaaa",
		kind: "tool",
		source: "bash",
		message: "Command exited with code 1",
		timestamp: "2026-07-16T12:00:00.000Z",
		sessionId: "session-a",
		project: "pi",
		originId: "origin",
		...overrides,
	};
}

test("filters by kind, source, project, time, and exclusions", () => {
	const errors = [
		error(),
		error({ fingerprint: "bbbbbbbbbbbb", kind: "model", source: "openai/model", message: "rate limit 429", project: "other", timestamp: "2026-07-10T00:00:00.000Z" }),
	];
	const now = Date.parse("2026-07-16T13:00:00.000Z");
	assert.deepEqual(filterErrors(errors, { kind: "tool", source: "BASH", project: "PI", since: "2h" }, now), [errors[0]]);
	assert.deepEqual(filterErrors(errors, { exclude: "model,rate limit" }, now), [errors[0]]);
	assert.throws(() => filterErrors(errors, { kind: "unknown" }), /kind must be/);
});

test("parses bounded relative and ISO since values", () => {
	const now = Date.parse("2026-07-16T12:00:00.000Z");
	assert.equal(parseSince("24h", now), now - 86_400_000);
	assert.equal(parseSince("2026-07-01T00:00:00Z", now), Date.parse("2026-07-01T00:00:00Z"));
	assert.throws(() => parseSince("forever", now), /ISO timestamp/);
	assert.throws(() => parseSince("999w", now), /366 days/);
});

test("normalizes bounded per-request exclusions", () => {
	assert.deepEqual(normalizeExclusions([" model, rate-limit ", "MODEL"]), ["model", "rate-limit"]);
	assert.throws(() => normalizeExclusions(Array.from({ length: 21 }, (_, index) => `x${index}`)), /at most 20/);
});

test("validates and selects exact fingerprints", () => {
	const errors = [error(), error({ fingerprint: "bbbbbbbbbbbb" })];
	assert.equal(validateFingerprint("aaaaaaaaaaaa"), "aaaaaaaaaaaa");
	assert.throws(() => validateFingerprint("AAAAAAAAAAAA"), /12 hexadecimal/);
	assert.deepEqual(selectFingerprint(errors, "bbbbbbbbbbbb"), [errors[1]]);
	assert.throws(() => validateFingerprint("abc"), /12 hexadecimal/);
	assert.throws(() => parseSince("July 16, 2026"), /ISO timestamp/);
	assert.throws(() => parseSince("2026-02-30T00:00:00Z"), /invalid ISO/);
});

test("computes new and comparison sets without persistent state", () => {
	const current = [error(), error({ fingerprint: "bbbbbbbbbbbb" })];
	const historical = [error({ fingerprint: "bbbbbbbbbbbb" }), error({ fingerprint: "cccccccccccc" })];
	assert.deepEqual(selectNewErrors(current, historical), [current[0]]);
	assert.deepEqual(compareErrors(current, historical), {
		currentErrors: 2,
		historicalErrors: 2,
		currentUnique: 2,
		historicalUnique: 2,
		currentOnly: ["aaaaaaaaaaaa"],
		recurring: ["bbbbbbbbbbbb"],
		historicalOnly: ["cccccccccccc"],
	});
});

test("returns deterministic recovery hints", () => {
	assert.equal(recoveryHint(error({ message: "ENOENT: no such file or directory" }))?.code, "missing-path");
	assert.equal(recoveryHint(error({ message: "WorkGuard blocked: search-output-budget" }))?.code, "workguard-bound");
	assert.equal(recoveryHint(error({ message: "Path is outside authorized FFF roots" }))?.code, "fff-root");
	assert.equal(recoveryHint(error({ kind: "model", message: "429 rate limit" }))?.code, "rate-limit");
	assert.equal(recoveryHint(error({ message: "unclassified failure" })), null);
});
