import assert from "node:assert/strict";
import test from "node:test";
import { formatComparisonReport, formatErrorReport } from "../src/format.ts";
import { compareErrors } from "../src/query.ts";
import type { ScanResult, SessionError } from "../src/scanner.ts";

function error(fingerprint: string, message: string): SessionError {
	return {
		fingerprint,
		kind: "tool",
		source: "bash",
		message,
		timestamp: "2026-07-16T12:00:00.000Z",
		sessionId: "session",
		project: "pi",
		originId: "origin",
	};
}

function scan(errors: SessionError[]): ScanResult {
	return {
		errors,
		stats: {
			filesConsidered: 2,
			filesScanned: 2,
			filesSkipped: 0,
			malformedLines: 0,
			oversizedLines: 0,
			bytesRead: 100,
			truncated: false,
		},
	};
}

test("formats deterministic hints in regular reports", () => {
	const report = formatErrorReport(scan([error("aaaaaaaaaaaa", "ENOENT: no such file or directory")]), "summary", 10, "Filtered errors");
	assert.match(report, /^Filtered errors:/);
	assert.match(report, /hint \[missing-path\]/);
});

test("formats bounded current-vs-history comparison sections", () => {
	const current = [error("aaaaaaaaaaaa", "new failure"), error("bbbbbbbbbbbb", "recurring")];
	const historical = [error("bbbbbbbbbbbb", "recurring"), error("cccccccccccc", "old")];
	const report = formatComparisonReport(scan([...current, ...historical]), current, historical, compareErrors(current, historical), 10);
	assert.match(report, /New: 1 · Recurring: 1 · Historical-only: 1/);
	assert.match(report, /fp:aaaaaaaaaaaa/);
	assert.match(report, /fp:bbbbbbbbbbbb/);
	assert.match(report, /fp:cccccccccccc/);
});
