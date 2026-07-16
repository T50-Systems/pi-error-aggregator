import { recoveryHint, type DiagnosticComparison } from "./query.js";
import type { ScanResult, SessionError } from "./scanner.js";

export type ReportMode = "summary" | "timeline" | "both";

export interface ErrorGroup {
	fingerprint: string;
	kind: SessionError["kind"];
	source: string;
	message: string;
	count: number;
	latest: string;
	sessions: Set<string>;
	projects: Set<string>;
}

function heading(scan: ScanResult, title = "Pi session errors"): string {
	const { stats } = scan;
	const warning = stats.truncated ? " · LIMIT REACHED" : "";
	return `${title}: ${scan.errors.length} errors · ${stats.filesScanned}/${stats.filesConsidered} sessions scanned · ${stats.malformedLines} malformed / ${stats.oversizedLines} oversized lines${warning}`;
}

export function groupErrors(errors: SessionError[]): ErrorGroup[] {
	const groups = new Map<string, ErrorGroup>();
	for (const error of errors) {
		const existing = groups.get(error.fingerprint);
		if (existing) {
			existing.count++;
			if (error.timestamp > existing.latest) {
				existing.latest = error.timestamp;
				existing.message = error.message;
			}
			existing.sessions.add(error.sessionId);
			existing.projects.add(error.project);
			continue;
		}
		groups.set(error.fingerprint, {
			fingerprint: error.fingerprint,
			kind: error.kind,
			source: error.source,
			message: error.message,
			count: 1,
			latest: error.timestamp,
			sessions: new Set([error.sessionId]),
			projects: new Set([error.project]),
		});
	}
	return [...groups.values()].sort((a, b) => b.count - a.count || b.latest.localeCompare(a.latest));
}

function shortDate(value: string): string {
	return value === new Date(0).toISOString() ? "unknown-time" : value.replace("T", " ").replace(/\.\d{3}Z$/, "Z");
}

export function formatErrorReport(scan: ScanResult, mode: ReportMode = "summary", limit = 20, title = "Pi session errors"): string {
	const safeLimit = Math.max(1, Math.min(100, Math.floor(limit)));
	const output: string[] = [heading(scan, title)];
	if (scan.errors.length === 0) return `${output[0]}\nNo detectable errors found.`;

	if (mode === "summary" || mode === "both") {
		const groups = groupErrors(scan.errors);
		output.push("", `Summary (${Math.min(safeLimit, groups.length)}/${groups.length} groups):`);
		for (const [index, group] of groups.slice(0, safeLimit).entries()) {
			const projects = [...group.projects].slice(0, 4).join(", ");
			output.push(
				`${index + 1}. [${group.count}×] ${group.kind}/${group.source} — ${group.message}`,
				`   latest ${shortDate(group.latest)} · ${group.sessions.size} session(s) · ${projects} · fp:${group.fingerprint}`,
			);
			const hint = recoveryHint(group);
			if (hint) output.push(`   hint [${hint.code}]: ${hint.text}`);
		}
	}

	if (mode === "timeline" || mode === "both") {
		const timeline = [...scan.errors].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
		output.push("", `Timeline (${Math.min(safeLimit, timeline.length)}/${timeline.length} events):`);
		for (const error of timeline.slice(0, safeLimit)) {
			output.push(
				`- ${shortDate(error.timestamp)} · ${error.kind}/${error.source} · ${error.project}/${error.sessionId.slice(0, 8)} · ${error.message}`,
			);
			const hint = recoveryHint(error);
			if (hint) output.push(`  hint [${hint.code}]: ${hint.text}`);
		}
	}

	if (scan.stats.filesSkipped > 0) output.push("", `Skipped session files: ${scan.stats.filesSkipped}`);
	return output.join("\n");
}

export function formatComparisonReport(
	scan: ScanResult,
	current: SessionError[],
	historical: SessionError[],
	comparison: DiagnosticComparison,
	limit = 20,
): string {
	const safeLimit = Math.max(1, Math.min(100, Math.floor(limit)));
	const currentGroups = new Map(groupErrors(current).map((group) => [group.fingerprint, group]));
	const historicalGroups = new Map(groupErrors(historical).map((group) => [group.fingerprint, group]));
	const output = [
		heading(scan, "Pi current vs history"),
		`Current: ${comparison.currentErrors} errors / ${comparison.currentUnique} groups`,
		`History: ${comparison.historicalErrors} errors / ${comparison.historicalUnique} groups`,
		`New: ${comparison.currentOnly.length} · Recurring: ${comparison.recurring.length} · Historical-only: ${comparison.historicalOnly.length}`,
	];
	const sections: Array<[string, string[], Map<string, ErrorGroup>]> = [
		["New in current session", comparison.currentOnly, currentGroups],
		["Recurring in current session", comparison.recurring, currentGroups],
		["Historical-only", comparison.historicalOnly, historicalGroups],
	];
	for (const [label, fingerprints, groups] of sections) {
		output.push("", `${label} (${Math.min(safeLimit, fingerprints.length)}/${fingerprints.length}):`);
		for (const fingerprint of fingerprints.slice(0, safeLimit)) {
			const group = groups.get(fingerprint);
			if (!group) continue;
			output.push(`- ${group.kind}/${group.source} · fp:${fingerprint} · ${group.message}`);
			const hint = recoveryHint(group);
			if (hint) output.push(`  hint [${hint.code}]: ${hint.text}`);
		}
	}
	return output.join("\n");
}
