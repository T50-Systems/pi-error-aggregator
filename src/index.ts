import os from "node:os";
import {
	SessionManager,
	truncateHead,
	type ExtensionAPI,
} from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import {
	compareErrors,
	filterErrors,
	selectFingerprint,
	selectNewErrors,
	type DiagnosticFilters,
} from "./query.js";
import {
	formatComparisonReport,
	formatErrorReport,
	type ReportMode,
} from "./format.js";
import { scanSessionFiles, sessionOriginId, type ScanResult } from "./scanner.js";

const DEFAULT_LIMIT = 20;
const MAX_OUTPUT_LINES = 240;
const MAX_OUTPUT_BYTES = 48 * 1024;

type ReportScope = "all" | "current";
type DiagnosticAction = "report" | "new" | "show" | "compare";

export interface ParsedCommand {
	action: DiagnosticAction;
	scope: ReportScope;
	mode: ReportMode;
	limit: number;
	fingerprint?: string;
	filters: DiagnosticFilters;
}

function parseMode(value: string | undefined): ReportMode {
	const normalized = value?.trim().toLowerCase();
	if (!normalized || normalized === "summary") return "summary";
	if (normalized === "list" || normalized === "timeline") return "timeline";
	if (normalized === "both") return "both";
	throw new Error("Mode must be summary, timeline/list, or both");
}

function parseScope(value: string | undefined): ReportScope | null {
	const normalized = value?.trim().toLowerCase();
	if (normalized === "all") return "all";
	if (normalized === "current" || normalized === "session") return "current";
	return null;
}

function parseAction(value: string | undefined): DiagnosticAction | null {
	const normalized = value?.trim().toLowerCase();
	return normalized === "report" || normalized === "new" || normalized === "show" || normalized === "compare"
		? normalized
		: null;
}

function parseLimit(value: string | undefined): number {
	if (!value) return DEFAULT_LIMIT;
	const limit = Number.parseInt(value, 10);
	if (!/^\d+$/.test(value) || !Number.isInteger(limit) || limit < 1 || limit > 100) {
		throw new Error("Limit must be an integer from 1 to 100");
	}
	return limit;
}

function splitFlags(tokens: string[]): { positionals: string[]; filters: DiagnosticFilters } {
	const positionals: string[] = [];
	const filters: DiagnosticFilters = {};
	const exclusions: string[] = [];
	const supported = new Set(["kind", "source", "project", "since", "exclude"]);
	for (let index = 0; index < tokens.length; index++) {
		const token = tokens[index]!;
		if (!token.startsWith("--")) {
			positionals.push(token);
			continue;
		}
		const equals = token.indexOf("=");
		const name = token.slice(2, equals === -1 ? undefined : equals).toLowerCase();
		if (!supported.has(name)) throw new Error(`Unknown filter: --${name}`);
		const value = equals === -1 ? tokens[++index] : token.slice(equals + 1);
		if (!value || value.startsWith("--")) throw new Error(`--${name} requires a value`);
		if (name === "exclude") exclusions.push(value);
		else if (name === "kind") filters.kind = value;
		else if (name === "source") filters.source = value;
		else if (name === "project") filters.project = value;
		else if (name === "since") filters.since = value;
	}
	if (exclusions.length) filters.exclude = exclusions;
	return { positionals, filters };
}

export function parseCommandArgs(args: string | undefined): ParsedCommand {
	const tokens = (args ?? "").trim().split(/\s+/).filter(Boolean);
	const { positionals, filters } = splitFlags(tokens);
	const explicitAction = parseAction(positionals[0]);
	const action = explicitAction ?? "report";
	if (explicitAction) positionals.shift();

	if (action === "report") {
		const explicitScope = parseScope(positionals[0]);
		const scope = explicitScope ?? "all";
		if (explicitScope) positionals.shift();
		const mode = parseMode(positionals.shift());
		const limit = parseLimit(positionals.shift());
		if (positionals.length) throw new Error("Usage: /errors [all|current] [summary|list|both] [limit] [filters]");
		return { action, scope, mode, limit, filters };
	}

	if (action === "show") {
		const fingerprint = positionals.shift();
		if (!fingerprint) throw new Error("Usage: /errors show <fingerprint> [all|current] [limit] [filters]");
		const explicitScope = parseScope(positionals[0]);
		const scope = explicitScope ?? "all";
		if (explicitScope) positionals.shift();
		const limit = parseLimit(positionals.shift());
		if (positionals.length) throw new Error("Usage: /errors show <fingerprint> [all|current] [limit] [filters]");
		return { action, scope, mode: "timeline", limit, fingerprint, filters };
	}

	const limit = parseLimit(positionals.shift());
	if (positionals.length) throw new Error(`Usage: /errors ${action} [limit] [filters]`);
	return { action, scope: "current", mode: "summary", limit, filters };
}

export function boundedOutput(formatted: string): { text: string; truncated: boolean } {
	const result = truncateHead(formatted, {
		maxLines: MAX_OUTPUT_LINES - 2,
		maxBytes: MAX_OUTPUT_BYTES - 256,
	});
	const suffix = result.truncated
		? `\n\n[Report output truncated to ${result.outputLines} lines / ${result.outputBytes} bytes. Narrow the action, filters, or limit.]`
		: "";
	return { text: result.content + suffix, truncated: result.truncated };
}

function withErrors(scan: ScanResult, errors: ScanResult["errors"]): ScanResult {
	return { ...scan, errors };
}

async function buildReport(
	query: ParsedCommand,
	currentSessionFile?: string,
	signal?: AbortSignal,
): Promise<{ text: string; details: Record<string, unknown> }> {
	const requiresCurrent = query.scope === "current" || query.action === "new" || query.action === "compare";
	if (requiresCurrent && !currentSessionFile) {
		throw new Error("The current session is not persisted; this action requires a session file");
	}
	const requiresAll = query.scope === "all" || query.action === "new" || query.action === "compare";
	let files: string[];
	if (requiresAll) {
		const sessions = await SessionManager.listAll();
		if (signal?.aborted) throw new Error("Operation aborted");
		files = sessions.map((session) => session.path);
	} else {
		files = [currentSessionFile!];
	}

	const scan = await scanSessionFiles(files, { homeDir: os.homedir(), signal });
	const currentOrigin = currentSessionFile ? sessionOriginId(currentSessionFile) : undefined;
	const currentRaw = requiresAll
		? scan.errors.filter((error) => error.originId === currentOrigin)
		: scan.errors;
	const historicalRaw = requiresAll
		? scan.errors.filter((error) => error.originId !== currentOrigin)
		: [];
	const selectedRaw = query.scope === "current" ? currentRaw : scan.errors;
	const selected = filterErrors(selectedRaw, query.filters);
	const current = filterErrors(currentRaw, query.filters);
	const historical = filterErrors(historicalRaw, query.filters);

	let formatted: string;
	if (query.action === "new") {
		const newErrors = selectNewErrors(current, historical);
		formatted = formatErrorReport(withErrors(scan, newErrors), query.mode, query.limit, "New errors in current session");
	} else if (query.action === "show") {
		const matches = selectFingerprint(selected, query.fingerprint ?? "");
		formatted = formatErrorReport(withErrors(scan, matches), "timeline", query.limit, `Fingerprint ${query.fingerprint?.toLowerCase()}`);
	} else if (query.action === "compare") {
		const comparison = compareErrors(current, historical);
		formatted = formatComparisonReport(withErrors(scan, [...current, ...historical]), current, historical, comparison, query.limit);
	} else {
		formatted = formatErrorReport(withErrors(scan, selected), query.mode, query.limit, query.scope === "current" ? "Current session errors" : "Pi session errors");
	}

	const output = boundedOutput(formatted);
	return {
		text: output.text,
		details: {
			action: query.action,
			scope: query.scope,
			errorCount: selected.length,
			filesScanned: scan.stats.filesScanned,
			filesConsidered: scan.stats.filesConsidered,
			filesSkipped: scan.stats.filesSkipped,
			malformedLines: scan.stats.malformedLines,
			oversizedLines: scan.stats.oversizedLines,
			scanTruncated: scan.stats.truncated,
			outputTruncated: output.truncated,
		},
	};
}

export default function errorAggregatorExtension(pi: ExtensionAPI) {
	pi.registerTool({
		name: "session_errors",
		label: "Session Errors",
		description: "Scan the current persisted Pi session or all sessions and return bounded redacted diagnostics. Supports report, new, show, and compare actions plus kind/source/project/time filters and per-request exclusions. Creates no aggregate database.",
		promptSnippet: "Aggregate and diagnose redacted errors across persisted Pi sessions",
		promptGuidelines: [
			"Use session_errors summary/report first; use new or compare for current-vs-history diagnosis and show for an exact fingerprint.",
		],
		parameters: Type.Object({
			action: Type.Optional(Type.String({ description: "report, new, show, or compare (default: report)" })),
			scope: Type.Optional(Type.String({ description: "current/session or all (default: all for report/show)" })),
			mode: Type.Optional(Type.String({ description: "summary, timeline, list, or both (default: summary)" })),
			limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 100, description: "Maximum groups/events per view (default: 20)" })),
			fingerprint: Type.Optional(Type.String({ description: "Exact 12-hex fingerprint required by show" })),
			kind: Type.Optional(Type.String({ description: "tool, model, bash, subagent, or extension" })),
			source: Type.Optional(Type.String({ description: "Case-insensitive source/tool substring" })),
			project: Type.Optional(Type.String({ description: "Case-insensitive project substring" })),
			since: Type.Optional(Type.String({ description: "ISO timestamp or relative duration such as 24h, 7d, or 2w" })),
			exclude: Type.Optional(Type.String({ description: "Comma-separated per-request noise tokens" })),
		}),
		async execute(_toolCallId, params, signal, _onUpdate, ctx) {
			if (signal?.aborted) throw new Error("Operation aborted");
			const action = parseAction(params.action) ?? (params.action ? null : "report");
			if (!action) throw new Error("Action must be report, new, show, or compare");
			const scope = parseScope(params.scope) ?? (params.scope ? null : action === "new" || action === "compare" ? "current" : "all");
			if (!scope) throw new Error("Scope must be current/session or all");
			const query: ParsedCommand = {
				action,
				scope,
				mode: parseMode(params.mode),
				limit: params.limit ?? DEFAULT_LIMIT,
				fingerprint: params.fingerprint,
				filters: {
					kind: params.kind,
					source: params.source,
					project: params.project,
					since: params.since,
					exclude: params.exclude,
				},
			};
			const report = await buildReport(
				query,
				ctx.sessionManager.getSessionFile(),
				signal,
			);
			return { content: [{ type: "text", text: report.text }], details: report.details };
		},
	});

	pi.registerCommand("errors", {
		description: "Diagnostics: /errors [all|current] ... | new | show <fp> | compare; filters: --kind/--source/--project/--since/--exclude",
		handler: async (args, ctx) => {
			try {
				const query = parseCommandArgs(args);
				ctx.ui.setStatus("pi-error-aggregator", "Scanning session errors…");
				const report = await buildReport(
					query,
					ctx.sessionManager.getSessionFile(),
					ctx.signal,
				);
				ctx.ui.notify(report.text, "info");
			} catch (error) {
				ctx.ui.notify(error instanceof Error ? error.message : String(error), "error");
			} finally {
				ctx.ui.setStatus("pi-error-aggregator", undefined);
			}
		},
	});
}
