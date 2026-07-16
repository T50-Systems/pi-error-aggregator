import type { ErrorKind, SessionError } from "./scanner.js";

const ERROR_KINDS = new Set<ErrorKind>(["tool", "model", "bash", "subagent", "extension"]);
const MAX_FILTER_LENGTH = 120;
const MAX_EXCLUSIONS = 20;
const FINGERPRINT_PATTERN = /^[0-9a-f]{12}$/;
const ISO_TIMESTAMP_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?(Z|([+-])(\d{2}):(\d{2}))$/;

export interface DiagnosticFilters {
	kind?: string;
	source?: string;
	project?: string;
	since?: string;
	exclude?: string | string[];
}

export interface RecoveryHint {
	code: string;
	text: string;
}

export interface DiagnosticComparison {
	currentErrors: number;
	historicalErrors: number;
	currentUnique: number;
	historicalUnique: number;
	currentOnly: string[];
	recurring: string[];
	historicalOnly: string[];
}

function bounded(value: string | undefined, name: string): string | undefined {
	const normalized = value?.trim();
	if (!normalized) return undefined;
	if (normalized.length > MAX_FILTER_LENGTH) {
		throw new Error(`${name} must be at most ${MAX_FILTER_LENGTH} characters`);
	}
	return normalized;
}

export function parseSince(value: string | undefined, now = Date.now()): number | undefined {
	const normalized = bounded(value, "since");
	if (!normalized) return undefined;
	const relative = normalized.match(/^(\d+)(m|h|d|w)$/i);
	if (relative) {
		const amount = Number.parseInt(relative[1]!, 10);
		const unit = relative[2]!.toLowerCase();
		const multiplier = unit === "m" ? 60_000 : unit === "h" ? 3_600_000 : unit === "d" ? 86_400_000 : 604_800_000;
		const duration = amount * multiplier;
		if (!Number.isSafeInteger(duration) || duration <= 0 || duration > 366 * 86_400_000) {
			throw new Error("since relative duration must be between 1 minute and 366 days");
		}
		return now - duration;
	}
	const iso = normalized.match(ISO_TIMESTAMP_PATTERN);
	if (!iso) {
		throw new Error("since must be an ISO timestamp or a relative duration such as 24h, 7d, or 2w");
	}
	const [year, month, day, hour, minute, second] = iso.slice(1, 7).map((part) => Number.parseInt(part || "0", 10));
	const calendar = new Date(Date.UTC(year!, month! - 1, day!));
	const invalidCalendar =
		calendar.getUTCFullYear() !== year ||
		calendar.getUTCMonth() !== month! - 1 ||
		calendar.getUTCDate() !== day;
	const offsetHour = iso[10] ? Number.parseInt(iso[10], 10) : 0;
	const offsetMinute = iso[11] ? Number.parseInt(iso[11], 10) : 0;
	if (invalidCalendar || hour! > 23 || minute! > 59 || second! > 59 || offsetHour > 23 || offsetMinute > 59) {
		throw new Error("since contains an invalid ISO timestamp");
	}
	const timestamp = Date.parse(normalized);
	if (Number.isNaN(timestamp)) throw new Error("since contains an invalid ISO timestamp");
	return timestamp;
}

export function normalizeExclusions(value: string | string[] | undefined): string[] {
	if (!value) return [];
	const raw = Array.isArray(value) ? value : [value];
	const tokens = raw
		.flatMap((item) => item.split(","))
		.map((item) => bounded(item, "exclude"))
		.filter((item): item is string => Boolean(item));
	if (tokens.length > MAX_EXCLUSIONS) throw new Error(`exclude accepts at most ${MAX_EXCLUSIONS} tokens`);
	return [...new Set(tokens.map((item) => item.toLowerCase()))];
}

export function filterErrors(errors: SessionError[], filters: DiagnosticFilters = {}, now = Date.now()): SessionError[] {
	const kindValue = bounded(filters.kind, "kind")?.toLowerCase();
	if (kindValue && !ERROR_KINDS.has(kindValue as ErrorKind)) {
		throw new Error(`kind must be one of: ${[...ERROR_KINDS].join(", ")}`);
	}
	const source = bounded(filters.source, "source")?.toLowerCase();
	const project = bounded(filters.project, "project")?.toLowerCase();
	const since = parseSince(filters.since, now);
	const exclusions = normalizeExclusions(filters.exclude);

	return errors.filter((error) => {
		if (kindValue && error.kind !== kindValue) return false;
		if (source && !error.source.toLowerCase().includes(source)) return false;
		if (project && !error.project.toLowerCase().includes(project)) return false;
		if (since !== undefined) {
			const timestamp = Date.parse(error.timestamp);
			if (Number.isNaN(timestamp) || timestamp < since) return false;
		}
		if (exclusions.length) {
			const searchable = `${error.kind}\n${error.source}\n${error.message}`.toLowerCase();
			if (exclusions.some((token) => searchable.includes(token))) return false;
		}
		return true;
	});
}

export function validateFingerprint(value: string | undefined): string {
	const normalized = value?.trim();
	if (!normalized || !FINGERPRINT_PATTERN.test(normalized)) {
		throw new Error("fingerprint must be exactly 12 hexadecimal characters");
	}
	return normalized;
}

export function selectFingerprint(errors: SessionError[], fingerprint: string): SessionError[] {
	const valid = validateFingerprint(fingerprint);
	return errors.filter((error) => error.fingerprint === valid);
}

export function selectNewErrors(current: SessionError[], historical: SessionError[]): SessionError[] {
	const historicalFingerprints = new Set(historical.map((error) => error.fingerprint));
	return current.filter((error) => !historicalFingerprints.has(error.fingerprint));
}

export function compareErrors(current: SessionError[], historical: SessionError[]): DiagnosticComparison {
	const currentSet = new Set(current.map((error) => error.fingerprint));
	const historicalSet = new Set(historical.map((error) => error.fingerprint));
	return {
		currentErrors: current.length,
		historicalErrors: historical.length,
		currentUnique: currentSet.size,
		historicalUnique: historicalSet.size,
		currentOnly: [...currentSet].filter((fingerprint) => !historicalSet.has(fingerprint)).sort(),
		recurring: [...currentSet].filter((fingerprint) => historicalSet.has(fingerprint)).sort(),
		historicalOnly: [...historicalSet].filter((fingerprint) => !currentSet.has(fingerprint)).sort(),
	};
}

export function recoveryHint(error: Pick<SessionError, "kind" | "source" | "message">): RecoveryHint | null {
	const text = `${error.source}\n${error.message}`.toLowerCase();
	if (/usage limit|rate limit|too many requests|\b429\b/.test(text)) {
		return { code: "rate-limit", text: "Wait for quota reset or switch to an available model/provider." };
	}
	if (/\benoent\b|no such file or directory/.test(text)) {
		return { code: "missing-path", text: "Verify the path, working directory, or whether the file was moved." };
	}
	if (/search-output-budget|explicit output bound|workguard blocked/.test(text)) {
		return { code: "workguard-bound", text: "Retry with an explicit result bound such as --max-count, head, or a tool limit." };
	}
	if (/outside (configured|authorized) fff roots|registered git worktree/.test(text)) {
		return { code: "fff-root", text: "Use a registered Git worktree or add only the smallest trusted FFF root." };
	}
	if (/cannot find module|module_not_found|err_module_not_found/.test(text)) {
		return { code: "missing-module", text: "Check package installation and runtime import resolution." };
	}
	if (/command exited with code [1-9]|exit status [1-9]/.test(text)) {
		return { code: "command-exit", text: "Inspect the bounded command output and retry the narrow failing command." };
	}
	return null;
}
