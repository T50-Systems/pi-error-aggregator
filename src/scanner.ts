import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { basename, resolve } from "node:path";

export type ErrorKind = "tool" | "model" | "bash" | "subagent" | "extension";

export interface SessionError {
	fingerprint: string;
	kind: ErrorKind;
	source: string;
	message: string;
	timestamp: string;
	sessionId: string;
	project: string;
	originId: string;
}

export interface ScanOptions {
	maxFiles?: number;
	maxErrors?: number;
	maxTotalBytes?: number;
	homeDir?: string;
	maxLineBytes?: number;
	signal?: AbortSignal;
}

export interface ScanResult {
	errors: SessionError[];
	stats: {
		filesConsidered: number;
		filesScanned: number;
		filesSkipped: number;
		malformedLines: number;
		oversizedLines: number;
		bytesRead: number;
		truncated: boolean;
	};
}

const DEFAULT_MAX_FILES = 10_000;
const DEFAULT_MAX_ERRORS = 10_000;
const DEFAULT_MAX_TOTAL_BYTES = 512 * 1024 * 1024;
const MAX_MESSAGE_CHARS = 800;
const DEFAULT_MAX_LINE_BYTES = 4 * 1024 * 1024;

function record(value: unknown): Record<string, unknown> | null {
	return value !== null && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: null;
}

function text(value: unknown): string {
	if (typeof value === "string") return value;
	if (!Array.isArray(value)) return "";
	return value
		.map((item) => {
			const block = record(item);
			return block?.type === "text" && typeof block.text === "string" ? block.text : "";
		})
		.filter(Boolean)
		.join("\n");
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function redactErrorText(input: string, homeDir = ""): string {
	let output = input
		.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
		.replace(/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/g, " ")
		.replace(/\s+/g, " ")
		.trim();
	if (homeDir) {
		const variants = new Set([homeDir, homeDir.replaceAll("\\", "/"), homeDir.replaceAll("/", "\\")]);
		for (const variant of variants) {
			if (variant) output = output.replace(new RegExp(escapeRegExp(variant), "gi"), "~");
		}
	}
	output = output
		.replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+:[^\s/@]+@/gi, "$1[credentials]@")
		.replace(/(["'])(?:[a-z]:[\\/]|\\\\)[^"']+\1/gi, "$1<path>$1")
		.replace(/(["'])\/[^"']+\1/g, "$1<path>$1")
		.replace(/\b[a-z]:[\\/][^\s"',;]+/gi, "<path>")
		.replace(/(^|\s)\\\\[^\s"',;]+/g, "$1<path>")
		.replace(/(^|[\s(=:])\/(?!\/)[^\s"',;]+/g, "$1<path>")
		.replace(/~[\\/][^\s"',;]+/g, "<home-path>")
		.replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, "$1[REDACTED]")
		.replace(/\b(Basic\s+)[A-Za-z0-9+/_=-]{8,}/gi, "$1[REDACTED]")
		.replace(/\b(sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,}|xox[baprs]-[A-Za-z0-9-]{12,})\b/g, "[REDACTED]")
		.replace(/\b((?:[a-z0-9]+_)*(?:api[_-]?key|secret(?:_access)?_key|access_token|token|password|passwd))\s*[:=]\s*["']?[^\s"',;]{4,}/gi, "$1=[REDACTED]")
		.replace(/\b[A-Za-z0-9+/_-]{80,}={0,2}\b/g, "[REDACTED_BLOB]");
	return output.length > MAX_MESSAGE_CHARS ? `${output.slice(0, MAX_MESSAGE_CHARS)}…` : output;
}

export function normalizeFingerprintText(input: string): string {
	return input
		.toLowerCase()
		.replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/g, "<uuid>")
		.replace(/\b[0-9a-f]{12,}\b/g, "<hash>")
		.replace(/[a-z]:[\\/][^\s"']+/gi, "<path>")
		.replace(/~[\\/][^\s"']+/g, "<path>")
		.replace(/(^|\s)\/(?:[^\s/]+\/)+[^\s"']+/g, "$1<path>")
		.replace(/\b\d+\b/g, "#")
		.replace(/\s+/g, " ")
		.trim();
}

function fingerprint(kind: ErrorKind, source: string, message: string): string {
	return createHash("sha256")
		.update(`${kind}\0${source.toLowerCase()}\0${normalizeFingerprintText(message)}`)
		.digest("hex")
		.slice(0, 12);
}

function isoTimestamp(entry: Record<string, unknown>, message?: Record<string, unknown>): string {
	const value = message?.timestamp ?? entry.timestamp;
	if (typeof value === "number") return new Date(value).toISOString();
	if (typeof value === "string" && !Number.isNaN(Date.parse(value))) return new Date(value).toISOString();
	return new Date(0).toISOString();
}

function dataErrorText(data: Record<string, unknown>): string {
	for (const key of ["error", "errorMessage", "message", "result", "description"]) {
		if (typeof data[key] === "string" && data[key]) return data[key];
	}
	return "Extension reported an error";
}

function extractCandidate(entry: Record<string, unknown>): { kind: ErrorKind; source: string; raw: string; message?: Record<string, unknown> } | null {
	if (entry.type === "message") {
		const message = record(entry.message);
		if (!message) return null;
		if (message.role === "toolResult" && message.isError === true) {
			return {
				kind: message.toolName === "Agent" ? "subagent" : "tool",
				source: typeof message.toolName === "string" ? message.toolName : "unknown-tool",
				raw: text(message.content) || "Tool execution failed",
				message,
			};
		}
		if (message.role === "assistant" && message.stopReason === "error") {
			const provider = typeof message.provider === "string" ? message.provider : "model";
			const model = typeof message.model === "string" ? message.model : "unknown";
			return {
				kind: "model",
				source: `${provider}/${model}`,
				raw: typeof message.errorMessage === "string" ? message.errorMessage : "Model response failed",
				message,
			};
		}
		if (message.role === "bashExecution" && typeof message.exitCode === "number" && message.exitCode !== 0) {
			return { kind: "bash", source: "user-bash", raw: text(message.output) || `Command exited with code ${message.exitCode}`, message };
		}
	}

	if (entry.type === "custom") {
		const data = record(entry.data);
		if (!data) return null;
		const status = typeof data.status === "string" ? data.status.toLowerCase() : "";
		if (status === "failed" || status === "error" || (!status && typeof data.error === "string")) {
			const customType = typeof entry.customType === "string" ? entry.customType : "unknown-extension";
			return {
				kind: customType.startsWith("subagents:") ? "subagent" : "extension",
				source: customType,
				raw: dataErrorText(data),
			};
		}
	}

	if (entry.type === "custom_message") {
		const details = record(entry.details);
		const status = typeof details?.status === "string" ? details.status.toLowerCase() : "";
		if (
			details &&
			typeof details.error === "string" &&
			status !== "completed" &&
			status !== "success" &&
			status !== "ok"
		) {
			return {
				kind: "extension",
				source: typeof entry.customType === "string" ? entry.customType : "unknown-extension",
				raw: details.error,
			};
		}
	}
	return null;
}

function comparablePath(value: string): string {
	const normalized = value.replaceAll("\\", "/").replace(/\/+$/, "");
	return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function safeLabel(value: string, homeDir = ""): string {
	return redactErrorText(value, homeDir)
		.replace(/[^\p{L}\p{N}_.:/@~<>?-]+/gu, "?")
		.slice(0, 120) || "unknown";
}

async function* readBoundedLines(
	file: string,
	maxLineBytes: number,
	onBytes: (count: number) => boolean,
	signal?: AbortSignal,
): AsyncGenerator<Buffer | null> {
	const input = createReadStream(file);
	const abort = () => input.destroy(new Error("Operation aborted"));
	signal?.addEventListener("abort", abort, { once: true });
	let pending = Buffer.alloc(0);
	let discarding = false;
	try {
		for await (const value of input) {
			if (signal?.aborted) throw new Error("Operation aborted");
			const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
			if (!onBytes(chunk.length)) {
				input.destroy();
				return;
			}
			let cursor = 0;
			while (cursor < chunk.length) {
				const newline = chunk.indexOf(0x0a, cursor);
				const end = newline === -1 ? chunk.length : newline;
				const segment = chunk.subarray(cursor, end);
				if (discarding) {
					if (newline !== -1) {
						discarding = false;
						yield null;
					}
				} else if (pending.length + segment.length > maxLineBytes) {
					pending = Buffer.alloc(0);
					if (newline === -1) discarding = true;
					else yield null;
				} else {
					pending = pending.length ? Buffer.concat([pending, segment]) : Buffer.from(segment);
					if (newline !== -1) {
						if (pending.at(-1) === 0x0d) pending = pending.subarray(0, -1);
						yield pending;
						pending = Buffer.alloc(0);
					}
				}
				if (newline === -1) break;
				cursor = newline + 1;
			}
		}
		if (discarding) yield null;
		else if (pending.length) yield pending;
	} finally {
		signal?.removeEventListener("abort", abort);
		input.destroy();
	}
}

export function sessionOriginId(file: string): string {
	const absolute = resolve(file).replaceAll("\\", "/");
	const normalized = process.platform === "win32" ? absolute.toLowerCase() : absolute;
	return createHash("sha256").update(normalized).digest("hex").slice(0, 16);
}

export async function scanSessionFiles(files: string[], options: ScanOptions = {}): Promise<ScanResult> {
	const maxFiles = Math.max(1, options.maxFiles ?? DEFAULT_MAX_FILES);
	const maxErrors = Math.max(1, options.maxErrors ?? DEFAULT_MAX_ERRORS);
	const maxTotalBytes = Math.max(1, options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES);
	const maxLineBytes = Math.max(1024, options.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES);
	const selected = files.slice(0, maxFiles);
	const errors: SessionError[] = [];
	const stats = {
		filesConsidered: files.length,
		filesScanned: 0,
		filesSkipped: Math.max(0, files.length - selected.length),
		malformedLines: 0,
		oversizedLines: 0,
		bytesRead: 0,
		truncated: files.length > selected.length,
	};
	let inputBudgetReached = false;

	outer: for (const file of selected) {
		if (options.signal?.aborted) throw new Error("Operation aborted");
		let sessionId = safeLabel(basename(file).replace(/\.jsonl$/i, ""), options.homeDir);
		let project = "unknown-project";
		const originId = sessionOriginId(file);
		try {
			stats.filesScanned++;
			const lines = readBoundedLines(
				file,
				maxLineBytes,
				(count) => {
					stats.bytesRead += count;
					inputBudgetReached = stats.bytesRead > maxTotalBytes;
					return !inputBudgetReached;
				},
				options.signal,
			);
			for await (const lineBuffer of lines) {
				if (lineBuffer === null) {
					stats.oversizedLines++;
					continue;
				}
				const line = lineBuffer.toString("utf8");
				if (!line.trim()) continue;
				let entry: Record<string, unknown>;
				try {
					const parsed = JSON.parse(line);
					const object = record(parsed);
					if (!object) throw new Error("not an object");
					entry = object;
				} catch {
					stats.malformedLines++;
					continue;
				}
				if (entry.type === "session") {
					if (typeof entry.id === "string") sessionId = safeLabel(entry.id.slice(0, 12), options.homeDir);
					if (typeof entry.cwd === "string") {
						const displayProject = options.homeDir && comparablePath(entry.cwd) === comparablePath(options.homeDir)
							? "~"
							: basename(entry.cwd.replaceAll("\\", "/")) || "root";
						project = safeLabel(displayProject, options.homeDir);
					}
					continue;
				}
				const candidate = extractCandidate(entry);
				if (!candidate) continue;
				const message = redactErrorText(candidate.raw, options.homeDir);
				if (!message) continue;
				const source = safeLabel(candidate.source, options.homeDir);
				errors.push({
					fingerprint: fingerprint(candidate.kind, source, message),
					kind: candidate.kind,
					source,
					message,
					timestamp: isoTimestamp(entry, candidate.message),
					sessionId,
					project,
					originId,
				});
				if (errors.length >= maxErrors) {
					stats.truncated = true;
					break outer;
				}
			}
			if (inputBudgetReached) {
				stats.truncated = true;
				break outer;
			}
		} catch (error) {
			if (options.signal?.aborted || (error instanceof Error && error.message === "Operation aborted")) throw error;
			stats.filesSkipped++;
		}
	}
	return { errors, stats };
}
