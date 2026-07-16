import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { formatErrorReport, groupErrors } from "../src/format.ts";
import {
	normalizeFingerprintText,
	redactErrorText,
	scanSessionFiles,
} from "../src/scanner.ts";

async function fixture(lines: unknown[]): Promise<{ dir: string; file: string }> {
	const dir = await mkdtemp(path.join(os.tmpdir(), "pi-errors-"));
	const file = path.join(dir, "session.jsonl");
	await writeFile(file, `${lines.map((line) => typeof line === "string" ? line : JSON.stringify(line)).join("\n")}\n`, "utf8");
	return { dir, file };
}

test("redacts credentials, filesystem paths, and opaque blobs", () => {
	const raw = "failed C:\\Users\\alice\\repo token=supersecret root=/etc AWS_SECRET_ACCESS_KEY=awssecret Basic dXNlcjpwYXNzd29yZA== ssh://user:pass@host/repo Bearer abcdefghijklmnop sk-abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRST";
	const redacted = redactErrorText(raw, "C:\\Users\\alice");
	assert.equal(redacted.includes("supersecret"), false);
	assert.equal(redacted.includes("abcdefghijklmnop"), false);
	assert.equal(redacted.includes("sk-abcdefghijklmnopqrstuvwxyz"), false);
	assert.equal(redacted.includes("awssecret"), false);
	assert.equal(redacted.includes("dXNlcjpwYXNzd29yZA"), false);
	assert.equal(redacted.includes("user:pass"), false);
	assert.equal(redacted.includes("/etc"), false);
	assert.match(redacted, /^failed <home-path> token=\[REDACTED\]/);
});

test("normalizes volatile ids, paths, and numbers for grouping", () => {
	assert.equal(
		normalizeFingerprintText("Error 42 at C:\\repo\\file.ts id 123e4567-e89b-12d3-a456-426614174000"),
		normalizeFingerprintText("Error 99 at D:\\other\\main.ts id 987e6543-e21b-12d3-a456-426614174999"),
	);
});

test("detects tool, model, bash, subagent, and extension errors", async () => {
	const { dir, file } = await fixture([
		{ type: "session", version: 3, id: "session-123456789", cwd: "C:/dev/demo" },
		{ type: "message", timestamp: "2026-01-01T00:00:00Z", message: { role: "toolResult", toolName: "bash", isError: true, content: [{ type: "text", text: "exit 1 token=secretvalue" }], timestamp: 1 } },
		{ type: "message", timestamp: "2026-01-02T00:00:00Z", message: { role: "assistant", provider: "openai", model: "model-x", stopReason: "error", errorMessage: "provider unavailable", timestamp: 2 } },
		{ type: "message", timestamp: "2026-01-03T00:00:00Z", message: { role: "bashExecution", exitCode: 7, output: "script failed", timestamp: 3 } },
		{ type: "custom", customType: "subagents:record", timestamp: "2026-01-04T00:00:00Z", data: { status: "failed", result: "agent crashed" } },
		{ type: "custom_message", customType: "sample-extension", timestamp: "2026-01-05T00:00:00Z", details: { error: "extension exploded" } },
		"{malformed",
	]);
	try {
		const result = await scanSessionFiles([file], { homeDir: "C:/Users/alice" });
		assert.deepEqual(result.errors.map((error) => error.kind), ["tool", "model", "bash", "subagent", "extension"]);
		assert.equal(result.stats.malformedLines, 1);
		assert.equal(result.errors[0]?.message.includes("secretvalue"), false);
		assert.equal(result.errors.every((error) => error.project === "demo"), true);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("groups similar errors and formats both views without raw paths", async () => {
	const { dir, file } = await fixture([
		{ type: "session", version: 3, id: "session-abcdefgh", cwd: "/home/alice/project" },
		{ type: "message", timestamp: "2026-01-01T00:00:00Z", message: { role: "toolResult", toolName: "bash", isError: true, content: [{ type: "text", text: "Command 42 failed at /home/alice/project/a.ts" }] } },
		{ type: "message", timestamp: "2026-01-02T00:00:00Z", message: { role: "toolResult", toolName: "bash", isError: true, content: [{ type: "text", text: "Command 99 failed at /home/alice/project/b.ts" }] } },
	]);
	try {
		const result = await scanSessionFiles([file], { homeDir: "/home/alice" });
		const groups = groupErrors(result.errors);
		assert.equal(groups.length, 1);
		assert.equal(groups[0]?.count, 2);
		const report = formatErrorReport(result, "both", 10);
		assert.match(report, /Summary/);
		assert.match(report, /Timeline/);
		assert.equal(report.includes("/home/alice"), false);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("enforces file and error budgets", async () => {
	const one = await fixture([{ type: "session", id: "one", cwd: "/one" }]);
	const two = await fixture([
		{ type: "session", id: "two", cwd: "/two" },
		{ type: "message", message: { role: "toolResult", toolName: "read", isError: true, content: "bad" } },
		{ type: "message", message: { role: "toolResult", toolName: "read", isError: true, content: "worse" } },
	]);
	try {
		const fileLimited = await scanSessionFiles([one.file, two.file], { maxFiles: 1 });
		assert.equal(fileLimited.stats.truncated, true);
		assert.equal(fileLimited.stats.filesSkipped, 1);
		const errorLimited = await scanSessionFiles([two.file], { maxErrors: 1 });
		assert.equal(errorLimited.errors.length, 1);
		assert.equal(errorLimited.stats.truncated, true);
		const byteLimited = await scanSessionFiles([two.file], { maxTotalBytes: 10 });
		assert.equal(byteLimited.stats.truncated, true);
		assert.equal(byteLimited.errors.length, 0);
	} finally {
		await rm(one.dir, { recursive: true, force: true });
		await rm(two.dir, { recursive: true, force: true });
	}
});

test("skips oversized JSONL lines without losing later errors", async () => {
	const { dir, file } = await fixture([
		"x".repeat(8_000),
		{ type: "session", id: "bounded", cwd: "/bounded" },
		{ type: "message", message: { role: "toolResult", toolName: "bash", isError: true, content: "later failure" } },
	]);
	try {
		const result = await scanSessionFiles([file], { maxLineBytes: 1_024 });
		assert.equal(result.stats.oversizedLines, 1);
		assert.equal(result.errors.length, 1);
		assert.equal(result.errors[0]?.message, "later failure");
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("sanitizes source labels and never falls back to assistant prose", async () => {
	const { dir, file } = await fixture([
		{ type: "session", id: "session\u001b[31m", cwd: "/project" },
		{ type: "message", message: { role: "toolResult", toolName: "evil\nsource", isError: true, content: "failed" } },
		{ type: "message", message: { role: "assistant", provider: "provider", model: "model", stopReason: "error", content: [{ type: "text", text: "private assistant prose" }] } },
		{ type: "custom", customType: "successful-extension", data: { status: "completed", error: "historical field" } },
		{ type: "custom_message", customType: "successful-message", details: { status: "success", error: "historical message field" } },
	]);
	try {
		const result = await scanSessionFiles([file]);
		assert.equal(result.errors.length, 2);
		assert.equal(result.errors[0]?.source, "evil?source");
		assert.equal(result.errors[1]?.message, "Model response failed");
		assert.equal(result.errors.some((error) => error.message.includes("private assistant prose")), false);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
