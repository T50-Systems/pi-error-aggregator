import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import assert from "node:assert/strict";
import test from "node:test";
import errorAggregatorExtension, { boundedOutput, parseCommandArgs } from "../src/index.ts";

test("registers the session_errors tool and errors command", () => {
	const tools: Array<{ name: string }> = [];
	const commands: string[] = [];
	const pi = {
		registerTool(tool: { name: string }) {
			tools.push(tool);
		},
		registerCommand(name: string) {
			commands.push(name);
		},
	};
	errorAggregatorExtension(pi as never);
	assert.deepEqual(tools.map((tool) => tool.name), ["session_errors"]);
	assert.deepEqual(commands, ["errors"]);
});

test("parses current-session and backwards-compatible command forms", () => {
	assert.deepEqual(parseCommandArgs("current list 50"), {
		action: "report",
		scope: "current",
		mode: "timeline",
		limit: 50,
		filters: {},
	});
	assert.deepEqual(parseCommandArgs("session both"), {
		action: "report",
		scope: "current",
		mode: "both",
		limit: 20,
		filters: {},
	});
	assert.deepEqual(parseCommandArgs("summary 10"), {
		action: "report",
		scope: "all",
		mode: "summary",
		limit: 10,
		filters: {},
	});
	assert.throws(() => parseCommandArgs("current both 20 extra"), /Usage/);
});

test("parses actions and additive filters", () => {
	assert.deepEqual(parseCommandArgs("new 25 --kind tool --since=24h --exclude model,rate-limit"), {
		action: "new",
		scope: "current",
		mode: "summary",
		limit: 25,
		filters: { kind: "tool", since: "24h", exclude: ["model,rate-limit"] },
	});
	assert.deepEqual(parseCommandArgs("show ABCDEF123456 current 10 --source bash"), {
		action: "show",
		scope: "current",
		mode: "timeline",
		limit: 10,
		fingerprint: "ABCDEF123456",
		filters: { source: "bash" },
	});
	assert.deepEqual(parseCommandArgs("compare --project pi"), {
		action: "compare",
		scope: "current",
		mode: "summary",
		limit: 20,
		filters: { project: "pi" },
	});
	assert.throws(() => parseCommandArgs("new --unknown value"), /Unknown filter/);
});

test("executes the legacy tool shape for a persisted current session and rejects ephemeral current scope", async () => {
	const dir = await mkdtemp(path.join(os.tmpdir(), "pi-errors-index-"));
	const file = path.join(dir, "session.jsonl");
	await writeFile(file, [
		JSON.stringify({ type: "session", version: 3, id: "legacy-session", cwd: "/project" }),
		JSON.stringify({ type: "message", message: { role: "toolResult", toolName: "bash", isError: true, content: "Command exited with code 1" } }),
	].join("\n") + "\n", "utf8");
	let tool: any;
	errorAggregatorExtension({
		registerTool(value: any) { tool = value; },
		registerCommand() {},
	} as never);
	const signal = new AbortController().signal;
	try {
		const result = await tool.execute("legacy", { scope: "current", mode: "summary", limit: 1 }, signal, undefined, {
			sessionManager: { getSessionFile: () => file },
		});
		assert.match(result.content[0].text, /^Current session errors:/);
		await assert.rejects(
			tool.execute("ephemeral", { scope: "current" }, signal, undefined, {
				sessionManager: { getSessionFile: () => undefined },
			}),
			/not persisted/,
		);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test("keeps final output within line and byte caps", () => {
	const output = boundedOutput(Array.from({ length: 400 }, (_, index) => `${index} ${"x".repeat(400)}`).join("\n"));
	assert.equal(output.truncated, true);
	assert.ok(output.text.split("\n").length <= 240);
	assert.ok(Buffer.byteLength(output.text, "utf8") <= 48 * 1024);
});
