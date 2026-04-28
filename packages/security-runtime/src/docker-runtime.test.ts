import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildExecCommand, buildSyncTargetsCommand, stripExecPidMarker } from "./docker-runtime.js";

describe("buildExecCommand", () => {
	it("wraps commands with a PID marker prelude", () => {
		assert.deepStrictEqual(buildExecCommand("echo hello"), [
			"sh",
			"-lc",
			'printf \'__NYATI_PID__=%s\\n\' "$$" >&2; exec sh -lc "$1"',
			"sh",
			"echo hello",
		]);
	});
});

describe("stripExecPidMarker", () => {
	it("extracts pid and removes the marker line", () => {
		assert.deepStrictEqual(stripExecPidMarker("__NYATI_PID__=123\nstderr line\n"), {
			pid: 123,
			stderr: "stderr line\n",
		});
	});

	it("returns null pid when the marker is absent", () => {
		assert.deepStrictEqual(stripExecPidMarker("stderr only\n"), {
			pid: null,
			stderr: "stderr only\n",
		});
	});
});

describe("buildSyncTargetsCommand", () => {
	it("writes scoped targets under the nyati metadata directory", () => {
		const command = buildSyncTargetsCommand([{ id: "t1", value: "https://example.com" }]);
		assert.match(command, /mkdir -p '\/workspace\/.nyati'/);
		assert.match(command, /> '\/workspace\/.nyati\/targets.json'$/);
		assert.match(command, /example\.com/);
	});
});
