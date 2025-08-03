import { getDigests } from "../dist/passken.js";

describe("getDigests", () => {
	test("returns an array", () => {
		expect(Array.isArray(getDigests())).toBe(true);
	});

	test("returns an array of strings", () => {
		const digests = getDigests();
		expect(digests.every((digest) => typeof digest === "string")).toBe(true);
	});

	test("returns a non-empty array", () => {
		expect(getDigests().length).toBeGreaterThan(0);
	});

	test("includes the default digest", () => {
		const digests = getDigests();
		expect(digests.includes("sha256")).toBe(true); // default digest
	});

	test("does not allow the returned array to mutate the original digests", () => {
		const originalDigests = getDigests();
		const digests = getDigests();
		digests.push("newDigest");
		expect(getDigests()).toEqual(originalDigests);
	});

	test("returns consistent values across multiple calls", () => {
		const firstCall = getDigests();
		const secondCall = getDigests();
		expect(secondCall).toEqual(firstCall);
	});

	test("does not include invalid or unexpected digest values", () => {
		const digests = getDigests();
		const invalidValues = digests.filter(
			(digest) => typeof digest !== "string" || digest === "",
		);
		expect(invalidValues.length).toBe(0);
	});
});
