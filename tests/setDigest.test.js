import { setDigest, getDigest } from "../dist/passken.js";

describe("setDigest", () => {
	test("sets the digest correctly", () => {
		const digest = "sha512";
		setDigest(digest);
		expect(getDigest()).toBe(digest);
	});

	test("returns false when setting an invalid digest", () => {
		expect(setDigest("invalidDigest")).toBe(false);
	});

	test("returns false when setting a null or undefined digest", () => {
		expect(setDigest(null)).toBe(false);
		expect(setDigest(undefined)).toBe(false);
	});

	test("returns false when setting a non-string digest", () => {
		expect(setDigest(123)).toBe(false);
	});

	test("returns false when setting an object as digest", () => {
		expect(setDigest({})).toBe(false);
	});

	test("returns false when setting an empty string", () => {
		expect(setDigest("")).toBe(false);
	});

	test("does not change the current digest when an invalid digest is provided", () => {
		const originalDigest = getDigest();
		setDigest("invalidDigest");
		expect(getDigest()).toBe(originalDigest);
	});

	test("is case-sensitive when setting a digest", () => {
		const lowerCaseDigest = "sha256";
		const upperCaseDigest = "SHA256";
		expect(setDigest(upperCaseDigest)).toBe(false);
		expect(setDigest(lowerCaseDigest)).toBe(true);
	});
});
