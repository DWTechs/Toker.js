import { setSaltRounds, getSaltRounds } from "../dist/passken.js";

describe("setSaltRounds", () => {
	test("sets the salt rounds correctly", () => {
		const saltRounds = 14;
		setSaltRounds(saltRounds);
		expect(getSaltRounds()).toBe(saltRounds);
	});

	test("sets the salt rounds at the upper limit", () => {
		const saltRounds = 100;
		setSaltRounds(saltRounds);
		expect(getSaltRounds()).toBe(saltRounds);
	});

	test("sets the salt rounds at the lower limit", () => {
		const saltRounds = 12;
		setSaltRounds(saltRounds);
		expect(getSaltRounds()).toBe(saltRounds);
	});

	test("returns false when setting an invalid number salt rounds", () => {
		expect(setSaltRounds(0)).toBe(false);
		expect(setSaltRounds(-1)).toBe(false);
		expect(setSaltRounds(1)).toBe(false);
		expect(setSaltRounds(101)).toBe(false);
		expect(setSaltRounds(3, 5)).toBe(false);
	});

	test("returns false when setting a null or undefined salt rounds", () => {
		expect(setSaltRounds(null)).toBe(false);
		expect(setSaltRounds(undefined)).toBe(false);
	});

	test("returns false when setting a non-number salt rounds", () => {
		expect(setSaltRounds("32")).toBe(false);
	});

	test("returns false when setting with an array", () => {
		expect(setSaltRounds([12])).toBe(false);
	});

	test("rejects a value just below the minimum limit", () => {
		expect(setSaltRounds(11)).toBe(false);
	});

	test("rejects a value just above the maximum limit", () => {
		expect(setSaltRounds(101)).toBe(false);
	});

	test("does not change saltRnds to an invalid value after setting a valid value", () => {
		setSaltRounds(14); // Set a valid value first
		setSaltRounds(101); // Then try to set an invalid value
		expect(getSaltRounds()).toBe(14); // Expect the saltRnds to remain at the last valid value
	});

	test("returns false when setting with a floating-point number", () => {
		expect(setSaltRounds(13.5)).toBe(false);
	});

	test("persists the salt rounds value after multiple valid set operations", () => {
		setSaltRounds(15);
		setSaltRounds(20);
		expect(getSaltRounds()).toBe(20);
	});
});
