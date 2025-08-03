import { setKeyLen, getKeyLen } from "../dist/passken.js";

describe("setKeyLen", () => {
	test("sets the key length correctly", () => {
		const keyLen = 24;
		setKeyLen(keyLen);
		expect(getKeyLen()).toBe(keyLen);
	});

	test("sets the key length at the upper limit", () => {
		const keyLen = 256;
		setKeyLen(keyLen);
		expect(getKeyLen()).toBe(keyLen);
	});

	test("sets the key length at the lower limit", () => {
		const keyLen = 2;
		setKeyLen(keyLen);
		expect(getKeyLen()).toBe(keyLen);
	});

	test("returns false when setting an invalid number key length", () => {
		expect(setKeyLen(0)).toBe(false);
		expect(setKeyLen(-1)).toBe(false);
		expect(setKeyLen(1)).toBe(false);
		expect(setKeyLen(257)).toBe(false);
		expect(setKeyLen(3.5)).toBe(false);
	});

	test("returns false when setting a null or undefined key length", () => {
		expect(setKeyLen(null)).toBe(false);
		expect(setKeyLen(undefined)).toBe(false);
	});

	test("returns false when setting a non-number key length", () => {
		expect(setKeyLen("32")).toBe(false);
	});

	test("persists the key length after multiple valid set operations", () => {
		setKeyLen(128);
		setKeyLen(192);
		expect(getKeyLen()).toBe(192);
	});

	test("returns false when setting a boolean value", () => {
		expect(setKeyLen(true)).toBe(false);
		expect(setKeyLen(false)).toBe(false);
	});

	test("returns false when setting an array or object", () => {
		expect(setKeyLen([128])).toBe(false);
		expect(setKeyLen({ length: 128 })).toBe(false);
	});

	test("does not change keyLen to an invalid value after setting a valid value", () => {
		setKeyLen(128); // Set a valid length first
		setKeyLen(0); // Then try to set an invalid length
		expect(getKeyLen()).toBe(128); // Expect the keyLen to remain at the last valid value
	});

	test("returns false when setting a floating-point number even if in valid range", () => {
		expect(setKeyLen(64.5)).toBe(false);
	});

	test("allows resetting keyLen to a default or another valid value", () => {
		setKeyLen(128); // Modify first
		setKeyLen(64); // Reset to default or another valid value
		expect(getKeyLen()).toBe(64);
	});
});
