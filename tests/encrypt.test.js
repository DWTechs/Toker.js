import { encrypt, randomSecret } from "../dist/passken.js";

describe("encrypt", () => {
	const password = "mySecret!/;6(A)Pwd";
	const InvalidSecret = {};
	const validSecret = randomSecret();
  console.log("validSecret", validSecret);

	test("returns a string when password and secret are encrypted", () => {
		expect(typeof encrypt(password, validSecret)).toBe("string");
	});

	test("Throw error when password is empty", () => {
		expect(() => {encrypt("", validSecret)}).toThrow();
	});

	test("Throw error when secret is empty", () => {
		expect(() => {encrypt(password, "")}).toThrow();
	});

	test("Throw error when secret is invalid", () => {
		expect(() => {encrypt(password, InvalidSecret)}).toThrow();
	});

	test("Throw error when password is not a string", () => {
		expect(() => {encrypt(123, validSecret)}).toThrow();
	});

	test("Throw error when secret is not a string", () => {
		expect(() => {encrypt(password, 123)}).toThrow();
	});

	test("generates different hashes for the same password and secret", () => {
		const hash1 = encrypt(password, validSecret);
		const hash2 = encrypt(password, validSecret);
		expect(hash1).not.toBe(hash2);
	});

	test("Throw error for non-string inputs", () => {
		expect(() => {encrypt(null, validSecret)}).toThrow();
		expect(() => {encrypt(password, null)}).toThrow();
		expect(() => {encrypt({}, validSecret)}).toThrow();
		expect(() => {encrypt(password, [])}).toThrow();
	});
});
