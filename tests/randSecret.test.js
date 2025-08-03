import { randomSecret } from "../dist/passken.js";

describe("randomSecret", () => {
	it("should generate a secret of the default length (32 bytes)", () => {
		const secret = randomSecret();
		expect(secret.length).toBeGreaterThan(59);
	});

	it("should generate a secret of the specified length (16 bytes)", () => {
		const secret = randomSecret(16);
		expect(secret.length).toBeGreaterThan(30);
	});

	it("should generate a secret of the specified length (64 bytes)", () => {
		const secret = randomSecret(64);
		expect(secret.length).toBeGreaterThan(123);
	});

	it('should not contain "+" characters', () => {
		const secret = randomSecret();
		expect(secret).not.toContain("+");
	});

	it('should not contain "/" characters', () => {
		const secret = randomSecret();
		expect(secret).not.toContain("/");
	});

	it('should not contain "=" characters', () => {
		const secret = randomSecret();
		expect(secret).not.toContain("=");
	});

	it("should generate unique secrets 1", () => {
		const secret1 = randomSecret();
		const secret2 = randomSecret();
		expect(secret1).not.toEqual(secret2);
	});

	it("should generate unique secrets 2", () => {
		const secret1 = randomSecret(64);
		const secret2 = randomSecret(64);
		expect(secret1).not.toEqual(secret2);
	});

	it("should generate unique secrets 3", () => {
		const secret1 = randomSecret(128);
		const secret2 = randomSecret(128);
		expect(secret1).not.toEqual(secret2);
	});

	it("should handle a length of 0 without throwing an error", () => {
		const secret = randomSecret(0);
		expect(secret).toHaveLength(0);
	});

	it("should return an empty string or throw an error for negative lengths", () => {
		expect(() => randomSecret(-1)).toThrow(
			'The value of "size" is out of range. It must be >= 0 && <= 2147483647. Received -1',
		);
	});

	it("should handle very large lengths", () => {
		const largeLength = 10000;
		const secret = randomSecret(largeLength);
		expect(secret.length).toBeGreaterThan(10000);
	});

	it("should only contain URL-friendly characters", () => {
		const secret = randomSecret();
		expect(secret).toMatch(/^[A-Za-z0-9_-]*$/);
	});
});
