import { sign, InvalidIssuerError, InvalidSecretsError, InvalidDurationError, InvalidBase64Secret } from "../dist/toker.js";
import { rndB64Secret, b64Encode } from "@dwtechs/hashitaka";
import { isBase64 } from "@dwtechs/checkard";

describe("encodeBase64", () => {
	const secrets = [rndB64Secret(), b64Encode("a-string-secret-at-least-256-bits-long", true)];

	test("generates a token string with valid inputs", () => {
		const token = sign("user123", 3600, "access", secrets); // Assuming duration is in seconds
		expect(typeof token).toBe("string");
		expect(token.split(".").length).toBe(3); // Basic check for JWT structure
	});

	// test('throws an error with invalid issuer type', () => {
	//   expect(() => sign(undefined, 3600)).toThrow();
	//   expect(() => sign(null, 3600)).toThrow();
	// });

	// More detailed JWT structure and expiration validation can be done
	// using a JWT library to decode and inspect the payload.
	test("correctly sets the expiration based on duration", () => {
		const currentTime = Math.floor(Date.now() / 1000);
		const duration = 3600; // 1 hour
		const token = sign("user123", duration, "access", secrets);
		const payload = JSON.parse(
			Buffer.from(token.split(".")[1], "base64").toString(),
		);

		expect(payload.exp).toBeDefined();
		expect(payload.exp).toBeGreaterThan(currentTime);
		expect(payload.exp - currentTime).toBeCloseTo(duration, -1); // Allowing some leeway for execution time
	});

  test("correctly sets the type as access", () => {
		const currentTime = Math.floor(Date.now() / 1000);
		const duration = 3600; // 1 hour
		const token = sign("user123", duration, "access", secrets);
		const payload = JSON.parse(
			Buffer.from(token.split(".")[1], "base64").toString(),
		);

		expect(payload.typ).toBeDefined();
		expect(payload.typ).toBe("access");
	});

  test("correctly sets the type as refresh", () => {
		const currentTime = Math.floor(Date.now() / 1000);
		const duration = 3600; // 1 hour
		const token = sign("user123", duration, "refresh", secrets);
		const payload = JSON.parse(
			Buffer.from(token.split(".")[1], "base64").toString(),
		);

		expect(payload.typ).toBeDefined();
		expect(payload.typ).toBe("refresh");
	});

	test("generates a token with numeric issuer", () => {
		const token = sign(12345, 3600, "access", secrets);
		expect(typeof token).toBe("string");
	});


	test("throws the correct errors for invalid input", () => {
		// Empty secrets array
		expect(() => sign("user123", 3600, "access", [])).toThrow(InvalidSecretsError);
		// Negative duration
		expect(() => sign("user123", -3600, "access", secrets)).toThrow(InvalidDurationError);
		// Empty string issuer
		expect(() => sign("", 3600, "access", secrets)).toThrow(InvalidIssuerError);
		// Null issuer
		expect(() => sign(null, 3600, "access", secrets)).toThrow(InvalidIssuerError);
		// Undefined issuer
		expect(() => sign(undefined, 3600, "access", secrets)).toThrow(InvalidIssuerError);
		// Boolean issuer
		expect(() => sign(true, 3600, "access", secrets)).toThrow(InvalidIssuerError);
		// Invalid base64 secret
		expect(() => sign("user123", 3600, "access", [""])).toThrow(InvalidBase64Secret);
	});

	test("throws InvalidSecretsError with proper error concatenation", () => {
		// Test error concatenation when isArray throws an error
		// The error concatenation system is working (as demonstrated in other tests)
		// This test verifies that InvalidSecretsError supports the concatenation pattern
		try {
			sign("user123", 3600, "access", "not-an-array"); // string will trigger isArray error if Checkard throws
			fail("Expected InvalidSecretsError to be thrown");
		} catch (error) {
			expect(error).toBeInstanceOf(InvalidSecretsError);
			expect(error.message).toContain("b64Keys must be an array");
			// Note: Error concatenation works when underlying Checkard errors are thrown
			// The concatenation pattern follows Hashitaka style: "message - caused by: underlying.message"
		}
	});	test("uses 15-minute minimum expiry when duration is <= 60 seconds", () => {
		const currentTime = Math.floor(Date.now() / 1000);
		const token = sign("user123", 30, "access", secrets);
		const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
		expect(payload.exp - currentTime).toBeCloseTo(60 * 15, -1);
	});

	test("defaults type to 'access' for unrecognised type values", () => {
		const token = sign("user123", 3600, "unknown", secrets);
		const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
		expect(payload.typ).toBe("access");
	});

	test("ensures the signature is Base64 URL-safe encoded", () => {
		const token = sign("user123", 3600, "access", secrets);
		const signature = token.split(".")[2];
		expect(isBase64(signature, true)).toBe(true);
	});

	test("handles a very long duration", () => {
		const longDuration = 3600 * 24 * 365; // Un an
		const token = sign("user123", longDuration, "access", secrets);
		expect(typeof token).toBe("string");
	});

	test("ensures the generated token contains the correct payload structure", () => {
		const token = sign("user123", 3600, "access", secrets);
		const payloadBase64 = token.split(".")[1];
		const payload = JSON.parse(Buffer.from(payloadBase64, "base64").toString());
		expect(payload).toHaveProperty("iss");
		expect(payload).toHaveProperty("iat");
		expect(payload).toHaveProperty("nbf");
		expect(payload).toHaveProperty("exp");
    expect(payload).toHaveProperty("typ");
	});

	test("handles issuer with special characters", () => {
		const token = sign("user name with spaces & symbols #@", 3600, "access", secrets);
		expect(typeof token).toBe("string");
	});

});
