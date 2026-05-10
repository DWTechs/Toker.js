import { verify, sign, InvalidTokenError, InactiveTokenError, ExpiredTokenError, InvalidSignatureError, InvalidSecretsError, InvalidBase64Secret } from "../dist/toker.js";
import { HashLengthMismatchError, b64Encode, b64Decode, hash } from "@dwtechs/hashitaka";
// Mock data
const expiredToken = 
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6MX0.eyJpc3MiOiJ1c2VyMTIzIiwiaWF0IjoxNzQwNjA1NjUyLCJuYmYiOjE3NDA2MDU2NTMsImV4cCI6MTc0MDYwOTI1MiwidHlwIjoiYWNjZXNzIn0.xpEKqwDu7EOjkYfyZHxCOaikcKzU3zX5mMPu5Can7FU";
const TokenWithBadSecret =
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6MH0.eyJpc3MiOiJ1c2VyMTIzIiwiaWF0IjoxNzQwMjQ3OTEzLCJuYmYiOjE3NDAyNDc5MTQsImV4cCI6MTc0MDI1MTUxMywidHlwIjoiYWNjZXNzIn0.YTNmYzk3Nzc5NjA5MzY4ZjI0YTdhM2YwNzkyNTk3M2ZlNTM0ZTk2YjkxNWViZjBmYTc5NDliYzE3ZjhjMTIyMg";
const invalidAlgToken =
	"eyJhbGciOiJpbnZhbGlkIiwidHlwIjoiSldUIiwia2lkIjowfQ.eyJpc3MiOiJ1c2VyMTIzIiwiaWF0IjoxNzM4MjMxNTQ0LCJuYmYiOjE3MzgyMzE1NDUsImV4cCI6MTczODIzNTE0NH0.bFhIP9c9oNf2kAk2usDBWFI57Xt3IK_BhonaTMGB5Ew";
const invalidTypToken =
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IklOVkFMSUQiLCJraWQiOjB9.eyJpc3MiOiJ1c2VyMTIzIiwiaWF0IjoxNzM4MjMxNTk0LCJuYmYiOjE3MzgyMzE1OTUsImV4cCI6MTczODIzNTE5NH0.OX2EdvtBv5bQwblpmx0rmLZXWnn-zoGdClYPccRTQ80";
const invalidToken = "invalid.token.signature";
const b64Secrets = [
  '77-977-9dxlAaDLXv--_ve-_vX3vv73vv73vv70-AxnbuDBAKO-_ve-_vQMGWO-_vWrvv73vv70',
  'YS1zdHJpbmctc2VjcmV0LWF0LWxlYXN0LTI1Ni1iaXRzLWxvbmc'
];
const otherB64Secrets = [
  '78-977-9dxlAaDLXv--_ve-_vX3vv73vv73vv70-AxnbuDBAKO-_ve-_vQMGWO-_vWrvv73vv70',
  'YR1zdHJpbmctc2VjcmV0LWF0LWxlYXN0LTI1Ni1iaXRzLWxvbmc'
];
const validToken = sign("user123", 3600, "access", b64Secrets);
const invalidTokenSecrets = sign("user123", 3600, "access", otherB64Secrets);

// Builds a token with a custom header for testing specific header fields
function makeToken(kid, payload = { iss: "test", iat: 1, nbf: 1, exp: 9999999999, typ: "access" }) {
	const header = { alg: "HS256", typ: "JWT", kid };
	const b64Header = Buffer.from(JSON.stringify(header)).toString("base64url");
	const b64Payload = Buffer.from(JSON.stringify(payload)).toString("base64url");
	return `${b64Header}.${b64Payload}.fakesignature`;
}

describe("verify", () => {

	it("should throw InvalidSecretsError for empty secrets array", () => {
		expect(() => { verify(validToken, []) }).toThrow(InvalidSecretsError);
	});

	it("should throw InvalidSecretsError when secrets is not an array", () => {
		expect(() => { verify(validToken, "not-an-array") }).toThrow(InvalidSecretsError);
	});

	it("should throw InvalidTokenError for kid out of bounds", () => {
		const token = makeToken(999); // b64Secrets only has 2 entries
		expect(() => { verify(token, b64Secrets, true) }).toThrow(InvalidTokenError);
	});

	it("should throw InvalidTokenError for kid as a string", () => {
		const token = makeToken("0");
		expect(() => { verify(token, b64Secrets, true) }).toThrow(InvalidTokenError);
	});

	it("should throw InvalidTokenError for kid as a negative number", () => {
		const token = makeToken(-1);
		expect(() => { verify(token, b64Secrets, true) }).toThrow(InvalidTokenError);
	});

	it("should throw InvalidBase64Secret when the key at the kid index is not valid base64", () => {
		// TokenWithBadSecret has kid=0; passing an invalid base64 key at index 0
		expect(() => { verify(TokenWithBadSecret, ["!!!not-valid-base64!!!"], true) }).toThrow(InvalidBase64Secret);
	});

	it("should throw error for a token with invalid segments", () => {
		expect(() => { verify("invalid.token", b64Secrets)}).toThrow(InvalidTokenError);
	});

	it("should throw error for a token with invalid header", () => {
		expect(() => { verify(invalidToken, b64Secrets)}).toThrow(InvalidTokenError);
	});

	it("should throw error for a token with invalid payload", () => {
		expect(() => { verify("valid.token.invalidPayload", b64Secrets)}).toThrow(InvalidTokenError);
	});

	it("should throw error for a token with invalid algorithm", () => {
		expect(() => { verify(invalidAlgToken, b64Secrets)}).toThrow(InvalidTokenError);
	});

	it("should throw error for a token with invalid typ", () => {
		expect(() => { verify(invalidTypToken, b64Secrets)}).toThrow(InvalidTokenError);
	});

	it("should throw error for a token with invalid kid", () => {
		const invalidKidToken = "invalidKid.token.signature";
		expect(() => { verify(invalidKidToken, b64Secrets)}).toThrow(InvalidTokenError);
	});

	it("should throw error for a token with exp claim in the past", () => {
		expect(() => { verify(expiredToken, b64Secrets)}).toThrow(ExpiredTokenError);
	});

  	it("should throw InvalidSignatureError when secrets don't match with different secret size", () => {
		expect(() => {verify(TokenWithBadSecret, b64Secrets, true)}).toThrow(InvalidSignatureError);
	});

	it("should throw InvalidSignatureError when secrets don't match", () => {
		expect(() => {verify(invalidTokenSecrets, b64Secrets, true)}).toThrow(InvalidSignatureError);
	});

	it("should throw error when signature does not match (wrong secret)", () => {
		// Use a valid token but verify with a different secret array
		const wrongSecrets = [
			'dGhpcy1pcy1ub3QtdGhlLXJpZ2h0LXNlY3JldA',
			'YW5vdGhlci1mYWtlLXNlY3JldC1mb3ItdGVzdA'
		];
		expect(() => {verify(validToken, wrongSecrets, true)}).toThrow(InvalidSignatureError);
	});

	it("should throw InvalidSignatureError when tse throws HashLengthMismatchError", () => {
		// Create a token with a signature of different length to trigger HashLengthMismatchError in tse
		// This tests the specific catch block: catch(err) { throw new InvalidSignatureError(undefined, err); }
		// The tse function will throw HashLengthMismatchError due to buffer length mismatch,
		// which should be wrapped in InvalidSignatureError with proper error chaining
		const tokenWithShortSignature = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6MH0.eyJpc3MiOiJ1c2VyMTIzIiwiaWF0IjoxNzQwMjQ3OTEzLCJuYmYiOjE3NDAyNDc5MTQsImV4cCI6MTc0MDI1MTUxMywidHlwIjoiYWNjZXNzIn0.short";
		
		try {
			verify(tokenWithShortSignature, b64Secrets, true);
			fail("Expected InvalidSignatureError to be thrown");
		} catch (error) {
			expect(error).toBeInstanceOf(InvalidSignatureError);
			expect(error.message).toContain("JWT token signature is invalid");
			expect(error.message).toContain("caused by:");
			expect(error.message).toContain("Hashes must have the same byte length");
		}
	});

  	it("should return the decoded token with exp claim in the past and ignoreExpiration = true", () => {
    	const result = verify(expiredToken, b64Secrets, true);
		expect(result).toBeInstanceOf(Object);
	});

	it("should return the decoded token for a valid token", () => {
		const result = verify(validToken, b64Secrets);
		expect(result).toBeInstanceOf(Object);
	});

	it("should throw InvalidTokenError when a segment is empty (e.g. header..sig)", () => {
		expect(() => { verify("a..c", b64Secrets) }).toThrow(InvalidTokenError);
		expect(() => { verify(".b.c", b64Secrets) }).toThrow(InvalidTokenError);
		expect(() => { verify("a.b.", b64Secrets) }).toThrow(InvalidTokenError);
	});

	it("should throw InactiveTokenError for a token with a future nbf claim", () => {
		const kid = 0;
		const secret = b64Decode(b64Secrets[kid], true);
		const now = Math.floor(Date.now() / 1000);
		const futureNbf = now + 3600;
		const hdr = { alg: "HS256", typ: "JWT", kid };
		const pl = { iss: "user123", iat: now, nbf: futureNbf, exp: now + 7200, typ: "access" };
		const b64Header = b64Encode(JSON.stringify(hdr), true);
		const b64Payload = b64Encode(JSON.stringify(pl), true);
		const sig = hash(`${b64Header}.${b64Payload}`, secret);
		const inactiveToken = `${b64Header}.${b64Payload}.${sig}`;
		expect(() => { verify(inactiveToken, b64Secrets) }).toThrow(InactiveTokenError);
	});

	it("InactiveTokenError should have correct code and statusCode", () => {
		const kid = 0;
		const secret = b64Decode(b64Secrets[kid], true);
		const now = Math.floor(Date.now() / 1000);
		const hdr = { alg: "HS256", typ: "JWT", kid };
		const pl = { iss: "user123", iat: now, nbf: now + 3600, exp: now + 7200, typ: "access" };
		const b64Header = b64Encode(JSON.stringify(hdr), true);
		const b64Payload = b64Encode(JSON.stringify(pl), true);
		const sig = hash(`${b64Header}.${b64Payload}`, secret);
		const inactiveToken = `${b64Header}.${b64Payload}.${sig}`;
		try {
			verify(inactiveToken, b64Secrets);
			fail("Expected InactiveTokenError");
		} catch (error) {
			expect(error).toBeInstanceOf(InactiveTokenError);
			expect(error.code).toBe("INACTIVE_TOKEN");
			expect(error.statusCode).toBe(401);
		}
	});

	it("should not throw InactiveTokenError when nbf is 0 (falsy)", () => {
		const kid = 0;
		const secret = b64Decode(b64Secrets[kid], true);
		const now = Math.floor(Date.now() / 1000);
		const hdr = { alg: "HS256", typ: "JWT", kid };
		const pl = { iss: "user123", iat: now, nbf: 0, exp: now + 3600, typ: "access" };
		const b64Header = b64Encode(JSON.stringify(hdr), true);
		const b64Payload = b64Encode(JSON.stringify(pl), true);
		const sig = hash(`${b64Header}.${b64Payload}`, secret);
		const tokenWithZeroNbf = `${b64Header}.${b64Payload}.${sig}`;
		expect(() => { verify(tokenWithZeroNbf, b64Secrets) }).not.toThrow();
	});

	it("should not throw InactiveTokenError when nbf equals now", () => {
		const kid = 0;
		const secret = b64Decode(b64Secrets[kid], true);
		const now = Math.floor(Date.now() / 1000);
		const hdr = { alg: "HS256", typ: "JWT", kid };
		const pl = { iss: "user123", iat: now, nbf: now, exp: now + 3600, typ: "access" };
		const b64Header = b64Encode(JSON.stringify(hdr), true);
		const b64Payload = b64Encode(JSON.stringify(pl), true);
		const sig = hash(`${b64Header}.${b64Payload}`, secret);
		const tokenNbfNow = `${b64Header}.${b64Payload}.${sig}`;
		expect(() => { verify(tokenNbfNow, b64Secrets) }).not.toThrow();
	});

	// Security: exp claim validation
	it("should throw InvalidTokenError when exp is null (would silently pass without validation)", () => {
		const kid = 0;
		const secret = b64Decode(b64Secrets[kid], true);
		const now = Math.floor(Date.now() / 1000);
		const hdr = { alg: "HS256", typ: "JWT", kid };
		const pl = { iss: "user123", iat: now, nbf: now, exp: null, typ: "access" };
		const b64Header = b64Encode(JSON.stringify(hdr), true);
		const b64Payload = b64Encode(JSON.stringify(pl), true);
		const sig = hash(`${b64Header}.${b64Payload}`, secret);
		expect(() => { verify(`${b64Header}.${b64Payload}.${sig}`, b64Secrets) }).toThrow(InvalidTokenError);
	});

	it("should throw InvalidTokenError when exp is a string (crafted payload)", () => {
		const kid = 0;
		const secret = b64Decode(b64Secrets[kid], true);
		const now = Math.floor(Date.now() / 1000);
		const hdr = { alg: "HS256", typ: "JWT", kid };
		const pl = { iss: "user123", iat: now, nbf: now, exp: "never", typ: "access" };
		const b64Header = b64Encode(JSON.stringify(hdr), true);
		const b64Payload = b64Encode(JSON.stringify(pl), true);
		const sig = hash(`${b64Header}.${b64Payload}`, secret);
		expect(() => { verify(`${b64Header}.${b64Payload}.${sig}`, b64Secrets) }).toThrow(InvalidTokenError);
	});

	it("should throw InvalidTokenError when exp is Infinity", () => {
		const kid = 0;
		const secret = b64Decode(b64Secrets[kid], true);
		const now = Math.floor(Date.now() / 1000);
		const hdr = { alg: "HS256", typ: "JWT", kid };
		// JSON.stringify turns Infinity to null, so use a workaround
		const rawPayload = `{"iss":"user123","iat":${now},"nbf":${now},"exp":1e309,"typ":"access"}`;
		const b64Header = b64Encode(JSON.stringify(hdr), true);
		const b64Payload = b64Encode(rawPayload, true);
		const sig = hash(`${b64Header}.${b64Payload}`, secret);
		expect(() => { verify(`${b64Header}.${b64Payload}.${sig}`, b64Secrets) }).toThrow(InvalidTokenError);
	});

	// Security: kid integer check
	it("should throw InvalidTokenError when kid is a float (e.g. 0.5)", () => {
		const kid = 0;
		const secret = b64Decode(b64Secrets[kid], true);
		const now = Math.floor(Date.now() / 1000);
		const hdr = { alg: "HS256", typ: "JWT", kid: 0.5 };
		const pl = { iss: "user123", iat: now, nbf: now, exp: now + 3600, typ: "access" };
		const b64Header = b64Encode(JSON.stringify(hdr), true);
		const b64Payload = b64Encode(JSON.stringify(pl), true);
		const sig = hash(`${b64Header}.${b64Payload}`, secret);
		expect(() => { verify(`${b64Header}.${b64Payload}.${sig}`, b64Secrets) }).toThrow(InvalidTokenError);
	});
});

