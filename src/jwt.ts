import {
	isNumber,
	isInteger,
	isString,
	isArray,
	isPositive,
} from "@dwtechs/checkard";
import {
  hash,
  tse,
  b64Encode,
  b64Decode,
} from "@dwtechs/hashitaka";
import { randomInt } from "node:crypto";
import type { Header, Payload, Type } from "./types";
import { 
  MissingAuthorizationError, 
  InvalidBearerFormatError,
  InvalidIssuerError,
  InvalidSecretsError,
  InvalidDurationError,
  InvalidBase64Secret,
  InvalidTokenError,
  ExpiredTokenError,
  InactiveTokenError,
  InvalidSignatureError
} from "./errors.js";

const WHITESPACE = /\s+/;

/**
 * Signs a JWT (JSON Web Token) with the given parameters.
 *
 * @param {number|string} iss - The issuer of the token, which can be a string or a number.
 * @param {number} duration - The duration for which the token is valid, in seconds.
 * @param {Type} type - The type of the token, either "access" or "refresh".
 * @param {string[]} b64Keys - An array of base64 encoded secrets used for signing the token.
 * @returns {string} The signed JWT as a string.
 * @throws {InvalidIssuerError} Throws when `iss` is not a string or a number - HTTP 400
 * @throws {InvalidSecretsError} Throws when `b64Keys` is not an array or is empty - HTTP 500
 * @throws {InvalidDurationError} Throws when `duration` is not a positive number - HTTP 400
 * @throws {InvalidBase64Secret} Throws when the secret cannot be decoded from base64 - HTTP 500
 * 
 * // Examples that throw specific errors:
 * sign(null, 3600, "access", secrets); // Throws InvalidIssuerError
 * sign("user123", 3600, "access", []); // Throws InvalidSecretsError
 * sign("user123", -1, "access", secrets); // Throws InvalidDurationError
 * sign("user123", 3600, "access", ["invalid-base64!"]); // Throws InvalidBase64Secret
 * ```
 */
function sign(
	iss: number | string,
	duration: number,
  type: Type,
	b64Keys: string[],
): string {
	// Check iss is a string or a number
	if (!isString(iss, "!0") && !isNumber(iss, true))
		throw new InvalidIssuerError();

	// Check b64Keys is an array
	try {
		isArray(b64Keys, ">", 0, true); // throwErr = true
	} catch (err) {
		throw new InvalidSecretsError(err);
	}

	// Check duration is a positive number
	try {
		isPositive(duration, true, true);
	} catch (err) {
		throw new InvalidDurationError(err)
	}

	const kid = randomInt(0, b64Keys.length);
	const b64Secret = b64Keys[kid];

	let secret: string;
	try {
		secret = b64Decode(b64Secret, true);
	} catch (err) {
		throw new InvalidBase64Secret(err);
	}

	const iat = Math.floor(Date.now() / 1000); // Current time in seconds
	const nbf = iat;
	const exp = duration > 60 ? iat + duration : iat + 60 * 15;
  const typ = type === "refresh" ? type : "access";
	const payload: Payload = { iss, iat, nbf, exp, typ };

	const hdr: Header = { alg: "HS256", typ: "JWT", kid };
	const b64Header = b64Encode(JSON.stringify(hdr), true);
	const b64Payload = b64Encode(JSON.stringify(payload), true);
  const b64Signature = hash(`${b64Header}.${b64Payload}`, secret);

	return `${b64Header}.${b64Payload}.${b64Signature}`;
}

/**
 * Verifies a JWT token using the provided base64-encoded secrets.
 *
 * @param {string} token - The JWT token to verify.
 * @param {string[]} b64Keys - An array of base64-encoded secrets used for verification.
 * @param {boolean} ignoreExpiration - Optional flag to ignore the expiration time of the token. Defaults to false.
 * @returns {Payload} The decoded payload of the JWT token.
 * @throws {InvalidTokenError} Throws when the token is malformed, has invalid structure, algorithm, or type - HTTP 401
 * @throws {InvalidSecretsError} Throws when b64Keys is not an array or is empty - HTTP 500
 * @throws {InactiveTokenError} Throws when the token cannot be used yet (nbf claim) - HTTP 401
 * @throws {ExpiredTokenError} Throws when the token has expired (exp claim) - HTTP 401
 * @throws {InvalidBase64Secret} Throws when the secret is not valid base64 encoded - HTTP 500
 * @throws {InvalidSignatureError} Throws when the token signature is invalid - HTTP 401
 * 
 * // Examples that throw specific errors:
 * verify("invalid.token", secrets); // Throws InvalidTokenError
 * verify(validToken, []); // Throws InvalidSecretsError
 * verify(expiredToken, secrets); // Throws ExpiredTokenError
 * verify(futureToken, secrets); // Throws InactiveTokenError
 * verify(tamperedToken, secrets); // Throws InvalidSignatureError
 * verify(validToken, ["invalid-base64!"]); // Throws InvalidBase64Secret
 * ```
 */
function verify(token: string, b64Keys: string[], ignoreExpiration = false): Payload {
	const segments = token.split(".");
	if (segments.length !== 3)
    throw new InvalidTokenError();

	// Split the token into its parts
	const [b64Header, b64Payload, b64Signature] = segments;
	if (!b64Header || !b64Payload || !b64Signature) 
    throw new InvalidTokenError();

	// Check b64Keys is an array
	try {
		isArray(b64Keys, ">", 0, true); // throwErr = true
	} catch (err) {
		throw new InvalidSecretsError(err);
	}

	// Decode and parse the header and payload in a single pass
	let header: Header;
	let payload: Payload;

	try {
		header = JSON.parse(b64Decode(b64Header, true)) as Header;
		payload = JSON.parse(b64Decode(b64Payload, true)) as Payload;
	} catch (err) {
		throw new InvalidTokenError(err);
	}

	// Ensure the algorithm in the header is what we expect (HS256)
	if (header.alg !== "HS256")
    throw new InvalidTokenError();

	// Ensure the typ in the header is what we expect (JWT)
	if (header.typ !== "JWT")
    throw new InvalidTokenError();

	// Ensure the kid is a valid non-negative integer within bounds
	if (!isInteger(header.kid, true) || header.kid < 0 || header.kid >= b64Keys.length)
		throw new InvalidTokenError();

	const b64Secret = b64Keys[header.kid];
	let secret: string;
	try {
		secret = b64Decode(b64Secret, true);
	} catch (err) {
		throw new InvalidBase64Secret(err);
	}

	// Verify the signature before checking time claims
  const expectedSignature = hash(`${b64Header}.${b64Payload}`, secret);
  const safeA = Buffer.from(expectedSignature);
  const safeB = Buffer.from(b64Signature);

  let signaturesMatch: boolean;
	try {
		signaturesMatch = tse(safeA, safeB);
	} catch (err) {
		throw new InvalidSignatureError(err);
	}

  if (!signaturesMatch)
		throw new InvalidSignatureError();

	// Validate that exp is a finite number before any time-based check
	if (!Number.isFinite(payload.exp))
		throw new InvalidTokenError();

	const now = Math.floor(Date.now() / 1000); // Current time in seconds since epoch

	// Validate "nbf" claim
	if (payload.nbf && payload.nbf > now)
    throw new InactiveTokenError();

	// Validate "exp" claim
	if (!ignoreExpiration && payload.exp < now)
    throw new ExpiredTokenError();

	return payload;
}

/**
 * Extracts the JWT token from an HTTP Authorization header with Bearer authentication scheme.
 * 
 * This function validates that the authorization header follows the correct Bearer token format
 * ("Bearer <token>") and extracts the token portion for further processing.
 * 
 * @param {string | undefined} authorization - The Authorization header value from an HTTP request
 * @returns {string} The extracted JWT token as a string
 * @throws {MissingAuthorizationError} Throws when the authorization parameter is undefined - HTTP 401
 * @throws {InvalidBearerFormatError} Throws when the format is invalid - HTTP 401
 * 
 * @example
 * ```typescript
 * import { parseBearer, MissingAuthorizationError, InvalidBearerFormatError } from "@dwtechs/passken";
 * 
 * // Valid Bearer tokens
 * const validHeader = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
 * const token = parseBearer(validHeader);
 * // Returns: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 * 
 * // Handles multiple spaces
 * const headerWithSpaces = "Bearer    token123";
 * const token2 = parseBearer(headerWithSpaces);
 * // Returns: "token123"
 * 
 * // Examples that throw specific errors:
 * parseBearer(undefined); // Throws MissingAuthorizationError: "Authorization header is missing"
 * parseBearer(""); // Throws InvalidBearerFormatError: "Authorization header must be in the format 'Bearer <token>'"
 * parseBearer("Basic dXNlcjpwYXNz"); // Throws InvalidBearerFormatError
 * parseBearer("Bearer"); // Throws InvalidBearerFormatError
 * parseBearer("Bearer "); // Throws InvalidBearerFormatError
 * ```
 * 
 */

function parseBearer(authorization: string | undefined): string {
  
  if (!authorization)
    throw new MissingAuthorizationError();
  
  if (!authorization.startsWith("Bearer "))
    throw new InvalidBearerFormatError();

  const token = authorization.slice(7).trimStart().split(WHITESPACE)[0];

  if (!token)
    throw new InvalidBearerFormatError();

  return token;

}

export { 
  sign, 
  verify,
  parseBearer,
};
