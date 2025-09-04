// import { hash, tse } from "./hash.js"; 
import {
	isNumber,
	isString,
	isArray,
	isJson,
	isPositive,
  // isBase64, 
} from "@dwtechs/checkard";
import {
  hash,
  tse,
  b64Encode,
  b64Decode
} from "@dwtechs/hashitaka";
import type { Header, Payload, Type } from "./types";
import { 
  MissingAuthorizationError, 
  InvalidBearerFormatError,
  InvalidIssuerError,
  InvalidSecretsError,
  InvalidDurationError,
  // InvalidBase64Secret,
  InvalidTokenError,
  ExpiredTokenError,
  InactiveTokenError,
  InvalidSignatureError
} from "./errors.js";
import { Buffer } from "buffer";

const header: Header = {
  alg: "HS256", // HMAC using SHA-256 hash algorithm
  typ: "JWT", // JSON Web Token
  kid: 0, // Random key ID
};

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
	if (!isArray(b64Keys, ">", 0)) 
    throw new InvalidSecretsError();

	if (!isNumber(duration, false) || !isPositive(duration, true)) 
    throw new InvalidDurationError();

	header.kid = randomPick(b64Keys);
	const b64Secret = b64Keys[header.kid];

	const secret = b64Decode(b64Secret, true);
	// if (!secret)
  //   throw new InvalidBase64Secret();

	const iat = Math.floor(Date.now() / 1000); // Current time in seconds
	const nbf = iat + 1;
	const exp = duration > 60 ? iat + duration : iat + 60 * 15;
  const typ = type === "refresh" ? type : "access";
	const payload: Payload = { iss, iat, nbf, exp, typ };

	const b64Header = b64Encode(JSON.stringify(header));
	const b64Payload = b64Encode(JSON.stringify(payload));
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
	if (!isArray(b64Keys, ">", 0)) 
    throw new InvalidSecretsError();

	// Decode and parse the header and payload
	const headerString = b64Decode(b64Header);
	const payloadString = b64Decode(b64Payload);
	if (!isJson(headerString) || !isJson(payloadString))
    throw new InvalidTokenError();
	
	const header = JSON.parse(headerString);
	const payload = JSON.parse(payloadString);

	// Ensure the algorithm in the header is what we expect (HS256)
	if (header.alg !== "HS256")
    throw new InvalidTokenError();

	// Ensure the typ in the header is what we expect (JWT)
	if (header.typ !== "JWT")
    throw new InvalidTokenError();

	// Ensure the kid in the header is what we expect (string or number)
  if (!isString(header.kid, "!0") && !isNumber(header.kid, true))
    throw new InvalidTokenError();

	const now = Math.floor(Date.now() / 1000); // Current time in seconds since epoch

	// Validate "nbf" claim
	if (payload.nbf && payload.nbf > now)
    throw new InactiveTokenError();

	// validate the "exp" claim
	if (!ignoreExpiration && payload.exp < now)
    throw new ExpiredTokenError();

	const b64Secret = b64Keys[header.kid];
	// if (!isBase64(b64Secret, true))
  //   throw new InvalidBase64Secret();

	const secret = b64Decode(b64Secret);

	// Verify the signature
  const expectedSignature = hash(`${b64Header}.${b64Payload}`, secret);
  const safeA = Buffer.from(expectedSignature);
  const safeB = Buffer.from(b64Signature);

	if (!tse(safeA, safeB)) 
    throw new InvalidSignatureError();

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

  // Split by spaces and filter out empty strings to handle multiple spaces
  const parts = authorization.split(" ").filter(part => part.length > 0);
  
  if (parts.length < 2 || !parts[1])
    throw new InvalidBearerFormatError();

  return parts[1];

}

// Generate a random index based on an array length
function randomPick(array: string[]): number {
	return Math.floor(Math.random() * array.length);
}

export { 
  sign, 
  verify,
  parseBearer,
};
