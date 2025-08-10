
[![License: MIT](https://img.shields.io/npm/l/@dwtechs/toker.svg?color=brightgreen)](https://opensource.org/licenses/MIT)
[![npm version](https://badge.fury.io/js/%40dwtechs%2Ftoker.svg)](https://www.npmjs.com/package/@dwtechs/toker)
[![last version release date](https://img.shields.io/github/release-date/DWTechs/Toker.js)](https://www.npmjs.com/package/@dwtechs/toker)
![Jest:coverage](https://img.shields.io/badge/Jest:coverage-100%25-brightgreen.svg)

- [Synopsis](#synopsis)
- [Support](#support)
- [Installation](#installation)
- [Usage](#usage)
  - [ES6](#es6)
  - [Configure](#configure)
- [API Reference](#api-reference)
- [Error Handling](#error-handling)
- [options](#options)
- [Express.js](#expressjs)
- [Contributors](#contributors)
- [Stack](#stack)


## Synopsis

**[Toker.js](https://github.com/DWTechs/Toker.js)** is an open source JWT management library for Node.js to sign, verify and parse bearer safely.

- 📦 Only 1 dependency to check inputs variables
- 🪶 Very lightweight
- 🧪 Thoroughly tested
- 🚚 Shipped as EcmaScrypt module
- 📝 Written in Typescript


## Support

- Node.js: 22

This is the oldest targeted versions.  
The library uses node:crypto.  


## Installation

```bash
$ npm i @dwtechs/toker
```


## Usage


Example of use with Express.js using ES6 module format

```javascript

import { compare, randomPwd, encrypt, sign, verify } from "@dwtechs/toker";

const { ACCESS_TOKEN_DURATION, REFRESH_TOKEN_DURATION, TOKEN_SECRET } = process.env;


function decodeAccessToken(req, res, next){
  let accessToken: string;
  try {
    accessToken = parseBearer(req.headers.authorization);
  } catch (err: any) {
    return next(err);
  }
  let decodedToken = null;
  try {
    decodedToken = verify(accessToken, [TOKEN_SECRET], true);
  } catch (err: any) {
    return next(err);
  }
  req.body.decodedAccessToken = decodedToken;
  next();
}

function refreshToken(req, res, next) {
  const iss = req.body.decodedAccessToken?.iss;
  const newAccessToken = sign(iss, ACCESS_TOKEN_DURATION, "access", secrets);
  const newRefreshToken = sign(iss, REFRESH_TOKEN_DURATION, "refresh", secrets);
  try {
    res.jwt = sign(req.userId, 3600, "access", [TOKEN_SECRET]);
    next();
  catch(err: any) {
    next(err);
  }
}

export {
  decodeAccessToken,
  refreshToken,
};

```


## API Reference


### Types
---

```javascript

// JWT
type Type = "access" | "refresh";

type Header = {
  alg: string,
  typ: string,
  kid: number,
};

type Payload = {
  iss: number | string,
  iat: number,
  nbf: number,
  exp: number,
  typ: Type,
}

```

### Methods
---

```javascript

// Default values
const header {
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
 * @throws {SecretDecodingError} Throws when the secret cannot be decoded from base64 - HTTP 500
 * 
 * // Examples that throw specific errors:
 * sign(null, 3600, "access", secrets); // Throws InvalidIssuerError
 * sign("user123", 3600, "access", []); // Throws InvalidSecretsError
 * sign("user123", -1, "access", secrets); // Throws InvalidDurationError
 * sign("user123", 3600, "access", ["invalid-base64!"]); // Throws SecretDecodingError
 * ```
 */
function sign( iss: number | string, 
               duration: number, 
               type: Type,
               b64Keys: string[]
             ): string {}

/**
 * Verifies a JWT token using the provided base64-encoded secrets.
 *
 * @param {string} token - The JWT token to verify.
 * @param {string[]} b64Keys - An array of base64-encoded secrets used for verification.
 * @param {boolean} ignoreExpiration - Optional flag to ignore the expiration time of the token. Defaults to false.
 * @returns {Payload} The decoded payload of the JWT token.
 * @throws {InvalidTokenError} Throws when the token is malformed, has invalid structure, algorithm, or type - HTTP 401
 * @throws {InvalidSecretsError} Throws when b64Keys is not an array or is empty - HTTP 500
 * @throws {TokenNotActiveError} Throws when the token cannot be used yet (nbf claim) - HTTP 401
 * @throws {TokenExpiredError} Throws when the token has expired (exp claim) - HTTP 401
 * @throws {SecretDecodingError} Throws when the secret is not valid base64 encoded - HTTP 500
 * @throws {InvalidSignatureError} Throws when the token signature is invalid - HTTP 401
 * 
 * // Examples that throw specific errors:
 * verify("invalid.token", secrets); // Throws InvalidTokenError
 * verify(validToken, []); // Throws InvalidSecretsError
 * verify(expiredToken, secrets); // Throws TokenExpiredError
 * verify(futureToken, secrets); // Throws TokenNotActiveError
 * verify(tamperedToken, secrets); // Throws InvalidSignatureError
 * verify(validToken, ["invalid-base64!"]); // Throws SecretDecodingError
 * ```
 */
function verify( token: string, 
                 b64Keys: string[],
                 ignoreExpiration = false
               ): Payload {}


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
function parseBearer(authorization: string | undefined): string {}

```

## Error Handling

Toker uses a structured error system that helps you identify and handle specific error cases. All errors extend from a base `TokerError` class.

### Error Classes Hierarchy

```
TokerError (abstract base class)
├── MissingAuthorizationError
├── InvalidBearerFormatError
├── InvalidTokenError
├── TokenExpiredError
├── TokenNotActiveError
├── InvalidSignatureError
├── InvalidIssuerError
├── InvalidSecretsError
├── InvalidDurationError
├── SecretDecodingError
```

### Common Properties

All error classes share these properties:

- `message`: Human-readable error description
- `code`: Human-readable error code (e.g., "TOKEN_EXPIRED")
- `statusCode`: Suggested HTTP status code (e.g., 401)
- `stack`: Error stack trace

### Using Error Handling

```typescript
import { sign, verify, parseBearer, TokenExpiredError, InvalidSignatureError } from "@dwtechs/passken";

try {
  // Attempt to verify a token
  const payload = verify(token, secrets);
  // Token is valid, proceed with the payload
} catch (error) {
  if (error instanceof TokenExpiredError) {
    // Handle expired token (e.g., prompt for reauthentication)
    console.log('Your session has expired. Please log in again.');
    console.log(`Status code: ${error.statusCode}`); // 401
  } else if (error instanceof InvalidSignatureError) {
    // Handle tampered token
    console.log('Invalid token signature detected');
    console.log(`Status code: ${error.statusCode}`); // 401
  } else {
    // Handle other verification errors
    console.log(`Token verification failed: ${error.message}`);
  }
}
```

### Error Types and HTTP Status Codes

| Error Class | Code | Status Code | Description |
|-------------|------|-------------|-------------|
| MissingAuthorizationError | MISSING_AUTHORIZATION | 401 | Authorization header is missing |
| InvalidBearerFormatError | INVALID_BEARER_FORMAT | 401 | Authorization header must be in the format 'Bearer <token>' |
| InvalidTokenError | INVALID_TOKEN | 401 | Invalid or malformed JWT token |
| TokenExpiredError | TOKEN_EXPIRED | 401 | JWT token has expired |
| TokenNotActiveError | TOKEN_NOT_ACTIVE | 401 | JWT token cannot be used yet (nbf claim) |
| InvalidSignatureError | INVALID_SIGNATURE | 401 | JWT token signature is invalid |
| InvalidIssuerError | INVALID_ISSUER | 400 | iss must be a string or a number |
| InvalidSecretsError | INVALID_SECRETS | 500 | b64Keys must be an array |
| InvalidDurationError | INVALID_DURATION | 400 | duration must be a positive number |
| SecretDecodingError | SECRET_DECODING_ERROR | 500 | could not decode the secret |

## Express.js

You can use Toker directly as Express.js middlewares using [@dwtechs/toker-express library](https://www.npmjs.com/package/@dwtechs/toker-express).
This way you do not have to write express controllers yourself to use **Toker**.


## Contributors

**Toker.js** is still in development and we would be glad to get all the help you can provide.
To contribute please read **[contributor.md](https://github.com/DWTechs/Toker.js/blob/main/contributor.md)** for detailed installation guide.


## Stack

| Purpose         |                    Choice                    |                             Motivation |
| :-------------- | :------------------------------------------: | -------------------------------------------------------------: |
| repository      |        [Github](https://github.com/)         |     hosting for software development version control using Git |
| package manager |     [npm](https://www.npmjs.com/get-npm)     |                                default node.js package manager |
| language        | [TypeScript](https://www.typescriptlang.org) | static type checking along with the latest ECMAScript features |
| module bundler  |      [Rollup.js](https://rollupjs.org)       |                        advanced module bundler for ES6 modules |
| unit testing    |          [Jest](https://jestjs.io/)          |                  delightful testing with a focus on simplicity |
