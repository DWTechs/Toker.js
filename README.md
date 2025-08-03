
[![License: MIT](https://img.shields.io/npm/l/@dwtechs/passken.svg?color=brightgreen)](https://opensource.org/licenses/MIT)
[![npm version](https://badge.fury.io/js/%40dwtechs%2Fpassken.svg)](https://www.npmjs.com/package/@dwtechs/passken)
[![last version release date](https://img.shields.io/github/release-date/DWTechs/Passken.js)](https://www.npmjs.com/package/@dwtechs/passken)
![Jest:coverage](https://img.shields.io/badge/Jest:coverage-100%25-brightgreen.svg)
[![minified size](https://img.shields.io/bundlephobia/min/@dwtechs/passken?color=brightgreen)](https://www.npmjs.com/package/@dwtechs/passken)

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

**[Passken.js](https://github.com/DWTechs/Passken.js)** is an open source password and JWT management library for Node.js to create, encrypt and compare safely.

- Only 1 dependency to check inputs variables
- Very lightweight
- Thoroughly tested
- EcmaScrypt module
- Works in Javascript and Typescript
- Written in Typescript


## Support

- Node.js: 22

This is the oldest targeted versions.  
The library uses node:crypto.  


## Installation

```bash
$ npm i @dwtechs/passken
```


## Usage


### ES6 / TypeScript

Example of use with Express.js using ES6 module format

```javascript

import { compare, randomPwd, encrypt, sign, verify } from "@dwtechs/passken";

const { PWD_SECRET, TOKEN_SECRET } = process.env;

/**
 * This function checks if a user-provided password matches a stored hashed password in a database.
 * It takes a request object req and a response object res as input, and uses a pass service to compare the password.
 * If the password is correct, it calls the next() function to proceed with the request.
 * If the password is incorrect or missing, it calls next() with an error status and message.
 */
function comparePwd(req, res, next) {
  
  const pwd = req.body.pwd; // from request
  const hash = req.user.hash; //from db
  if (compare(pwd, hash, PWD_SECRET))
    return next();
  
  return next({ status: 401, msg: "Wrong password" });

}


/**
 * Generates a random password for a user and encrypts it.
 */
function createPwd(req, res, next) {

  const user = req.body.user;
  const options = {
    len: 14,
    num: true,
    ucase: true,
    lcase: true,
    sym: true,
    strict: true,
    similarChars: true,
  };
  user.pwd = randomPwd(options);
  user.pwdHash = encrypt(user.pwd, PWD_SECRET);
  next();

}

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
}

// JWT
function refreshToken(req, res, next) {
  const iss = req.body.decodedAccessToken?.iss;
  const newAccessToken = sign(iss, ACCESS_TOKEN_DURATION, "access", secrets);
  const newRefreshToken = sign(iss, REFRESH_TOKEN_DURATION, "refresh", secrets);
  res.jwt = sign(req.userId, 3600, "access", [TOKEN_SECRET]);
  next();
}

export {
  comparePwd,
  createPwd,
  decodeAccessToken,
  refreshToken,
};

```


### Configure

Passken will start with the following default password configuration : 

```Javascript
  Options = {
    len: 12,
    num: true,
    ucase: true,
    lcase: true,
    sym: false,
    strict: true,
    similarChars: false,
  };
```

### Environment variables

You can update password default configuration using the following environment variables :  

```bash
  PWD_LENGTH,
  PWD_NUMBERS,
  PWD_UPPERCASE,
  PWD_LOWERCASE,
  PWD_SYMBOLS,
  PWD_STRICT,
  PWD_SIMILAR_CHARS,
```

These environment variables will update the default values of the lib at start up.
With this strategy you do not need to send options parameter in the randomPwd() method anymore.


## API Reference


### Types
---

```javascript
// Password
type Options = {
  len: number,
  num: boolean,
  ucase: boolean,
  lcase: boolean,
  sym: boolean,
  strict: boolean,
  similarChars: boolean,
};

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

#### Password

```javascript

// Default values
let saltRnds = 12
let digest = "sha256";
let keyLen = 64;

/**
 * Returns the number of salt rounds used for hashing.
 *
 * @returns {number} The number of salt rounds.
 */
function getSaltRounds(): number {}

/**
 * Sets the number of salt rounds for hashing.
 *
 * @param {number} rnds - The number of salt rounds to set. Must be a valid integer between 12 and 100.
 * @returns {boolean} True if the salt rounds were successfully set, otherwise false.
 */
function setSaltRounds(rnds: number): boolean {} // between 12 and 100

/**
 * Returns the key length used for hashing.
 *
 * @returns {number} The key length.
 */
function getKeyLen(): number {}

/**
 * Sets the key length to the specified value for hashing.
 *
 * @param {number} len - The desired key length. Must be a valid integer between 2 and 256.
 * @returns {boolean} True if the key length was successfully set; otherwise false.
 */
function setKeyLen(r: number): boolean {} // between 2 and 256

/**
 * Returns the hash function used for hashing.
 *
 * @returns {string} The hash function.
 */
function getDigest(): string {}

/**
 * Sets the hash function used for hashing.
 * the list of available digests is returned by getDigests()
 *
 * @param {string} func - The hash function. Must be a valid value from the list of available hash functions.
 * @returns {boolean} True if the hash function was successfully set; otherwise false.
 */
function setDigest(d: string): boolean {}

/**
 * Returns the list of available hash functions.
 *
 * @returns {string[]} The list of available hash functions.
 */
function getDigests(): string[] {}

/**
 * Encrypts a password using a base64 encoded secret.
 *
 * @param {string} pwd - The password to encrypt. Must be a non-empty string.
 * @param {string} b64Secret - The base64 encoded secret used for encryption. Must be a valid base64 encoded string.
 * @returns {string} The encrypted password as a hex string prefixed with a random salt.
 * @throws {InvalidPasswordError} If `pwd` is not a non-empty string.
 * @throws {InvalidBase64SecretError} If `b64Secret` is not a valid base64 encoded string.
 */
function encrypt( pwd: string, 
                  b64Secret: string
                ): string | false {}

/**
 * Compares a plaintext password with a hashed password using a secret.
 *
 * @param {string} pwd - The plaintext password to compare.
 * @param {string} hash - The hashed password to compare against.
 * @param {string} b64Secret - The base64 encoded secret used for hashing.
 * @returns {boolean} true if the password matches the hash, false otherwise.
 */
function compare( pwd: string, 
                  hash: string,
                  b64Secret: string
                ): boolean {}

/**
 * Generate a random password.
 * 
 * @param {Partial<Options>} opts - The options to generate the password.
 * @returns {string} The generated password.
 * 
 */
function randomPwd(opts: Partial<Options> = defOpts): string {}

```


## options

Any of these can be passed into the options object for each function.

| Name         | type    |              Description                                     | Default |  
| :----------- | :------ | :----------------------------------------------------------- | :------ |
| len	         | Integer | Minimal length of password.                                  | 12      |
| num*	       | Boolean | use numbers in password.                                     | true    |
| sym*	       | Boolean | use symbols in password                                      | true    |
| lcase*	     | Boolean | use lowercase in password                                    | true    |
| ucase*	     | Boolean | use uppercase letters in password.                           | true    |
| strict	     | Boolean | password must include at least one character from each pool.	| true    |
| similarChars | Boolean | allow close looking chars.                                   | false   | 

*At least one of those options must be true.  

- Symbols used : !@#%*_-+=:?><./()  
- Similar characters : l, I, 1, o, O, 0


#### JWT

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
             ): string;

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
               ): Payload;


/**
 * Verifies a JWT token using the provided base64-encoded secrets.
 *
 * @param {string} token - The JWT token to verify.
 * @param {string[]} b64Keys - An array of base64-encoded secrets used for verification.
 * @param {boolean} ignoreExpiration - Optional flag to ignore the expiration time of the token. Defaults to false.
 * @returns {Payload} The decoded payload of the JWT token as a string.
 * @throws Will throw an error if the token does not have 3 segments.
 * @throws Will throw an error if the token does not have a header, payload, and signature.
 * @throws Will throw an error if b64Keys is not an array.
 * @throws Will throw an error if the header or payload are not valid JSON.
 * @throws Will throw an error if the algorithm or token type are not supported.
 * @throws Will throw an error if the kid in the header is invalid.
 * @throws Will throw an error if the token cannot be used yet (nbf claim).
 * @throws Will throw an error if the token has expired (exp claim).
 * @throws Will throw an error if the secret is not valid base64 url-sale encoded.
 * @throws Will throw an error if the signature is invalid.
 */
function verify(token: string, b64Keys: string[], ignoreExpiration = false): Payload;

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
function parseBearer(authorization: string | undefined): string;

```

#### Secret

```javascript

/**
 * Generates a random string of the specified length, encoded in base64.
 *
 * @param {number} [length=32] - The length of the random string to generate. Defaults to 32 if not specified.
 * @returns {string} The generated random string encoded in base64.
 */
randomSecret(length = 32): string

```

## Error Handling

Passken uses a structured error system that helps you identify and handle specific error cases. All errors extend from a base `PasskenError` class.

### Error Classes Hierarchy

```
PasskenError (abstract base class)
├── MissingAuthorizationError
├── InvalidBearerFormatError
├── InvalidTokenError
├── TokenExpiredError
├── TokenNotActiveError
├── InvalidSignatureError
├── MissingClaimsError
├── InvalidIssuerError
├── InvalidSecretsError
├── InvalidDurationError
├── SecretDecodingError
├── HashLengthMismatchError
├── InvalidPasswordError
└── InvalidBase64SecretError
```

### Common Properties

All error classes share these properties:

- `message`: Human-readable error description
- `code`: Machine-readable error code (e.g., "TOKEN_EXPIRED")
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
| MissingClaimsError | MISSING_CLAIMS | 400 | JWT token is missing required claims |
| InvalidIssuerError | INVALID_ISSUER | 400 | iss must be a string or a number |
| InvalidSecretsError | INVALID_SECRETS | 500 | b64Keys must be an array |
| InvalidDurationError | INVALID_DURATION | 400 | duration must be a positive number |
| SecretDecodingError | SECRET_DECODING_ERROR | 500 | could not decode the secret |
| HashLengthMismatchError | HASH_LENGTH_MISMATCH | 400 | Hashes must have the same byte length |
| InvalidPasswordError | INVALID_PASSWORD | 400 | pwd must be a non-empty string |
| InvalidBase64SecretError | INVALID_BASE64_SECRET | 400 | b64Secret must be a base64 encoded string |

## Express.js

You can use Passken directly as Express.js middlewares using [@dwtechs/passken-express library](https://www.npmjs.com/package/@dwtechs/passken-express).
This way you do not have to write express controllers yourself to use **Passken**.


## Contributors

**Passken.js** is still in development and we would be glad to get all the help you can provide.
To contribute please read **[contributor.md](https://github.com/DWTechs/Passken.js/blob/main/contributor.md)** for detailed installation guide.


## Stack

| Purpose         |                    Choice                    |                             Motivation |
| :-------------- | :------------------------------------------: | -------------------------------------------------------------: |
| repository      |        [Github](https://github.com/)         |     hosting for software development version control using Git |
| package manager |     [npm](https://www.npmjs.com/get-npm)     |                                default node.js package manager |
| language        | [TypeScript](https://www.typescriptlang.org) | static type checking along with the latest ECMAScript features |
| module bundler  |      [Rollup.js](https://rollupjs.org)       |                        advanced module bundler for ES6 modules |
| unit testing    |          [Jest](https://jestjs.io/)          |                  delightful testing with a focus on simplicity |
