/**
 * Custom error classes for Passken JWT authentication library
 */

/**
 * Prefix for all Toker error messages
 */
const TOKER_PREFIX = "Toker: ";

/**
 * Chains the current error message with the underlying error message
 * @param err The underlying error that caused this error
 */
function chainMessage(message: string, err: Error): string {
  return `${message} - caused by: ${err.message}`;
}

/**
 * Base class for all Toker authentication errors
 */
export abstract class TokerError extends Error {
  abstract readonly code: string;
  abstract readonly statusCode: number;
  
  constructor(message: string, causedBy?: Error) {
    super(causedBy ? chainMessage(message, causedBy) : message);
    this.name = `${TOKER_PREFIX}${this.constructor.name}`;
    
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

/**
 * Error thrown when the Authorization header is missing or undefined
 * 
 * @example
 * ```typescript
 * try {
 *   parseBearer(undefined);
 * } catch (error) {
 *   if (error instanceof MissingAuthorizationError) {
 *     // Handle missing authorization - typically 401 Unauthorized
 *     console.log(error.message); // "Authorization header is missing"
 *   }
 * }
 * ```
 */
export class MissingAuthorizationError extends TokerError {
  readonly code = "MISSING_AUTHORIZATION";
  readonly statusCode = 401;

  constructor() {
    super(`${TOKER_PREFIX}Authorization header is missing`);
  }
}

/**
 * Error thrown when the Authorization header exists but is not in the correct Bearer token format
 * 
 * @example
 * ```typescript
 * try {
 *   parseBearer("Basic dXNlcjpwYXNz");
 * } catch (error) {
 *   if (error instanceof InvalidBearerFormatError) {
 *     // Handle invalid format - typically 401 Unauthorized
 *     console.log(error.message); // "Authorization header must be in the format 'Bearer <token>'"
 *   }
 * }
 * ```
 */
export class InvalidBearerFormatError extends TokerError {
  readonly code = "INVALID_BEARER_FORMAT";
  readonly statusCode = 401;

  constructor() {
    super(`${TOKER_PREFIX}Authorization header must be in the format 'Bearer <token>'`);
  }
}

/**
 * Error thrown when JWT token verification fails
 * 
 * @example
 * ```typescript
 * try {
 *   verify(token, secrets);
 * } catch (error) {
 *   if (error instanceof InvalidTokenError) {
 *     // Handle invalid token - typically 401 Unauthorized
 *     console.log(error.message); // "Invalid or malformed JWT token"
 *   }
 * }
 * ```
 */
export class InvalidTokenError extends TokerError {
  readonly code = "INVALID_TOKEN";
  readonly statusCode = 401;

  constructor(causedBy?: Error) {
    super(`${TOKER_PREFIX}Invalid or malformed JWT token`, causedBy);
  }
}

/**
 * Error thrown when JWT token has expired
 * 
 * @example
 * ```typescript
 * try {
 *   verify(token, secrets, false); // Don't ignore expiration
 * } catch (error) {
 *   if (error instanceof ExpiredTokenError) {
 *     // Handle expired token - typically 401 Unauthorized
 *     console.log(error.message); // "JWT token has expired"
 *   }
 * }
 * ```
 */
export class ExpiredTokenError extends TokerError {
  readonly code = "EXPIRED_TOKEN";
  readonly statusCode = 401;

  constructor() {
    super(`${TOKER_PREFIX}JWT token has expired`);
  }
}

/**
 * Error thrown when JWT token cannot be used yet (nbf claim)
 * 
 * @example
 * ```typescript
 * try {
 *   verify(token, secrets);
 * } catch (error) {
 *   if (error instanceof InactiveTokenError) {
 *     // Handle token not yet active - typically 401 Unauthorized
 *     console.log(error.message); // "JWT token cannot be used yet (nbf claim)"
 *   }
 * }
 * ```
 */
export class InactiveTokenError extends TokerError {
  readonly code = "INACTIVE_TOKEN";
  readonly statusCode = 401;

  constructor() {
    super(`${TOKER_PREFIX}JWT token cannot be used yet (nbf claim)`);
  }
  
}

/**
 * Error thrown when JWT token signature verification fails
 */
export class InvalidSignatureError extends TokerError {
  readonly code = "INVALID_SIGNATURE";
  readonly statusCode = 401;

  constructor(causedBy?: Error) {
    super(`${TOKER_PREFIX}JWT token signature is invalid`, causedBy);
  }
}

/**
 * Error thrown when JWT token is missing required claims (like iss)
 */
// export class MissingClaimsError extends TokerError {
//   readonly code = "MISSING_CLAIMS";
//   readonly statusCode = 400;

//   constructor(message = `${TOKER_PREFIX}JWT token is missing required claims`) {
//     super(message);
//   }
// }

/**
 * Error thrown when the issuer (iss) parameter is invalid during JWT signing
 * 
 * @example
 * ```typescript
 * try {
 *   sign(null, 3600, "access", secrets);
 * } catch (error) {
 *   if (error instanceof InvalidIssuerError) {
 *     console.log(error.message); // "iss must be a string or a number"
 *   }
 * }
 * ```
 */
export class InvalidIssuerError extends TokerError {
  readonly code = "INVALID_ISSUER";
  readonly statusCode = 400;

  constructor() {
    super(`${TOKER_PREFIX}iss must be a string or a number`);
  }
}

/**
 * Error thrown when the secrets array is invalid during JWT signing
 * 
 * @example
 * ```typescript
 * try {
 *   sign("user123", 3600, "access", []);
 * } catch (error) {
 *   if (error instanceof InvalidSecretsError) {
 *     console.log(error.message); // "b64Keys must be an array"
 *   }
 * }
 * ```
 */
export class InvalidSecretsError extends TokerError {
  readonly code = "INVALID_SECRETS";
  readonly statusCode = 500;

  constructor(causedBy?: Error) {
    super(`${TOKER_PREFIX}b64Keys must be an array`, causedBy);
  }

}

/**
 * Error thrown when the duration parameter is invalid during JWT signing
 * 
 * @example
 * ```typescript
 * try {
 *   sign("user123", -1, "access", secrets);
 * } catch (error) {
 *   if (error instanceof InvalidDurationError) {
 *     console.log(error.message); // "duration must be a positive number"
 *   }
 * }
 * ```
 */
export class InvalidDurationError extends TokerError {
  readonly code = "INVALID_DURATION";
  readonly statusCode = 400;

  constructor(causedBy?: Error) {
    super(`${TOKER_PREFIX}duration must be a positive number`, causedBy);
  }

}

/**
 * Error thrown when the secret cannot be decoded during JWT signing
 * 
 * @example
 * ```typescript
 * try {
 *   sign("user123", 3600, "access", ["invalid-base64"]);
 * } catch (error) {
 *   if (error instanceof InvalidBase64Secret) {
 *     console.log(error.message); // "could not decode the secret"
 *   }
 * }
 * ```
 */
export class InvalidBase64Secret extends TokerError {
  readonly code = "INVALID_BASE64_SECRET";
  readonly statusCode = 500;

  constructor(causedBy?: Error) {
    super(`${TOKER_PREFIX}could not decode the base64 secret`, causedBy);
  }
}
