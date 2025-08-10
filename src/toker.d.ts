
export type Type = "access" | "refresh";
export type Header = {
  alg: string;
  typ: string;
  kid: number;
};
export type Payload = {
  iss: number | string;
  iat: number;
  nbf: number;
  exp: number;
  typ: Type;
};

// Error classes
export abstract class TokerError extends Error {
  abstract readonly code: string;
  abstract readonly statusCode: number;
}

export class MissingAuthorizationError extends TokerError {
  readonly code: string;
  readonly statusCode: number;
}

export class InvalidBearerFormatError extends TokerError {
  readonly code: string;
  readonly statusCode: number;
}

export class InvalidTokenError extends TokerError {
  readonly code: string;
  readonly statusCode: number;
}

export class ExpiredTokenError extends TokerError {
  readonly code: string;
  readonly statusCode: number;
}

export class InactiveTokenError extends TokerError {
  readonly code: string;
  readonly statusCode: number;
}

export class InvalidSignatureError extends TokerError {
  readonly code: string;
  readonly statusCode: number;
}

// export class MissingClaimsError extends TokerError {
//   readonly code: string;
//   readonly statusCode: number;
// }

export class InvalidIssuerError extends TokerError {
  readonly code: string;
  readonly statusCode: number;
}

export class InvalidSecretsError extends TokerError {
  readonly code: string;
  readonly statusCode: number;
}

export class InvalidDurationError extends TokerError {
  readonly code: string;
  readonly statusCode: number;
}

export class InvalidBase64Secret extends TokerError {
  readonly code: string;
  readonly statusCode: number;
}

declare function sign(iss: number | string, duration: number, type: Type, b64Keys: string[]): string;
declare function verify(token: string, b64Keys: string[], ignoreExpiration?: boolean): Payload;
declare function parseBearer(authorization: string | undefined): string;

export { 
  sign,
  verify,
  parseBearer,
};
