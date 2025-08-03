
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
export abstract class PasskenError extends Error {
  abstract readonly code: string;
  abstract readonly statusCode: number;
}

export class MissingAuthorizationError extends PasskenError {
  readonly code: string;
  readonly statusCode: number;
}

export class InvalidBearerFormatError extends PasskenError {
  readonly code: string;
  readonly statusCode: number;
}

export class InvalidTokenError extends PasskenError {
  readonly code: string;
  readonly statusCode: number;
}

export class TokenExpiredError extends PasskenError {
  readonly code: string;
  readonly statusCode: number;
}

export class TokenNotActiveError extends PasskenError {
  readonly code: string;
  readonly statusCode: number;
}

export class InvalidSignatureError extends PasskenError {
  readonly code: string;
  readonly statusCode: number;
}

export class MissingClaimsError extends PasskenError {
  readonly code: string;
  readonly statusCode: number;
}

export class InvalidIssuerError extends PasskenError {
  readonly code: string;
  readonly statusCode: number;
}

export class InvalidSecretsError extends PasskenError {
  readonly code: string;
  readonly statusCode: number;
}

export class InvalidDurationError extends PasskenError {
  readonly code: string;
  readonly statusCode: number;
}

export class SecretDecodingError extends PasskenError {
  readonly code: string;
  readonly statusCode: number;
}

export class InvalidBase64SecretError extends PasskenError {
  readonly code: string;
  readonly statusCode: number;
}

declare function getSaltRounds(): number;
declare function setSaltRounds(rnds: number): boolean;
declare function getKeyLen(): number;
declare function setKeyLen(len: number): boolean;
declare function getDigest(): string;
declare function setDigest(func: string): boolean;
declare function getDigests(): string[];
declare function encrypt(pwd: string, b64Secret: string): string | false;
declare function compare(pwd: string, hash: string, b64Secret: string): boolean;
declare function randomSecret(length?: number): string;
declare function sign(iss: number | string, duration: number, type: Type, b64Keys: string[]): string;
declare function verify(token: string, b64Keys: string[], ignoreExpiration?: boolean): Payload;
declare function parseBearer(authorization: string | undefined): string;

export { 
  getSaltRounds,
  setSaltRounds,
  getKeyLen,
  setKeyLen,
  getDigest,
  setDigest,
  getDigests,
  encrypt,
  compare,
  randomSecret,
  sign,
  verify,
  parseBearer,
};
