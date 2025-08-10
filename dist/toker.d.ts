/*
MIT License

Copyright (c) 2022 DWTechs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

https://github.com/DWTechs/Toker.js
*/


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

export class TokenExpiredError extends TokerError {
  readonly code: string;
  readonly statusCode: number;
}

export class TokenNotActiveError extends TokerError {
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

export class SecretDecodingError extends TokerError {
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
