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
export declare abstract class TokerError extends Error {
    abstract readonly code: string;
    abstract readonly statusCode: number;
    constructor(message: string, causedBy?: Error);
}
export declare class MissingAuthorizationError extends TokerError {
    readonly code = "MISSING_AUTHORIZATION";
    readonly statusCode = 401;
    constructor();
}
export declare class InvalidBearerFormatError extends TokerError {
    readonly code = "INVALID_BEARER_FORMAT";
    readonly statusCode = 401;
    constructor();
}
export declare class InvalidTokenError extends TokerError {
    readonly code = "INVALID_TOKEN";
    readonly statusCode = 401;
    constructor(causedBy?: Error);
}
export declare class ExpiredTokenError extends TokerError {
    readonly code = "EXPIRED_TOKEN";
    readonly statusCode = 401;
    constructor();
}
export declare class InactiveTokenError extends TokerError {
    readonly code = "INACTIVE_TOKEN";
    readonly statusCode = 401;
    constructor();
}
export declare class InvalidSignatureError extends TokerError {
    readonly code = "INVALID_SIGNATURE";
    readonly statusCode = 401;
    constructor(causedBy?: Error);
}
export declare class InvalidIssuerError extends TokerError {
    readonly code = "INVALID_ISSUER";
    readonly statusCode = 400;
    constructor();
}
export declare class InvalidSecretsError extends TokerError {
    readonly code = "INVALID_SECRETS";
    readonly statusCode = 500;
    constructor(causedBy?: Error);
}
export declare class InvalidDurationError extends TokerError {
    readonly code = "INVALID_DURATION";
    readonly statusCode = 400;
    constructor(causedBy?: Error);
}
export declare class InvalidBase64Secret extends TokerError {
    readonly code = "INVALID_BASE64_SECRET";
    readonly statusCode = 500;
    constructor(causedBy?: Error);
}

declare function sign(iss: number | string, duration: number, type: Type, b64Keys: string[]): string;
declare function verify(token: string, b64Keys: string[], ignoreExpiration?: boolean): Payload;
declare function parseBearer(authorization: string | undefined): string;

export { 
  sign,
  verify,
  parseBearer,
};
