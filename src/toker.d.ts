
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
