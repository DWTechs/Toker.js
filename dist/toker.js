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

import { isString, isNumber, isArray, isPositive, isJson, isBase64 } from '@dwtechs/checkard';
import { b64Decode, b64Encode, hash, tse } from '@dwtechs/hashitaka';
import { Buffer } from 'buffer';

const TOKER_PREFIX = "Toker: ";
class TokerError extends Error {
    constructor(message) {
        super(message);
        this.name = this.constructor.name;
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, this.constructor);
        }
    }
}
class MissingAuthorizationError extends TokerError {
    constructor(message = `${TOKER_PREFIX}Authorization header is missing`) {
        super(message);
        this.code = "MISSING_AUTHORIZATION";
        this.statusCode = 401;
    }
}
class InvalidBearerFormatError extends TokerError {
    constructor(message = `${TOKER_PREFIX}Authorization header must be in the format 'Bearer <token>'`) {
        super(message);
        this.code = "INVALID_BEARER_FORMAT";
        this.statusCode = 401;
    }
}
class InvalidTokenError extends TokerError {
    constructor(message = `${TOKER_PREFIX}Invalid or malformed JWT token`) {
        super(message);
        this.code = "INVALID_TOKEN";
        this.statusCode = 401;
    }
}
class ExpiredTokenError extends TokerError {
    constructor(message = `${TOKER_PREFIX}JWT token has expired`) {
        super(message);
        this.code = "EXPIRED_TOKEN";
        this.statusCode = 401;
    }
}
class InactiveTokenError extends TokerError {
    constructor(message = `${TOKER_PREFIX}JWT token cannot be used yet (nbf claim)`) {
        super(message);
        this.code = "INACTIVE_TOKEN";
        this.statusCode = 401;
    }
}
class InvalidSignatureError extends TokerError {
    constructor(message = `${TOKER_PREFIX}JWT token signature is invalid`) {
        super(message);
        this.code = "INVALID_SIGNATURE";
        this.statusCode = 401;
    }
}
class InvalidIssuerError extends TokerError {
    constructor(message = `${TOKER_PREFIX}iss must be a string or a number`) {
        super(message);
        this.code = "INVALID_ISSUER";
        this.statusCode = 400;
    }
}
class InvalidSecretsError extends TokerError {
    constructor(message = `${TOKER_PREFIX}b64Keys must be an array`) {
        super(message);
        this.code = "INVALID_SECRETS";
        this.statusCode = 500;
    }
}
class InvalidDurationError extends TokerError {
    constructor(message = `${TOKER_PREFIX}duration must be a positive number`) {
        super(message);
        this.code = "INVALID_DURATION";
        this.statusCode = 400;
    }
}
class InvalidBase64Secret extends TokerError {
    constructor(message = `${TOKER_PREFIX}could not decode the base64 secret`) {
        super(message);
        this.code = "INVALID_BASE64_SECRET";
        this.statusCode = 500;
    }
}

const header = {
    alg: "HS256",
    typ: "JWT",
    kid: 0,
};
function sign(iss, duration, type, b64Keys) {
    if (!isString(iss, "!0") && !isNumber(iss, true))
        throw new InvalidIssuerError();
    if (!isArray(b64Keys, ">", 0))
        throw new InvalidSecretsError();
    if (!isNumber(duration, false) || !isPositive(duration, true))
        throw new InvalidDurationError();
    header.kid = randomPick(b64Keys);
    const b64Secret = b64Keys[header.kid];
    const secret = b64Decode(b64Secret, true);
    if (!secret)
        throw new InvalidBase64Secret();
    const iat = Math.floor(Date.now() / 1000);
    const nbf = iat + 1;
    const exp = duration > 60 ? iat + duration : iat + 60 * 15;
    const typ = type === "refresh" ? type : "access";
    const payload = { iss, iat, nbf, exp, typ };
    const b64Header = b64Encode(JSON.stringify(header));
    const b64Payload = b64Encode(JSON.stringify(payload));
    const b64Signature = hash(`${b64Header}.${b64Payload}`, secret);
    return `${b64Header}.${b64Payload}.${b64Signature}`;
}
function verify(token, b64Keys, ignoreExpiration = false) {
    const segments = token.split(".");
    if (segments.length !== 3)
        throw new InvalidTokenError();
    const [b64Header, b64Payload, b64Signature] = segments;
    if (!b64Header || !b64Payload || !b64Signature)
        throw new InvalidTokenError();
    if (!isArray(b64Keys, ">", 0))
        throw new InvalidSecretsError();
    const headerString = b64Decode(b64Header);
    const payloadString = b64Decode(b64Payload);
    if (!isJson(headerString) || !isJson(payloadString))
        throw new InvalidTokenError();
    const header = JSON.parse(headerString);
    const payload = JSON.parse(payloadString);
    if (header.alg !== "HS256")
        throw new InvalidTokenError();
    if (header.typ !== "JWT")
        throw new InvalidTokenError();
    if (!isString(header.kid, "!0") && !isNumber(header.kid, true))
        throw new InvalidTokenError();
    const now = Math.floor(Date.now() / 1000);
    if (payload.nbf && payload.nbf > now)
        throw new InactiveTokenError();
    if (!ignoreExpiration && payload.exp < now)
        throw new ExpiredTokenError();
    const b64Secret = b64Keys[header.kid];
    if (!isBase64(b64Secret, true))
        throw new InvalidBase64Secret();
    const secret = b64Decode(b64Secret);
    const expectedSignature = hash(`${b64Header}.${b64Payload}`, secret);
    const safeA = Buffer.from(expectedSignature);
    const safeB = Buffer.from(b64Signature);
    if (!tse(safeA, safeB))
        throw new InvalidSignatureError();
    return payload;
}
function parseBearer(authorization) {
    if (!authorization)
        throw new MissingAuthorizationError();
    if (!authorization.startsWith("Bearer "))
        throw new InvalidBearerFormatError();
    const parts = authorization.split(" ").filter(part => part.length > 0);
    if (parts.length < 2 || !parts[1])
        throw new InvalidBearerFormatError();
    return parts[1];
}
function randomPick(array) {
    return Math.floor(Math.random() * array.length);
}

export { ExpiredTokenError, InactiveTokenError, InvalidBase64Secret, InvalidBearerFormatError, InvalidDurationError, InvalidIssuerError, InvalidSecretsError, InvalidSignatureError, InvalidTokenError, MissingAuthorizationError, TokerError, parseBearer, sign, verify };
