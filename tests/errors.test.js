import {
  TokerError,
  MissingAuthorizationError,
  InvalidBearerFormatError,
  InvalidTokenError,
  ExpiredTokenError,
  InactiveTokenError,
  InvalidSignatureError,
  InvalidIssuerError,
  InvalidSecretsError,
  InvalidDurationError,
  InvalidBase64Secret,
} from "../dist/toker.js";

// Error classes that take no constructor arguments
const noArgErrors = [
  {
    Ctor: MissingAuthorizationError,
    code: "MISSING_AUTHORIZATION",
    statusCode: 401,
    message: "Toker: Authorization header is missing",
  },
  {
    Ctor: InvalidBearerFormatError,
    code: "INVALID_BEARER_FORMAT",
    statusCode: 401,
    message: "Toker: Authorization header must be in the format 'Bearer <token>'",
  },
  {
    Ctor: ExpiredTokenError,
    code: "EXPIRED_TOKEN",
    statusCode: 401,
    message: "Toker: JWT token has expired",
  },
  {
    Ctor: InactiveTokenError,
    code: "INACTIVE_TOKEN",
    statusCode: 401,
    message: "Toker: JWT token cannot be used yet (nbf claim)",
  },
  {
    Ctor: InvalidIssuerError,
    code: "INVALID_ISSUER",
    statusCode: 400,
    message: "Toker: iss must be a string or a number",
  },
];

// Error classes that accept an optional `causedBy` argument and chain the message
const chainableErrors = [
  {
    Ctor: InvalidTokenError,
    code: "INVALID_TOKEN",
    statusCode: 401,
    message: "Toker: Invalid or malformed JWT token",
  },
  {
    Ctor: InvalidSignatureError,
    code: "INVALID_SIGNATURE",
    statusCode: 401,
    message: "Toker: JWT token signature is invalid",
  },
  {
    Ctor: InvalidSecretsError,
    code: "INVALID_SECRETS",
    statusCode: 500,
    message: "Toker: b64Keys must be an array",
  },
  {
    Ctor: InvalidDurationError,
    code: "INVALID_DURATION",
    statusCode: 400,
    message: "Toker: duration must be a positive number",
  },
  {
    Ctor: InvalidBase64Secret,
    code: "INVALID_BASE64_SECRET",
    statusCode: 500,
    message: "Toker: could not decode the base64 secret",
  },
];

describe("errors", () => {

  describe("no-argument error classes", () => {
    test.each(noArgErrors)(
      "$Ctor.name exposes correct code, statusCode, name and message",
      ({ Ctor, code, statusCode, message }) => {
        const err = new Ctor();

        expect(err).toBeInstanceOf(TokerError);
        expect(err).toBeInstanceOf(Error);
        expect(err.code).toBe(code);
        expect(err.statusCode).toBe(statusCode);
        expect(err.name).toBe(`Toker: ${Ctor.name}`);
        expect(err.message).toBe(message);
      },
    );
  });

  describe("chainable error classes", () => {
    test.each(chainableErrors)(
      "$Ctor.name exposes correct code, statusCode, name and message with no cause",
      ({ Ctor, code, statusCode, message }) => {
        const err = new Ctor();

        expect(err).toBeInstanceOf(TokerError);
        expect(err.code).toBe(code);
        expect(err.statusCode).toBe(statusCode);
        expect(err.name).toBe(`Toker: ${Ctor.name}`);
        expect(err.message).toBe(message);
      },
    );

    test.each(chainableErrors)(
      "$Ctor.name chains an underlying Error cause into its message",
      ({ Ctor, message }) => {
        const cause = new Error("underlying failure");
        const err = new Ctor(cause);

        expect(err.message).toBe(`${message} - caused by: underlying failure`);
      },
    );

    test.each(chainableErrors)(
      "$Ctor.name chains a non-Error cause (string) into its message via String()",
      ({ Ctor, message }) => {
        const err = new Ctor("plain string cause");

        expect(err.message).toBe(`${message} - caused by: plain string cause`);
      },
    );

    test.each(chainableErrors)(
      "$Ctor.name chains a non-Error, non-string cause (object) into its message via String()",
      ({ Ctor, message }) => {
        const cause = { reason: "boom" };
        const err = new Ctor(cause);

        expect(err.message).toBe(`${message} - caused by: ${String(cause)}`);
      },
    );
  });

  describe("TokerError base class", () => {
    test("all custom errors are instances of TokerError and Error", () => {
      const errors = [
        new MissingAuthorizationError(),
        new InvalidBearerFormatError(),
        new InvalidTokenError(),
        new ExpiredTokenError(),
        new InactiveTokenError(),
        new InvalidSignatureError(),
        new InvalidIssuerError(),
        new InvalidSecretsError(),
        new InvalidDurationError(),
        new InvalidBase64Secret(),
      ];

      for (const err of errors) {
        expect(err).toBeInstanceOf(TokerError);
        expect(err).toBeInstanceOf(Error);
      }
    });

    test("stack trace is captured", () => {
      const err = new InvalidTokenError();
      expect(typeof err.stack).toBe("string");
      expect(err.stack.length).toBeGreaterThan(0);
    });
  });

});
