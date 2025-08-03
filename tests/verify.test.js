const { verify, sign } = require("../dist/passken.js");
// Mock data
const expiredToken = 
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6MX0.eyJpc3MiOiJ1c2VyMTIzIiwiaWF0IjoxNzQwNjA1NjUyLCJuYmYiOjE3NDA2MDU2NTMsImV4cCI6MTc0MDYwOTI1MiwidHlwIjoiYWNjZXNzIn0.xpEKqwDu7EOjkYfyZHxCOaikcKzU3zX5mMPu5Can7FU";
const TokenWithBadSecret =
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6MH0.eyJpc3MiOiJ1c2VyMTIzIiwiaWF0IjoxNzQwMjQ3OTEzLCJuYmYiOjE3NDAyNDc5MTQsImV4cCI6MTc0MDI1MTUxMywidHlwIjoiYWNjZXNzIn0.YTNmYzk3Nzc5NjA5MzY4ZjI0YTdhM2YwNzkyNTk3M2ZlNTM0ZTk2YjkxNWViZjBmYTc5NDliYzE3ZjhjMTIyMg";
const invalidAlgToken =
	"eyJhbGciOiJpbnZhbGlkIiwidHlwIjoiSldUIiwia2lkIjowfQ.eyJpc3MiOiJ1c2VyMTIzIiwiaWF0IjoxNzM4MjMxNTQ0LCJuYmYiOjE3MzgyMzE1NDUsImV4cCI6MTczODIzNTE0NH0.bFhIP9c9oNf2kAk2usDBWFI57Xt3IK_BhonaTMGB5Ew";
const invalidTypToken =
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IklOVkFMSUQiLCJraWQiOjB9.eyJpc3MiOiJ1c2VyMTIzIiwiaWF0IjoxNzM4MjMxNTk0LCJuYmYiOjE3MzgyMzE1OTUsImV4cCI6MTczODIzNTE5NH0.OX2EdvtBv5bQwblpmx0rmLZXWnn-zoGdClYPccRTQ80";
const invalidToken = "invalid.token.signature";
const b64Secrets = [
  '77-977-9dxlAaDLXv--_ve-_vX3vv73vv73vv70-AxnbuDBAKO-_ve-_vQMGWO-_vWrvv73vv70',
  'YS1zdHJpbmctc2VjcmV0LWF0LWxlYXN0LTI1Ni1iaXRzLWxvbmc'
];
const validToken = sign("user123", 3600, "access", b64Secrets);
const validTokenWithBadLength = sign("user123", 3600, "access", b64Secrets);

function wait(duration = 1000) {
	return new Promise((resolve) => setTimeout(resolve, duration));
}

describe("verify", () => {
	it("should throw error for a token with invalid segments", () => {
		expect(() => { verify("invalid.token", b64Secrets)}).toThrow();
	});

	it("should throw error for a token with invalid header", () => {
		expect(() => { verify(invalidToken, b64Secrets)}).toThrow();
	});

	it("should throw error for a token with invalid payload", () => {
		expect(() => { verify("valid.token.invalidPayload", b64Secrets)}).toThrow();
	});

	it("should throw error for a token with invalid algorithm", () => {
		expect(() => { verify(invalidAlgToken, b64Secrets)}).toThrow();
	});

	it("should throw error for a token with invalid typ", () => {
		expect(() => { verify(invalidTypToken, b64Secrets)}).toThrow();
	});

	it("should throw error for a token with invalid kid", () => {
		const invalidKidToken = "invalidKid.token.signature";
		expect(() => { verify(invalidKidToken, b64Secrets)}).toThrow();
	});

	it("should throw error for a token with nbf claim in the future", () => {
		expect(() => { verify(validToken, b64Secrets)}).toThrow();
	});

	it("should throw error for a token with exp claim in the past", () => {
		expect(() => { verify(expiredToken, b64Secrets)}).toThrow();
	});

  it("should throw error when secrets don't match", () => {
		expect(() => {verify(TokenWithBadSecret, b64Secrets, true)}).toThrow();
	});

	it("should throw error when secrets don't have the same size", () => {
		expect(() => {verify(validTokenWithBadLength, b64Secrets, true)}).toThrow();
	});

  it("should return the decoded token with exp claim in the past and ignoreExpiration = true", () => {
    const result = verify(expiredToken, b64Secrets, true);
		expect(result).toBeInstanceOf(Object);
	});

	it("should return the decoded token for a valid token", async () => {
		await wait(); // Wait to not throw nbf error
		const result = verify(validToken, b64Secrets);
		expect(result).toBeInstanceOf(Object);
	});
});
