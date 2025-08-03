import { compare, encrypt } from "../dist/passken.js";

describe("compare", () => {
	const password = "mySecret!/;6(A)Pwd";
	const wrongPassword = "wr0ngPa55word!";
	const emptyPassword = "";
	const secret = "8zYSoxUV36qy8tiIGytsA7qPdFecywiQs0sHBze_Skg";
	const hashedPassword = encrypt(password, secret);
  const hashedPassword2 = encrypt(password, secret);
	const otherHashedPassword = encrypt(password, secret);
  const otherHashedPassword2 = encrypt(password, secret);
	const anotherHashedPassword = encrypt(password, secret);
  const anotherHashedPassword2 = encrypt(password, secret);
  console.log("hashedPassword", hashedPassword);
  console.log("hashedPassword2", hashedPassword2);
  console.log("otherHashedPassword", otherHashedPassword);
  console.log("otherHashedPassword2", otherHashedPassword2);
  console.log("anotherHashedPassword", anotherHashedPassword);
  console.log("anotherHashedPassword2", anotherHashedPassword2);
  
	test("returns true when comparing with the right password", () => {
		expect(compare(password, hashedPassword, secret)).toBe(true);
	});

	test("returns true when comparing another hash with the right password", () => {
		expect(compare(password, otherHashedPassword, secret)).toBe(true);
	});

	test("returns true when comparing yet another hash with the right password", () => {
		expect(compare(password, anotherHashedPassword, secret)).toBe(true);
	});

	test("Test if two hashes of the same password are different ", () => {
		expect(hashedPassword).not.toBe(otherHashedPassword);
	});

	test("Test if two other hashes of the same password are different ", () => {
		expect(hashedPassword).not.toBe(anotherHashedPassword);
	});

	test("Test if two yet other hashes of the same password are different ", () => {
		expect(otherHashedPassword).not.toBe(anotherHashedPassword);
	});

	test("returns false when comparing with wrong password", () => {
		expect(compare(wrongPassword, hashedPassword, secret)).toBe(false);
	});

	test("returns false when comparing with an empty password", () => {
		expect(compare(emptyPassword, hashedPassword, secret)).toBe(false);
	});

	test("returns false when secret is empty", () => {
		expect(compare(password, hashedPassword, "")).toBe(false);
	});

	test("returns false when hashed password is empty", () => {
		expect(compare(password, "", secret)).toBe(false);
	});
});
