import { randomPwd } from "../dist/passken.js";

describe("create", () => {
	test("should return a string", () => {
		const password = randomPwd();
		expect(typeof password).toBe("string");
	});

	test("should return a password of the correct length", () => {
		const length = 12;
		const password = randomPwd({ len: length });
		expect(password.length).toBe(length);
	});

	test("should include lowercase letters", () => {
		const password = randomPwd({ lcase: true });
		expect(/[a-z]/.test(password)).toBe(true);
	});

	test("should include uppercase letters", () => {
		const password = randomPwd({ ucase: true });
		expect(/[A-Z]/.test(password)).toBe(true);
	});

	test("should include numbers", () => {
		const password = randomPwd({ num: true });
		expect(/[0-9]/.test(password)).toBe(true);
	});

	test("should include symbols", () => {
		const password = randomPwd({ sym: true });
		expect(/[^a-zA-Z0-9]/.test(password)).toBe(true);
	});

	test("should exclude similar characters lI1oO0", () => {
		const password = randomPwd({ similarChars: true });
		expect(!/[lI1oO0]/.test(password)).toBe(true);
	});

	test("should generate a password with at least one of each required character type", () => {
		const password = randomPwd({
			strict: true,
			lcase: true,
			ucase: true,
			num: true,
			sym: true,
		});
		expect(/[a-z]/.test(password)).toBe(true);
		expect(/[A-Z]/.test(password)).toBe(true);
		expect(/[0-9]/.test(password)).toBe(true);
		expect(/[^a-zA-Z0-9]/.test(password)).toBe(true);
	});

	test("should generate a password with random characters", () => {
		const password1 = randomPwd();
		const password2 = randomPwd();
		expect(password1).not.toBe(password2);
	});

	test("should generate a complex password with all character types with specific length", () => {
		const options = {
			len: 20,
			num: true,
			ucase: true,
			lcase: true,
			sym: true,
			strict: true,
		};
		const password = randomPwd(options);
		const hasLowercase = /[a-z]/.test(password);
		const hasUppercase = /[A-Z]/.test(password);
		const hasNumber = /[0-9]/.test(password);
		const hasSymbol = /[^a-zA-Z0-9]/.test(password);
		expect(hasLowercase && hasUppercase && hasNumber && hasSymbol).toBe(true);
	});

	test("should handle extreme password lengths", () => {
		const shortPassword = randomPwd({ len: 1 });
		expect(shortPassword.length).toBe(12);

		const longPasswordLength = 1000; // Une valeur arbitrairement grande
		const longPassword = randomPwd({ len: longPasswordLength });
		expect(longPassword.length).toBe(12);
	});

	test("should ignore unsupported options", () => {
		const password = randomPwd({ unsupportedOption: true });
		expect(typeof password).toBe("string");
	});

	test("should handle contradictory options gracefully", () => {
		const password = randomPwd({
			strict: true,
			num: false,
			ucase: false,
			lcase: false,
			sym: false,
		});
		expect(typeof password).toBe("string");
	});
});
