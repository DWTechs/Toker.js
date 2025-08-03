import { randomBytes } from "node:crypto";
import { b64Encode } from "@dwtechs/checkard";

/**
 * Generates a random string of the specified length, encoded in base64.
 *
 * @param {number} [length=32] - The length of the random string to generate. Defaults to 32 if not specified.
 * @returns {string} The generated random string encoded in base64.
 */
function create(length = 32): string {
	return b64Encode(randomBytes(length).toString("utf8"), true);
}

export { create };
