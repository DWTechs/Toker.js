import { getDigest } from "../dist/passken.js";

describe('getDigest', () => {
  test('returns a string', () => {
    expect(typeof getDigest()).toBe('string');
  });

  test('returns default digest', () => {
    const digest = getDigest();
    expect(digest).toBe('sha256'); // default digest
  });

  test('returns the same digest multiple times', () => {
    const digest1 = getDigest();
    const digest2 = getDigest();
    expect(digest1).toBe(digest2);
  });
});