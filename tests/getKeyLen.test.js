import { getKeyLen } from "../dist/passken.js";

describe('getKeyLen', () => {
  test('returns a number', () => {
    expect(typeof getKeyLen()).toBe('number');
  });

  test('returns a positive number', () => {
    expect(getKeyLen()).toBeGreaterThan(0);
  });

  test('returns the same key length multiple times', () => {
    const keyLen1 = getKeyLen();
    const keyLen2 = getKeyLen();
    expect(keyLen1).toBe(keyLen2);
  });

  test('returns the correct default key length', () => {
    const expectedKeyLen = 64; // expected key length for sha256
    expect(getKeyLen()).toBe(expectedKeyLen);
  });
});