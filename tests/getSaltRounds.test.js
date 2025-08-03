import { getSaltRounds } from "../dist/passken.js";

describe('getSaltRounds', () => {
  test('returns a number', () => {
    expect(typeof getSaltRounds()).toBe('number');
  });

  test('returns a positive number', () => {
    expect(getSaltRounds()).toBeGreaterThan(0);
  });

  test('returns the same salt rounds multiple times', () => {
    const saltRounds1 = getSaltRounds();
    const saltRounds2 = getSaltRounds();
    expect(saltRounds1).toBe(saltRounds2);
  });

  test('returns the default salt rounds', () => {
    const defaultSaltRounds = 12; // default salt rounds
    expect(getSaltRounds()).toBe(defaultSaltRounds);
  });
});