# 0.2.2 (Jul 09th 2026)

- Updated dependencies :
  - @dwtechs/checkard to 3.6.1

# 0.2.1 (May 10th 2026)

- `exp` claim is now validated as a finite number before any time-based comparison, preventing crafted payloads (`null`, strings, `Infinity`) from bypassing expiration checks
- `kid` header field is now validated as a strict integer using `isInteger()` from `@dwtechs/checkard`, preventing float values (e.g. `0.5`) from producing an out-of-bounds array access
- Fixed `causedBy` parameter type in error class declarations
- Eliminated redundant JSON parsing in `verify()`: header and payload are now decoded and parsed in a single pass
- Hoisted the `/\s+/` regex in `parseBearer()` to a module-level constant to avoid recompilation on every call

# 0.2.0 (May 09th 2026)

- Now distributed as a native ES2022 ECMAScript module (ESM)
- Signature is now verified **before** checking `nbf`/`exp` claims, preventing timing-based information leakage on forged tokens
- Updated dependencies :
  - @dwtechs/hashitaka to 0.4.0
  - @dwtechs/checkard to 3.6.0

# 0.1.2 (Feb 7th 2026)

- Fixed JWT token "not before" (nbf) claim timing. Tokens are now immediately valid upon issuance (nbf = iat)

# 0.1.1 (Sep 6th 2025)

- Updated dependencies :
  - @dwtechs/checkard to 3.5.1
  - @dwtechs/hashitaka to 0.3.1
- Improved error messages using Hashitaka and Checkard errors

# 0.1.0 (Aug 10th 2025)

- initial release
