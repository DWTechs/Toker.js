# 0.2.0 (May 10th 2026)

- Now distributed as a native ES2022 ECMAScript module (ESM)
### Security
- Signature is now verified **before** checking `nbf`/`exp` claims, preventing timing-based information leakage on forged tokens
- Replaced `Math.random()` with `crypto.randomInt()` (CSPRNG) for key index selection
- JWT header is now built as a local object per call instead of a shared mutable module-level variable
- `kid` claim is now bounds-checked against the provided keys array in `verify`
- `b64Decode` errors in `sign` are now properly caught and rethrown as `InvalidBase64Secret`

### Dependencies
- Updated `@dwtechs/hashitaka` to 0.4.0
- Removed redundant `isBase64` pre-check in `verify`, now relying on hashitaka's own validation

### Performance
- `parseBearer` no longer allocates an intermediate array; uses `slice` + `trimStart` + `split` instead

### Cleanup
- Removed unused `isBase64` import from `@dwtechs/checkard`
- Removed explicit `Buffer` import (Node.js global)

# 0.1.2 (Feb 7th 2026)

- Fixed JWT token "not before" (nbf) claim timing. Tokens are now immediately valid upon issuance (nbf = iat)

# 0.1.1 (Sep 6th 2025)

- Updated dependencies in package.json:
  - @dwtechs/checkard to 3.5.1
  - @dwtechs/hashitaka to 0.3.1
- Improved error messages using Hashitaka and Checkard errors

# 0.1.0 (Aug 10th 2025)

- initial release
