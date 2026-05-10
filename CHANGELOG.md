# 0.2.0 (May 10th 2026)

- Now distributed as a native ES2022 ECMAScript module (ESM)
### Security
- Signature is now verified **before** checking `nbf`/`exp` claims, preventing timing-based information leakage on forged tokens
### Dependencies
- Updated `@dwtechs/hashitaka` to 0.4.0

# 0.1.2 (Feb 7th 2026)

- Fixed JWT token "not before" (nbf) claim timing. Tokens are now immediately valid upon issuance (nbf = iat)

# 0.1.1 (Sep 6th 2025)

- Updated dependencies in package.json:
  - @dwtechs/checkard to 3.5.1
  - @dwtechs/hashitaka to 0.3.1
- Improved error messages using Hashitaka and Checkard errors

# 0.1.0 (Aug 10th 2025)

- initial release
