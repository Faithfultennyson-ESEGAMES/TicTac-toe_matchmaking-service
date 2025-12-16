# Changelog

All notable changes to the `matchmaking-server` will be documented in this file.

## [Unreleased] - 2024-05-21

### Fixed
-   **Webhook Authentication:** Corrected HMAC signature verification to use the `X-Signature` header (as `x-signature` in Express) sent by the `game-server`. This resolves authentication failures for the `/session-closed` webhook.
-   **Webhook Payload Parsing:** Fixed a critical bug in the `/session-closed` handler that looked for `session_id` (snake_case) instead of the correct `sessionId` (camelCase) in the payload. This ensures active game sessions are now properly cleared.

### Added
-   **Documentation:** Created a comprehensive `README.md` with detailed instructions for setup, configuration, environment variables, client integration, and API endpoint usage.
