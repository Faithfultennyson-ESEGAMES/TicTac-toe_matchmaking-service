# Matchmaking Server for ESEGAMES

This Node.js application is the central matchmaking service for the ESEGAMES platform. It manages a player queue, forms matches, and communicates with the `game-server` to create game sessions. It maintains a simple state of the player queue and active games using a local JSON file (`db.json`).

## High-Level Workflow

1.  **Client Connection**: A player connects to this server via Socket.IO.
2.  **Match Request**: The client emits a `request-match` event with `playerId`, `playerName`, `gameType`, and `mode`.
3.  **Queuing**: The player is added to a queue. If two players are present, a match is formed.
4.  **Session Creation**: The server sends a signed, server-to-server `POST` request to the appropriate game server (`dice` or `tictactoe`) `/start` endpoint using the selected mode.
5.  **Receive Game Details**: The `game-server` responds with a `sessionId` and a `joinUrl`. This response is verified using a shared HMAC secret.
6.  **Notify Players**: The server emits a `match-found` event to both players, providing the `sessionId` and `joinUrl`.
7.  **Client Redirect**: The clients construct the final game URL using the received data and redirect the players to the game client.
8.  **Session Closure**: After the game ends, the `game-server` sends a `POST /session-closed` webhook back to this server.
9.  **State Cleanup**: This server validates the webhook, removes the players from the active games list, and emits a `session-ended` event to notify the clients they can play again.

---

## Getting Started

### 1. Installation

Clone the repository and install the dependencies.

```bash
npm install
```

### 2. Configuration (`.env` file)

Create a `.env` file in the `matchmaking-server/` directory. This is essential for configuring the server.

```bash
# .env

# Port for the matchmaking server.
PORT=3330

# Dice game-server URL (e.g., http://localhost:3001).
DICE_GAME_SERVER_URL=http://localhost:3001

# TicTacToe game-server URL (e.g., http://localhost:5500).
TICTACTOE_GAME_SERVER_URL=http://localhost:5500

# The shared password for authenticating with the game-server's protected endpoints.
# This MUST match the DLQ_PASSWORD in the game-server's .env file.
DLQ_PASSWORD=your_strong_secret_password

# A shared secret for HMAC-SHA256 signature verification.
# This MUST match the HMAC_SECRET in the game-server's .env file.
HMAC_SECRET=your_very_strong_hmac_secret

# --- Optional Settings ---
MAX_SESSION_CREATION_ATTEMPTS=3
SESSION_CREATION_RETRY_DELAY_MS=1500
DB_ENTRY_TTL_MS=3600000

# --- Per-game Turn Timers ---
# Dice /start expects turnTimeMs
DICE_TURN_TIME_MS=8000

# TicTacToe /start expects turnDurationSec
TICTACTOE_TURN_DURATION_SEC=10

# --- Queue Cooldown (cancel/join spam protection) ---
CANCEL_JOIN_WINDOW_MS=300000
MAX_CANCEL_JOIN=8
COOLDOWN_MS=60000
```

### 3. Running the Server

```bash
node index.js
```


---

## Client Integration Guide

Clients must use Socket.IO to connect and interact with this server.

### 1. Connect and Request a Match

```javascript
import { io } from "socket.io-client";

const socket = io("https://tictac-toematchmaking-service-production.up.railway.app"); // Your matchmaking server URL

const playerDetails = {
    playerId: 'user-12345-abcdef', // A unique, stable identifier
    playerName: 'RizzoTheRat',     // Display name
    gameType: 'dice',              // 'dice' or 'tictactoe'
    mode: 4                        // dice modes: 2/4/6/15 (tictactoe always 2)
};

socket.emit('request-match', playerDetails);
```

Dice modes supported: `2`, `4`, `6`, `15`. TicTacToe always uses mode `2`.
For TicTacToe requests, `mode` is optional and will be forced to `2`.

### Queue behavior and overflow

Queues are per game type and per mode. If more players are queued than needed (e.g., 7/4), the server will create one session using 4 players and leave the remaining players in the queue. It keeps matching as long as `queue.length >= requiredPlayers`.

### 2. Handle Server Responses

Your client must handle the primary server events.

**`match-found`**: The server has found a match and created a game session. The payload contains the necessary information to join.

```javascript
socket.on('match-found', (data) => {
    console.log('Match Found!', data);
    // data = { 
    //   sessionId: "d2c1ba68-ab40-46b5-9651-b48ed4cb8069",
    //   joinUrl: "http://game-server:5500/session/d2c1ba68-ab40-46b5-9651-b48ed4cb8069/join",
    //   gameType: "dice",
    //   mode: 4
    // }

    // IMPORTANT: Construct the URL for your game client, passing the details.
    const gameClientUrl = new URL('http://localhost:8080/index.html'); // URL to your game client
    gameClientUrl.searchParams.set('joinUrl', data.joinUrl);
    gameClientUrl.searchParams.set('playerId', playerDetails.playerId);
    gameClientUrl.searchParams.set('playerName', playerDetails.playerName);

    // Redirect the user to the game client.
    window.location.href = gameClientUrl.toString();
});
```

**`match-error`**: The server failed to create a game session or another error occurred (including cooldown blocks).

```javascript
socket.on('match-error', (error) => {
    console.error('Matchmaking Error:', error.message);
    // error = { message: "Could not create game session.", cooldownUntil?: 1698400000000 }
    // Display a "Try again" UI to the user.
});
```

If `cooldownUntil` is provided, the client should disable further queue requests until that timestamp.

The cooldown triggers after a player cancels/joins the queue more than `MAX_CANCEL_JOIN` times within `CANCEL_JOIN_WINDOW_MS`.

**`cancel-match`**: Client request to leave any queue (also used when switching modes).

```javascript
socket.emit('cancel-match', { playerId: 'user-12345-abcdef' });
```

**`session-ended`**: The game has officially concluded. The user is now free to request a new match.

```javascript
socket.on('session-ended', (data) => {
    console.log(`Session ${data.sessionId} has ended.`);
    // data = { sessionId: "..." }

    // Update the UI to allow the user to start a new match search.
});
```

**`queue-status`**: The server broadcasts queue counts by game and mode.

```javascript
socket.on('queue-status', (data) => {
    // data = { dice: { 2: 1, 4: 3, 6: 0, 15: 0 }, tictactoe: { 2: 2 } }
});
```

**`queue-cancelled`**: The server confirmed the player left the queue.

```javascript
socket.on('queue-cancelled', (data) => {
    // data = { playerId: "user-12345-abcdef" }
});
```

### Error codes and reasons

`match-error` payloads always include a `message` and may include `cooldownUntil`.

Common errors:

- `Invalid gameType. Use dice or tictactoe.` (unknown game type)
- `Invalid mode. Dice modes: 2, 4, 6, 15.` (invalid mode)
- `playerId and playerName are required.` (missing required fields)
- `Cooldown active. Please wait before re-queueing.` (rate limit triggered)
- `Could not create game session.` (game server `/start` failed after retries)
- `Invalid session report. You are not in that session.` (bad `report-invalid-session`)

### Rate limit / cooldown policy

- Each `request-match` and `cancel-match` counts toward the same rolling window.
- If a player exceeds `MAX_CANCEL_JOIN` actions within `CANCEL_JOIN_WINDOW_MS`, the server blocks new queue requests until `COOLDOWN_MS` passes.
- During cooldown, the server responds with `match-error` and includes `cooldownUntil` (epoch ms).

### 3. Handling Invalid Sessions (Client-Side Recovery)

In rare cases, a client may be assigned to a session that is invalid (e.g., the game client fails to connect, or the session is already full or seems to be over). If a client cannot successfully join the game specified in `match-found`, it should report the session as invalid so the server can clear the active session entry. The client can then decide when to call `request-match` again.

**`report-invalid-session`**: Sent by the client to report a broken session and clear the active session entry.

```javascript
// Let's say you stored the sessionId from the 'match-found' event
const currentSessionId = "d2c1ba68-ab40-46b5-9651-b48ed4cb8069";

// If your game client determines this session is bad, report it.
const reportPayload = {
    playerId: 'user-12345-abcdef',
    playerName: 'RizzoTheRat',
    sessionId: currentSessionId
};

socket.emit('report-invalid-session', reportPayload);
```

**`session-cleared`**: The server confirms the report was valid and the player was removed from the active session.

```javascript
socket.on('session-cleared', () => {
    console.log('Server confirmed our report. You can request a new match.');
    // Update UI to show "Find Match" or "Play Again".
});
```

---

## Backend API Endpoints

The server exposes one HTTP endpoint for server-to-server communication.

### `POST /session-closed`

This endpoint is called by the `game-server` when a session ends.

*   **Method**: `POST`
*   **Security**: The caller **must** include an `X-Hub-Signature-256` header containing the HMAC-SHA256 signature of the raw request body, using the shared `HMAC_SECRET`.
*   **Request Body**: The full `session.ended` webhook payload from the game server. The matchmaking server will extract the `sessionId` from this object.

    ```json
    {
      "sessionId": "ccdb7fae-68a3-4dac-9e45-92d50299f471",
      "status": "ended",
      "players": [...],
      "board": [...],
      "winnerPlayerId": "p1",
      // ... and other session fields
    }
    ```
*   **Success Response**: `200 OK`
*   **Error Responses**:
    *   `400 Bad Request`: If `sessionId` is missing.
    *   `401 Unauthorized`: If the signature header is missing.
    *   `403 Forbidden`: If the signature is invalid.
