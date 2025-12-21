require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const { JSONFile, Low } = require('lowdb');
const cors = require('cors');

// --- Configuration & Initialization ---

const PORT = process.env.PORT || 3330;
const DLQ_PASSWORD = process.env.DLQ_PASSWORD;
const HMAC_SECRET = process.env.HMAC_SECRET;
const GAME_SERVER_URL = process.env.GAME_SERVER_URL;
const DICE_GAME_SERVER_URL = process.env.DICE_GAME_SERVER_URL || GAME_SERVER_URL;
const TICTACTOE_GAME_SERVER_URL = process.env.TICTACTOE_GAME_SERVER_URL || GAME_SERVER_URL;
const DICE_TURN_TIME_MS = parseInt(process.env.DICE_TURN_TIME_MS, 10) || 8000;
const TICTACTOE_TURN_DURATION_SEC = parseInt(process.env.TICTACTOE_TURN_DURATION_SEC, 10) || 10;
const DB_ENTRY_TTL_MS = parseInt(process.env.DB_ENTRY_TTL_MS, 10) || 3600000;
const MAX_SESSION_CREATION_ATTEMPTS = parseInt(process.env.MAX_SESSION_CREATION_ATTEMPTS, 10) || 3;
const SESSION_CREATION_RETRY_DELAY_MS = parseInt(process.env.SESSION_CREATION_RETRY_DELAY_MS, 10) || 1500;
const CANCEL_JOIN_WINDOW_MS = parseInt(process.env.CANCEL_JOIN_WINDOW_MS, 10) || 300000;
const MAX_CANCEL_JOIN = parseInt(process.env.MAX_CANCEL_JOIN, 10) || 8;
const COOLDOWN_MS = parseInt(process.env.COOLDOWN_MS, 10) || 60000;
const DICE_MODES = [2, 4, 6, 15];

if (!DLQ_PASSWORD || !HMAC_SECRET || !DICE_GAME_SERVER_URL || !TICTACTOE_GAME_SERVER_URL) {
    console.error('FATAL ERROR: DLQ_PASSWORD, HMAC_SECRET, DICE_GAME_SERVER_URL, and TICTACTOE_GAME_SERVER_URL must be defined in .env file.');
    process.exit(1);
}

const app = express();
const server = http.createServer(app);

// --- Middleware ---

app.use(cors());

const saveRawBody = (req, res, buf, encoding) => {
    if (buf && buf.length) {
        req.rawBody = buf.toString(encoding || 'utf8');
    }
};
app.use(express.json({ verify: saveRawBody }));

const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const verifyWebhookSignature = (req, res, next) => {
    const signature = req.headers['x-hub-signature-256'];
    if (!signature) {
        console.error("[Webhook Error] Signature header missing. Expected 'x-hub-signature-256'.");
        return res.status(401).send("Signature header missing. Expected 'x-hub-signature-256'.");
    }
    
    if (!req.rawBody) {
        console.error('[Webhook Error] Raw body not available for signature verification.');
        return res.status(500).send('Internal Server Error: Raw body not saved.');
    }

    const expectedSignature = crypto.createHmac('sha256', HMAC_SECRET).update(req.rawBody).digest('hex');

    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
        console.error('[Webhook Error] Invalid signature.');
        return res.status(403).send('Invalid signature.');
    }
    next();
};


// --- Database Setup ---

const adapter = new JSONFile('db.json');
const db = new Low(adapter);

async function initializeDatabase() {
    await db.read();
    db.data = db.data || {};
    ensureQueueStructure(db.data);
    await db.write();
}

// --- Helper Functions ---
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
const matchingLocks = new Set();

function normalizeGameType(raw) {
    const value = (raw || '').toString().trim().toLowerCase();
    if (value === 'dice') return 'dice';
    if (value === 'tictactoe' || value === 'tic-tac-toe' || value === 'ttt') return 'tictactoe';
    return null;
}

function normalizeMode(gameType, mode) {
    if (gameType === 'tictactoe') return 2;
    const parsed = parseInt(mode, 10);
    if (!Number.isFinite(parsed)) return null;
    return DICE_MODES.includes(parsed) ? parsed : null;
}

function ensureQueueStructure(data) {
    if (!data.queue || Array.isArray(data.queue)) {
        const legacyQueue = Array.isArray(data.queue) ? data.queue : [];
        data.queue = {
            dice: { '2': [], '4': [], '6': [], '15': [] },
            tictactoe: { '2': [] }
        };
        if (legacyQueue.length) {
            data.queue.tictactoe['2'] = legacyQueue;
        }
    }
    data.queue.dice = data.queue.dice || {};
    data.queue.tictactoe = data.queue.tictactoe || {};
    for (const mode of DICE_MODES) {
        const key = String(mode);
        data.queue.dice[key] = data.queue.dice[key] || [];
    }
    data.queue.tictactoe['2'] = data.queue.tictactoe['2'] || [];

    data.active_games = data.active_games || {};
    data.ended_games = data.ended_games || {};
    data.rate_limit = data.rate_limit || {};
}

function getQueueBucket(data, gameType, mode) {
    ensureQueueStructure(data);
    const key = String(mode);
    return data.queue?.[gameType]?.[key] || [];
}

function buildQueueStatus(data) {
    ensureQueueStructure(data);
    const dice = {};
    for (const mode of DICE_MODES) {
        dice[mode] = data.queue.dice[String(mode)]?.length || 0;
    }
    const tictactoe = { 2: data.queue.tictactoe['2']?.length || 0 };
    return { dice, tictactoe };
}

function broadcastQueueStatus() {
    io.emit('queue-status', buildQueueStatus(db.data));
}

function removeFromQueues(data, playerId) {
    let removed = false;
    ensureQueueStructure(data);
    const buckets = [
        ...Object.values(data.queue.dice || {}),
        ...Object.values(data.queue.tictactoe || {})
    ];
    for (const bucket of buckets) {
        let index = bucket.findIndex((entry) => entry.playerId === playerId);
        while (index !== -1) {
            bucket.splice(index, 1);
            removed = true;
            index = bucket.findIndex((entry) => entry.playerId === playerId);
        }
    }
    return removed;
}

function upsertRateLimit(data, playerId) {
    ensureQueueStructure(data);
    const now = Date.now();
    const entry = data.rate_limit[playerId] || { count: 0, windowStart: now, cooldownUntil: 0 };
    if (now - entry.windowStart > CANCEL_JOIN_WINDOW_MS) {
        entry.count = 0;
        entry.windowStart = now;
    }
    data.rate_limit[playerId] = entry;
    return entry;
}

function registerQueueAction(data, playerId, { blockOnLimit }) {
    const entry = upsertRateLimit(data, playerId);
    const now = Date.now();
    if (entry.cooldownUntil && now < entry.cooldownUntil) {
        return { blocked: true, cooldownUntil: entry.cooldownUntil };
    }
    entry.count += 1;
    if (entry.count > MAX_CANCEL_JOIN) {
        entry.cooldownUntil = now + COOLDOWN_MS;
        entry.count = 0;
        entry.windowStart = now;
        return blockOnLimit ? { blocked: true, cooldownUntil: entry.cooldownUntil } : { blocked: false };
    }
    return { blocked: false };
}

async function createSessionForMatch(gameType, mode) {
    const url = gameType === 'dice' ? DICE_GAME_SERVER_URL : TICTACTOE_GAME_SERVER_URL;
    const body =
        gameType === 'dice'
            ? { minPlayers: mode, maxPlayers: mode, turnTimeMs: DICE_TURN_TIME_MS }
            : { turnDurationSec: TICTACTOE_TURN_DURATION_SEC };

    for (let attempt = 1; attempt <= MAX_SESSION_CREATION_ATTEMPTS; attempt++) {
        try {
            console.log(`[Game Server] Attempt ${attempt} to create ${gameType} session (mode=${mode})`);
            const response = await fetch(`${url}/start`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${DLQ_PASSWORD}`
                },
                body: JSON.stringify(body)
            });

            const receivedSignature = response.headers.get('x-hub-signature-256');
            const rawBody = await response.text();

            if (!response.ok) {
                throw new Error(`Game server returned status ${response.status}: ${rawBody}`);
            }

            if (!receivedSignature) {
                throw new Error('Response from game server is missing signature header');
            }

            const computedSignature = crypto.createHmac('sha256', HMAC_SECRET).update(rawBody).digest('hex');

            if (!crypto.timingSafeEqual(Buffer.from(receivedSignature), Buffer.from(computedSignature))) {
                throw new Error('Invalid response signature from game server');
            }

            const parsed = JSON.parse(rawBody);
            const { sessionId, joinUrl } = parsed;
            if (!sessionId || !joinUrl) {
                throw new Error('Invalid response payload from game server');
            }

            return { ok: true, sessionId, joinUrl };
        } catch (error) {
            console.error(`[Error] Attempt ${attempt} failed:`, error.message);
            if (attempt < MAX_SESSION_CREATION_ATTEMPTS) {
                await delay(SESSION_CREATION_RETRY_DELAY_MS);
            } else {
                return { ok: false, message: error.message };
            }
        }
    }
    return { ok: false, message: 'Unknown error creating session' };
}

async function attemptMatchmaking(gameType, mode) {
    const key = `${gameType}:${mode}`;
    if (matchingLocks.has(key)) return;
    matchingLocks.add(key);

    try {
        await db.read();
        ensureQueueStructure(db.data);
        let queue = getQueueBucket(db.data, gameType, mode);
        const requiredPlayers = mode;

        while (queue.length >= requiredPlayers) {
            const candidates = [];
            while (queue.length > 0 && candidates.length < requiredPlayers) {
                const entry = queue.shift();
                const socket = io.sockets.sockets.get(entry.socketId);
                if (!socket || socket.disconnected) {
                    console.log(`[State] Dropping queued player ${entry.playerId} (socket offline).`);
                    continue;
                }
                candidates.push(entry);
            }

            if (candidates.length < requiredPlayers) {
                queue.unshift(...candidates);
                break;
            }

            await db.write();
            const sessionResult = await createSessionForMatch(gameType, mode);

            await db.read();
            ensureQueueStructure(db.data);
            queue = getQueueBucket(db.data, gameType, mode);

            if (!sessionResult.ok) {
                console.error(`[Fatal] Failed to create ${gameType} session: ${sessionResult.message}`);
                for (const entry of candidates.reverse()) {
                    getQueueBucket(db.data, gameType, mode).unshift(entry);
                    io.to(entry.playerId)?.emit('match-error', { message: 'Could not create game session.' });
                }
                await db.write();
                break;
            }

            const { sessionId, joinUrl } = sessionResult;
            for (const entry of candidates) {
                db.data.active_games[entry.playerId] = { sessionId, joinUrl, gameType, mode };
            }
            await db.write();

            await db.read();
            ensureQueueStructure(db.data);
            queue = getQueueBucket(db.data, gameType, mode);

            for (const entry of candidates) {
                io.to(entry.playerId).emit('match-found', { sessionId, joinUrl, gameType, mode });
            }
        }

        broadcastQueueStatus();
    } finally {
        matchingLocks.delete(key);
    }
}

// --- Main Application Logic ---

async function main() {
    await initializeDatabase();

    // --- HTTP ROUTES ---
    app.post('/session-closed', verifyWebhookSignature, async (req, res) => {
        const { sessionId } = req.body;
        console.log(`[Webhook] Received session-closed event for session: ${sessionId}`);

        if (!sessionId) {
            console.warn('[Webhook] Received session-closed event with no sessionId.');
            return res.status(400).send('Bad Request: sessionId is required.');
        }

        try {
            await db.read();
            ensureQueueStructure(db.data);

            const playerIdsInSession = Object.keys(db.data.active_games).filter(
                (playerId) => db.data.active_games[playerId].sessionId === sessionId
            );

            if (playerIdsInSession.length === 0) {
                console.log(`[Webhook] No active players found for session ${sessionId}. It might have already been cleared.`);
                return res.status(200).send('Session already cleared or unknown.');
            }

            console.log(`[State] Clearing active session ${sessionId} for players: ${playerIdsInSession.join(', ')}`);

            for (const playerId of playerIdsInSession) {
                console.log(`[Socket] Notifying player ${playerId} that session ${sessionId} has ended.`);
                io.to(playerId).emit('session-ended', { sessionId });
                delete db.data.active_games[playerId];
            }

            db.data.ended_games[sessionId] = { ended_at: new Date().toISOString() };

            await db.write();
            broadcastQueueStatus();

            console.log(`[State] Session ${sessionId} successfully closed and moved to ended_games.`);
            res.status(200).send('Session successfully closed.');
        } catch (error) {
            console.error(`[FATAL] Error processing /session-closed for session ${sessionId}:`, error);
            res.status(500).send('Internal Server Error.');
        }
    });


    // --- SOCKET.IO LOGIC ---
    io.on('connection', (socket) => {
        console.log(`[Socket] Client connected: ${socket.id}`);

        db.read()
            .then(() => {
                ensureQueueStructure(db.data);
                socket.emit('queue-status', buildQueueStatus(db.data));
            })
            .catch((err) => {
                console.error('[Socket] Failed to send initial queue status:', err.message);
            });

        socket.on('request-match', async (data) => {
            try {
                const { playerId, playerName, gameType: rawGameType, mode: rawMode } = data || {};
                if (!playerId || !playerName) {
                    return socket.emit('match-error', { message: 'playerId and playerName are required.' });
                }

                const gameType = normalizeGameType(rawGameType);
                if (!gameType) {
                    return socket.emit('match-error', { message: 'Invalid gameType. Use dice or tictactoe.' });
                }

                const mode = normalizeMode(gameType, rawMode);
                if (!mode) {
                    return socket.emit('match-error', { message: 'Invalid mode. Dice modes: 2, 4, 6, 15.' });
                }

                console.log(`[Socket] Match requested by PlayerID: ${playerId} (${gameType} ${mode})`);
                socket.join(playerId);

                await db.read();
                ensureQueueStructure(db.data);

                const activeGame = db.data.active_games[playerId];
                if (activeGame) {
                    const { sessionId, joinUrl, gameType: activeGameType, mode: activeMode } = activeGame;
                    const resolvedGameType = activeGameType || 'tictactoe';
                    const resolvedMode = activeMode || 2;
                    if (db.data.ended_games[sessionId]) {
                        console.log(`[State] Player ${playerId} was in session ${sessionId}, but it has ended. Clearing and allowing to re-queue.`);
                        delete db.data.active_games[playerId];
                    } else {
                        console.log(`[State] Player ${playerId} is already in an active game. Resending session details.`);
                        await db.write();
                        return socket.emit('match-found', { sessionId, joinUrl, gameType: resolvedGameType, mode: resolvedMode });
                    }
                }

                const rateCheck = registerQueueAction(db.data, playerId, { blockOnLimit: true });
                if (rateCheck.blocked) {
                    await db.write();
                    return socket.emit('match-error', {
                        message: 'Cooldown active. Please wait before re-queueing.',
                        cooldownUntil: rateCheck.cooldownUntil
                    });
                }

                removeFromQueues(db.data, playerId);

                const queueBucket = getQueueBucket(db.data, gameType, mode);
                const existing = queueBucket.find((entry) => entry.playerId === playerId);
                if (existing) {
                    existing.playerName = playerName;
                    existing.socketId = socket.id;
                    existing.queuedAt = new Date().toISOString();
                } else {
                    queueBucket.push({
                        playerId,
                        playerName,
                        socketId: socket.id,
                        gameType,
                        mode,
                        queuedAt: new Date().toISOString()
                    });
                }

                await db.write();
                broadcastQueueStatus();
                attemptMatchmaking(gameType, mode);
            } catch (err) {
                console.error('[FATAL] Unhandled error in request-match handler:', err);
                socket.emit('match-error', { message: 'An unexpected server error occurred.' });
            }
        });

        socket.on('cancel-match', async (data) => {
            try {
                const { playerId } = data || {};
                if (!playerId) {
                    return socket.emit('match-error', { message: 'playerId is required to cancel.' });
                }

                await db.read();
                ensureQueueStructure(db.data);
                const removed = removeFromQueues(db.data, playerId);
                registerQueueAction(db.data, playerId, { blockOnLimit: false });
                await db.write();

                if (removed) {
                    socket.emit('queue-cancelled', { playerId });
                }
                broadcastQueueStatus();
            } catch (err) {
                console.error('[FATAL] Unhandled error in cancel-match handler:', err);
                socket.emit('match-error', { message: 'An unexpected server error occurred while cancelling.' });
            }
        });

        socket.on('disconnect', async () => {
            console.log(`[Socket] Client disconnected: ${socket.id}`);
            try {
                await db.read();
                ensureQueueStructure(db.data);
                let removedPlayer = null;
                const buckets = [
                    ...Object.values(db.data.queue.dice || {}),
                    ...Object.values(db.data.queue.tictactoe || {})
                ];
                for (const bucket of buckets) {
                    const index = bucket.findIndex((entry) => entry.socketId === socket.id);
                    if (index !== -1) {
                        removedPlayer = bucket.splice(index, 1)[0];
                        break;
                    }
                }
                if (removedPlayer) {
                    console.log(`[State] Player ${removedPlayer.playerId} removed from queue due to disconnect.`);
                    await db.write();
                    broadcastQueueStatus();
                }
            } catch (err) {
                console.error('[FATAL] Unhandled error in disconnect handler:', err);
            }
        });

        socket.on('report-invalid-session', async (data) => {
            try {
                const { playerId, sessionId } = data || {};
                if (!playerId || !sessionId) {
                    return socket.emit('match-error', { message: 'playerId and sessionId are required to report an invalid session.' });
                }

                await db.read();
                ensureQueueStructure(db.data);
                
                const activeGame = db.data.active_games[playerId];

                if (activeGame && activeGame.sessionId === sessionId) {
                    console.log(`[State] Player ${playerId} reported invalid session ${sessionId}. Clearing active game entry.`);

                    delete db.data.active_games[playerId];
                    const removedFromQueue = removeFromQueues(db.data, playerId);

                    await db.write();
                    socket.emit('session-cleared', { playerId, sessionId, removedFromQueue });
                    broadcastQueueStatus();
                } else {
                    console.warn(`[State] Player ${playerId} sent an invalid report for session ${sessionId}. Their active session is ${activeGame ? activeGame.sessionId : 'non-existent'}.`);
                    socket.emit('match-error', { message: 'Invalid session report. You are not in that session.' });
                }
            } catch (err) {
                console.error('[FATAL] Unhandled error in report-invalid-session handler:', err);
                socket.emit('match-error', { message: 'An unexpected server error occurred while reporting session.' });
            }
        });
    });

    server.listen(PORT, () => {
        console.log(`Matchmaking server listening on http://localhost:${PORT}`);
    });
}

main();
