require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const { createClient } = require('redis');
const cors = require('cors');

// --- Configuration & Initialization ---

const PORT = process.env.PORT || 3330;
const DLQ_PASSWORD = process.env.DLQ_PASSWORD;
const HMAC_SECRET = process.env.HMAC_SECRET;
const GAME_SERVER_URL = process.env.GAME_SERVER_URL;
const DICE_GAME_SERVER_URL = process.env.DICE_GAME_SERVER_URL || GAME_SERVER_URL;
const TICTACTOE_GAME_SERVER_URL = process.env.TICTACTOE_GAME_SERVER_URL || GAME_SERVER_URL;
const CARD_GAME_SERVER_URL = process.env.CARD_GAME_SERVER_URL || GAME_SERVER_URL;
const REDIS_URL = process.env.REDIS_URL;
const REDIS_HOST = process.env.REDIS_HOST;
const REDIS_PORT = parseInt(process.env.REDIS_PORT, 10);
const REDIS_USERNAME = process.env.REDIS_USERNAME;
const REDIS_PASSWORD = process.env.REDIS_PASSWORD;
const REDIS_USE_TLS = String(process.env.REDIS_USE_TLS || 'true').toLowerCase() === 'true';
const AUTH_REQUIRED = String(process.env.AUTH_REQUIRED || 'false').toLowerCase() === 'true';
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_JWKS_URL = process.env.SUPABASE_JWKS_URL
    || (SUPABASE_URL ? `${SUPABASE_URL.replace(/\/$/, '')}/auth/v1/.well-known/jwks.json` : null);
const SUPABASE_JWT_ISSUER = process.env.SUPABASE_JWT_ISSUER
    || (SUPABASE_URL ? `${SUPABASE_URL.replace(/\/$/, '')}/auth/v1` : null);
const SUPABASE_JWT_AUDIENCE = process.env.SUPABASE_JWT_AUDIENCE || 'authenticated';
const DICE_TURN_TIME_MS = parseInt(process.env.DICE_TURN_TIME_MS, 10) || 8000;
const TICTACTOE_TURN_DURATION_SEC = parseInt(process.env.TICTACTOE_TURN_DURATION_SEC, 10) || 6;
const CARD_TURN_DURATION_SEC = parseInt(process.env.CARD_TURN_DURATION_SEC, 10) || 10;
const DB_ENTRY_TTL_MS = parseInt(process.env.DB_ENTRY_TTL_MS, 10) || 3600000;
const ACTIVE_GAMES_TTL_MS = parseInt(process.env.ACTIVE_GAMES_TTL_MS, 10) || DB_ENTRY_TTL_MS;
const MAX_SESSION_CREATION_ATTEMPTS = parseInt(process.env.MAX_SESSION_CREATION_ATTEMPTS, 10) || 3;
const SESSION_CREATION_RETRY_DELAY_MS = parseInt(process.env.SESSION_CREATION_RETRY_DELAY_MS, 10) || 1500;
const CANCEL_JOIN_WINDOW_MS = parseInt(process.env.CANCEL_JOIN_WINDOW_MS, 10) || 300000;
const MAX_CANCEL_JOIN = parseInt(process.env.MAX_CANCEL_JOIN, 10) || 8;
const COOLDOWN_MS = parseInt(process.env.COOLDOWN_MS, 10) || 60000;
const PRIVATE_LOBBY_IDLE_MS = parseInt(process.env.PRIVATE_LOBBY_IDLE_MS, 10) || 1800000;
const PRIVATE_LOBBY_EMPTY_GRACE_MS = parseInt(process.env.PRIVATE_LOBBY_EMPTY_GRACE_MS, 10) || 60000;
const PRIVATE_LOBBY_DISCONNECT_GRACE_MS = parseInt(process.env.PRIVATE_LOBBY_DISCONNECT_GRACE_MS, 10) || 120000;
const DICE_MODES = [2, 4, 6, 15];
const CARD_MODES = [2, 3, 4, 5, 6];
const CLEANUP_INTERVAL_MS = Math.min(300000, DB_ENTRY_TTL_MS);
const nodeMajor = parseInt(process.versions.node.split('.')[0], 10);
if (Number.isFinite(nodeMajor) && nodeMajor < 18) {
    console.warn(`[Matchmaking] Node ${process.versions.node} detected. JWKS verification requires Node 18+.`);
}
if (!globalThis.crypto) {
    try {
        const { webcrypto } = require('crypto');
        if (webcrypto) {
            globalThis.crypto = webcrypto;
            console.warn('[Matchmaking] WebCrypto polyfill enabled for JWKS verification.');
        }
    } catch (error) {
        console.warn('[Matchmaking] WebCrypto polyfill failed:', error?.message || error);
    }
}

if (!DLQ_PASSWORD || !HMAC_SECRET || !DICE_GAME_SERVER_URL || !TICTACTOE_GAME_SERVER_URL || !CARD_GAME_SERVER_URL) {
    console.error('FATAL ERROR: DLQ_PASSWORD, HMAC_SECRET, DICE_GAME_SERVER_URL, TICTACTOE_GAME_SERVER_URL, and CARD_GAME_SERVER_URL must be defined in .env file.');
    process.exit(1);
}

if (!REDIS_URL && (!REDIS_HOST || !REDIS_PORT)) {
    console.error('FATAL ERROR: REDIS_URL or REDIS_HOST + REDIS_PORT must be defined in .env file.');
    process.exit(1);
}

if (AUTH_REQUIRED && (!SUPABASE_JWKS_URL || !SUPABASE_JWT_ISSUER)) {
    console.error('FATAL ERROR: AUTH_REQUIRED is true but SUPABASE_URL/SUPABASE_JWKS_URL or SUPABASE_JWT_ISSUER is missing.');
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

if (AUTH_REQUIRED) {
    io.use(async (socket, next) => {
        try {
            const token = getSocketAuthToken(socket);
            const result = await verifySupabaseJwt(token);
            if (!result.ok) {
                console.warn('[Auth] Socket connection rejected:', result.reason);
                return next(new Error('unauthorized'));
            }
            socket.auth = { userId: result.payload?.sub || null };
            return next();
        } catch (error) {
            console.warn('[Auth] Socket connection rejected:', error?.message || error);
            return next(new Error('unauthorized'));
        }
    });
}

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

    if (signature.length !== expectedSignature.length) {
        console.error('[Webhook Error] Invalid signature length.');
        return res.status(403).send('Invalid signature.');
    }

    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
        console.error('[Webhook Error] Invalid signature.');
        return res.status(403).send('Invalid signature.');
    }
    next();
};


// --- Redis Setup ---

let redisClient = null;

function buildRedisClientOptions() {
    if (REDIS_URL) {
        const options = { url: REDIS_URL };
        if (REDIS_USERNAME) {
            options.username = REDIS_USERNAME;
        }
        if (REDIS_PASSWORD) {
            options.password = REDIS_PASSWORD;
        }
        if (REDIS_USE_TLS) {
            options.socket = { tls: {} };
        }
        return options;
    }
    return {
        username: REDIS_USERNAME || undefined,
        socket: {
            host: REDIS_HOST,
            port: REDIS_PORT,
            tls: REDIS_USE_TLS ? {} : undefined
        },
        password: REDIS_PASSWORD || undefined
    };
}

async function initializeRedis() {
    redisClient = createClient(buildRedisClientOptions());
    redisClient.on('error', (err) => {
        console.error('[Redis] Client error:', err.message);
    });
    await redisClient.connect();
    console.log('[Redis] Connected.');
}

// --- Helper Functions ---
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
const matchingLocks = new Set();
const retryTimers = new Map();
const POP_N_SCRIPT = `
local key = KEYS[1]
local count = tonumber(ARGV[1])
local items = redis.call('LRANGE', key, 0, count - 1)
if #items < count then
  return {}
end
redis.call('LTRIM', key, count, -1)
return items
`;

const QUEUE_KEYS = [
    ...DICE_MODES.map((mode) => ({ gameType: 'dice', mode })),
    { gameType: 'tictactoe', mode: 2 },
    ...CARD_MODES.map((mode) => ({ gameType: 'card', mode }))
];

const getQueueKey = (gameType, mode) => `queue:${gameType}:${mode}`;
const getQueueEntryKey = (playerId) => `queue_entry:${playerId}`;
const getPlayerQueueKey = (playerId) => `player_queue:${playerId}`;
const getSocketQueueKey = (socketId) => `socket_queue:${socketId}`;
const getActiveGamePlayerKey = (playerId) => `active_game:player:${playerId}`;
const getActiveGameSessionKey = (sessionId) => `active_game:session:${sessionId}`;
const getEndedGameKey = (sessionId) => `ended_game:${sessionId}`;
const getRateLimitKey = (type, value) => `rate_limit:${type}:${value}`;
const getPrivateLobbyKey = (lobbyId) => `private_lobby:lobby:${lobbyId}`;
const getPrivateLobbyPlayersKey = (lobbyId) => `private_lobby:players:${lobbyId}`;
const getPrivateLobbyConnectedKey = (lobbyId) => `private_lobby:connected:${lobbyId}`;
const getPrivateLobbyPlayerKey = (playerId) => `private_lobby:player:${playerId}`;
const getPrivateLobbySessionKey = (sessionId) => `private_lobby:session:${sessionId}`;
const getPrivateLobbySocketKey = (socketId) => `private_lobby:socket:${socketId}`;
const getPrivateLobbyPlayerSocketKey = (playerId) => `private_lobby:player_socket:${playerId}`;
const getPrivateLobbyDisconnectKey = (playerId) => `private_lobby:disconnect:${playerId}`;
const getPrivateLobbyRoom = (lobbyId) => `private-lobby:${lobbyId}`;

function normalizeGameType(raw) {
    const value = (raw || '').toString().trim().toLowerCase();
    if (value === 'dice') return 'dice';
    if (value === 'tictactoe' || value === 'tic-tac-toe' || value === 'ttt') return 'tictactoe';
    if (value === 'card' || value === 'cardgame' || value === 'card-game' || value === 'whot') return 'card';
    return null;
}

function normalizeMode(gameType, mode) {
    if (gameType === 'tictactoe') return 2;
    if (gameType === 'card') {
        const parsed = parseInt(mode, 10);
        if (!Number.isFinite(parsed)) return null;
        return CARD_MODES.includes(parsed) ? parsed : null;
    }
    const parsed = parseInt(mode, 10);
    if (!Number.isFinite(parsed)) return null;
    return DICE_MODES.includes(parsed) ? parsed : null;
}

let josePromise = null;
let jwksCache = null;

function getJose() {
    if (!josePromise) {
        josePromise = import('jose');
    }
    return josePromise;
}

async function getJwks() {
    if (jwksCache) return jwksCache;
    const { createRemoteJWKSet } = await getJose();
    jwksCache = createRemoteJWKSet(new URL(SUPABASE_JWKS_URL));
    return jwksCache;
}

function getSocketAuthToken(socket) {
    const authToken = socket.handshake?.auth?.token;
    if (authToken) return authToken;
    const header = socket.handshake?.headers?.authorization || '';
    if (typeof header === 'string' && header.toLowerCase().startsWith('bearer ')) {
        return header.slice(7).trim();
    }
    return null;
}

async function verifySupabaseJwt(token) {
    if (!token) {
        return { ok: false, reason: 'missing_token' };
    }

    try {
        const { jwtVerify } = await getJose();
        const jwks = await getJwks();
        const { payload } = await jwtVerify(token, jwks, {
            issuer: SUPABASE_JWT_ISSUER,
            audience: SUPABASE_JWT_AUDIENCE
        });
        return { ok: true, payload };
    } catch (error) {
        return { ok: false, reason: error?.message || 'invalid_token' };
    }
}

function getClientIp(socket) {
    const forwarded = socket.handshake.headers['x-forwarded-for'];
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    return socket.handshake.address || 'unknown';
}

function resolveOutcome(payload, playerId) {
    if (!payload || !playerId) return 'draw';

    const winners = Array.isArray(payload.winners) ? payload.winners : null;
    if (winners) {
        if (winners.length === 0) return 'draw';
        const isWinner = winners.some((winner) => winner?.playerId === playerId);
        return isWinner ? 'win' : 'loss';
    }

    const winnerId = payload.winnerPlayerId || payload.winner_player_id || payload.winnerId;
    if (winnerId) {
        return winnerId === playerId ? 'win' : 'loss';
    }

    const winState = (payload.winState || payload.win_state || payload.outcome || payload.result || payload.reason || '')
        .toString()
        .toLowerCase();
    if (winState === 'draw' || winState === 'tie') {
        return 'draw';
    }

    return 'draw';
}

function createLobbyId() {
    return crypto.randomUUID();
}

function generateVoiceChannel(sessionId, lobbyId = null) {
    if (lobbyId) {
        return `lobby_${lobbyId}`;
    }
    if (sessionId) {
        return `session_${sessionId}`;
    }
    return null;
}

function parseLobbyConfig(gameType, rawConfig) {
    if (!rawConfig || typeof rawConfig !== 'object') {
        return { error: 'config is required for private lobbies.' };
    }

    if (gameType === 'dice') {
        const playerCount = parseInt(rawConfig.playerCount ?? rawConfig.mode, 10);
        const turnTimeMs = parseInt(rawConfig.turnTimeMs, 10);
        if (!DICE_MODES.includes(playerCount)) {
            return { error: 'Invalid playerCount for dice. Use 2, 4, 6, or 15.' };
        }
        if (!Number.isFinite(turnTimeMs) || turnTimeMs <= 0) {
            return { error: 'turnTimeMs is required for dice private lobbies.' };
        }
        return { mode: playerCount, config: { playerCount, turnTimeMs } };
    }

    if (gameType === 'tictactoe') {
        const turnDurationSec = parseInt(rawConfig.turnDurationSec, 10);
        if (!Number.isFinite(turnDurationSec) || turnDurationSec <= 0) {
            return { error: 'turnDurationSec is required for tictactoe private lobbies.' };
        }
        return { mode: 2, config: { turnDurationSec } };
    }

    if (gameType === 'card') {
        const playerCount = parseInt(rawConfig.playerCount ?? rawConfig.mode, 10);
        const turnDurationSec = parseInt(rawConfig.turnDurationSec, 10);
        if (!CARD_MODES.includes(playerCount)) {
            return { error: 'Invalid playerCount for card. Use 2-6.' };
        }
        if (!Number.isFinite(turnDurationSec) || turnDurationSec <= 0) {
            return { error: 'turnDurationSec is required for card private lobbies.' };
        }
        return { mode: playerCount, config: { playerCount, turnDurationSec } };
    }

    return { error: 'Invalid gameType. Use dice, tictactoe, or card.' };
}

async function loadLobby(lobbyId) {
    const raw = await redisClient.get(getPrivateLobbyKey(lobbyId));
    if (!raw) return null;
    try {
        return JSON.parse(raw);
    } catch (error) {
        return null;
    }
}

async function touchPrivateLobbyKeys(lobbyId) {
    await redisClient.pExpire(getPrivateLobbyKey(lobbyId), DB_ENTRY_TTL_MS);
    await redisClient.pExpire(getPrivateLobbyPlayersKey(lobbyId), DB_ENTRY_TTL_MS);
    await redisClient.pExpire(getPrivateLobbyConnectedKey(lobbyId), DB_ENTRY_TTL_MS);
}

async function persistLobby(lobby) {
    lobby.updatedAt = new Date().toISOString();
    if (!lobby.voiceChannel) {
        lobby.voiceChannel = generateVoiceChannel(lobby.sessionId, lobby.lobbyId);
    }
    await redisClient.set(getPrivateLobbyKey(lobby.lobbyId), JSON.stringify(lobby), { PX: DB_ENTRY_TTL_MS });
    await touchPrivateLobbyKeys(lobby.lobbyId);
}

async function buildLobbyState(lobbyId) {
    const lobby = await loadLobby(lobbyId);
    if (!lobby) return null;

    const playerMap = await redisClient.hGetAll(getPrivateLobbyPlayersKey(lobbyId));
    const connectedIds = new Set(await redisClient.sMembers(getPrivateLobbyConnectedKey(lobbyId)));
    const players = Object.values(playerMap).map((raw) => {
        try {
            const data = JSON.parse(raw);
            return {
                playerId: data.playerId,
                playerName: data.playerName,
                joinedAt: data.joinedAt,
                connected: connectedIds.has(data.playerId)
            };
        } catch (error) {
            return null;
        }
    }).filter(Boolean);

    return {
        lobbyId: lobby.lobbyId,
        adminPlayerId: lobby.adminPlayerId,
        gameType: lobby.gameType,
        mode: lobby.mode,
        config: lobby.config,
        playerCount: lobby.playerCount,
        inGame: lobby.inGame,
        sessionId: lobby.sessionId,
        voiceChannel: lobby.voiceChannel || generateVoiceChannel(lobby.sessionId, lobby.lobbyId),
        players,
        connectedCount: connectedIds.size,
        createdAt: lobby.createdAt,
        updatedAt: lobby.updatedAt,
        lastActivityAt: lobby.lastActivityAt,
        emptySince: lobby.emptySince
    };
}

async function emitLobbyUpdate(lobbyId) {
    const state = await buildLobbyState(lobbyId);
    if (!state) return;
    io.to(getPrivateLobbyRoom(lobbyId)).emit('private-lobby-updated', state);
}

async function hydrateLobbyForSocket(socket, playerId) {
    if (!playerId) return;
    const lobbyId = await redisClient.get(getPrivateLobbyPlayerKey(playerId));
    if (!lobbyId) return;

    const lobby = await loadLobby(lobbyId);
    if (!lobby) return;

    const previousSocketId = await redisClient.get(getPrivateLobbyPlayerSocketKey(playerId));
    if (previousSocketId && previousSocketId !== socket.id) {
        await redisClient.del(getPrivateLobbySocketKey(previousSocketId));
    }

    await redisClient.set(getPrivateLobbySocketKey(socket.id), JSON.stringify({ lobbyId, playerId }), { PX: DB_ENTRY_TTL_MS });
    await redisClient.set(getPrivateLobbyPlayerSocketKey(playerId), socket.id, { PX: DB_ENTRY_TTL_MS });
    await redisClient.sAdd(getPrivateLobbyConnectedKey(lobbyId), playerId);
    await redisClient.del(getPrivateLobbyDisconnectKey(playerId));
    socket.join(getPrivateLobbyRoom(lobbyId));

    const state = await buildLobbyState(lobbyId);
    if (state) {
        socket.emit('private-lobby-joined', state);
    }
}

async function removePlayerFromLobby(lobbyId, playerId, { kicked = false } = {}) {
    const lobby = await loadLobby(lobbyId);
    if (!lobby) return { removed: false };

    await redisClient.hDel(getPrivateLobbyPlayersKey(lobbyId), playerId);
    await redisClient.sRem(getPrivateLobbyConnectedKey(lobbyId), playerId);
    await redisClient.del(getPrivateLobbyPlayerKey(playerId));

    const socketId = await redisClient.get(getPrivateLobbyPlayerSocketKey(playerId));
    if (socketId) {
        await redisClient.del(getPrivateLobbySocketKey(socketId));
        await redisClient.del(getPrivateLobbyPlayerSocketKey(playerId));
    }

    const remainingPlayers = await redisClient.hGetAll(getPrivateLobbyPlayersKey(lobbyId));
    const remainingIds = Object.keys(remainingPlayers);

    if (lobby.adminPlayerId === playerId) {
        if (remainingIds.length > 0) {
            const nextAdmin = remainingIds
                .map((id) => {
                    try {
                        return JSON.parse(remainingPlayers[id]);
                    } catch (error) {
                        return null;
                    }
                })
                .filter(Boolean)
                .sort((a, b) => new Date(a.joinedAt) - new Date(b.joinedAt))[0];
            lobby.adminPlayerId = nextAdmin ? nextAdmin.playerId : null;
        } else {
            lobby.adminPlayerId = null;
        }
    }

    lobby.lastActivityAt = new Date().toISOString();

    const connectedCount = await redisClient.sCard(getPrivateLobbyConnectedKey(lobbyId));
    if (!lobby.inGame && connectedCount === 0) {
        lobby.emptySince = lobby.emptySince || new Date().toISOString();
    }

    await persistLobby(lobby);
    await emitLobbyUpdate(lobbyId);

    if (kicked && socketId) {
        io.to(socketId).emit('private-lobby-kicked', { lobbyId });
    }

    return { removed: true };
}

async function closePrivateLobby(lobbyId, reason) {
    const lobby = await loadLobby(lobbyId);
    if (!lobby) return;

    const playerMap = await redisClient.hGetAll(getPrivateLobbyPlayersKey(lobbyId));
    const playerIds = Object.keys(playerMap);
    for (const playerId of playerIds) {
        await redisClient.del(getPrivateLobbyPlayerKey(playerId));
        const socketId = await redisClient.get(getPrivateLobbyPlayerSocketKey(playerId));
        if (socketId) {
            await redisClient.del(getPrivateLobbySocketKey(socketId));
            await redisClient.del(getPrivateLobbyPlayerSocketKey(playerId));
        }
    }

    if (lobby.sessionId) {
        await redisClient.del(getPrivateLobbySessionKey(lobby.sessionId));
    }

    await redisClient.del(getPrivateLobbyKey(lobbyId));
    await redisClient.del(getPrivateLobbyPlayersKey(lobbyId));
    await redisClient.del(getPrivateLobbyConnectedKey(lobbyId));

    io.to(getPrivateLobbyRoom(lobbyId)).emit('private-lobby-closed', { lobbyId, reason });
}

function getRateLimitKeys(playerId, ip, deviceId) {
    const keys = [];
    if (playerId) keys.push(getRateLimitKey('player', playerId));
    if (ip) keys.push(getRateLimitKey('ip', ip));
    if (deviceId) keys.push(getRateLimitKey('device', deviceId));
    keys.push(getRateLimitKey('combo', `${playerId || 'none'}|${ip || 'none'}|${deviceId || 'none'}`));
    return keys;
}

async function readRateEntry(key) {
    const raw = await redisClient.get(key);
    if (!raw) {
        return { count: 0, windowStart: Date.now(), cooldownUntil: 0 };
    }
    try {
        return JSON.parse(raw);
    } catch (error) {
        return { count: 0, windowStart: Date.now(), cooldownUntil: 0 };
    }
}

async function writeRateEntry(key, entry) {
    await redisClient.set(key, JSON.stringify(entry), { PX: DB_ENTRY_TTL_MS });
}

async function registerQueueAction(playerId, ip, deviceId, { blockOnLimit }) {
    const keys = getRateLimitKeys(playerId, ip, deviceId);
    const now = Date.now();
    let blockedUntil = 0;
    const entries = new Map();

    for (const key of keys) {
        const entry = await readRateEntry(key);
        if (now - entry.windowStart > CANCEL_JOIN_WINDOW_MS) {
            entry.count = 0;
            entry.windowStart = now;
            entry.cooldownUntil = 0;
        }
        if (entry.cooldownUntil && now < entry.cooldownUntil) {
            blockedUntil = Math.max(blockedUntil, entry.cooldownUntil);
        }
        entries.set(key, entry);
    }

    if (blockedUntil && blockOnLimit) {
        return { blocked: true, cooldownUntil: blockedUntil };
    }

    for (const [key, entry] of entries.entries()) {
        entry.count += 1;
        if (entry.count > MAX_CANCEL_JOIN) {
            entry.cooldownUntil = now + COOLDOWN_MS;
            entry.count = 0;
            entry.windowStart = now;
            blockedUntil = Math.max(blockedUntil, entry.cooldownUntil);
        }
        await writeRateEntry(key, entry);
    }

    if (blockedUntil && blockOnLimit) {
        return { blocked: true, cooldownUntil: blockedUntil };
    }

    return blockedUntil ? { blocked: false, cooldownUntil: blockedUntil } : { blocked: false };
}

async function resetRateLimit(playerId, ip, deviceId) {
    const keys = getRateLimitKeys(playerId, ip, deviceId);
    const entry = {
        count: 0,
        windowStart: Date.now(),
        cooldownUntil: 0
    };
    for (const key of keys) {
        await writeRateEntry(key, entry);
    }
}

async function buildQueueStatus() {
    const dice = {};
    for (const mode of DICE_MODES) {
        dice[mode] = await redisClient.lLen(getQueueKey('dice', mode));
    }
    const tictactoe = { 2: await redisClient.lLen(getQueueKey('tictactoe', 2)) };
    const card = {};
    for (const mode of CARD_MODES) {
        card[mode] = await redisClient.lLen(getQueueKey('card', mode));
    }
    return { dice, tictactoe, card };
}

async function broadcastQueueStatus() {
    io.emit('queue-status', await buildQueueStatus());
}

async function removeFromQueueKey(queueKey, playerId) {
    const removedCount = await redisClient.lRem(queueKey, 0, playerId);
    if (removedCount > 0) {
        const entryRaw = await redisClient.get(getQueueEntryKey(playerId));
        let socketId = null;
        if (entryRaw) {
            try {
                socketId = JSON.parse(entryRaw).socketId;
            } catch (error) {
                socketId = null;
            }
        }
        await redisClient.del(getQueueEntryKey(playerId));
        await redisClient.del(getPlayerQueueKey(playerId));
        if (socketId) {
            await redisClient.del(getSocketQueueKey(socketId));
        }
    }
    return removedCount > 0;
}

async function removeFromQueues(playerId) {
    let removed = false;
    const queueKey = await redisClient.get(getPlayerQueueKey(playerId));
    if (queueKey) {
        removed = await removeFromQueueKey(queueKey, playerId);
        if (!removed) {
            const entryRaw = await redisClient.get(getQueueEntryKey(playerId));
            let socketId = null;
            if (entryRaw) {
                try {
                    socketId = JSON.parse(entryRaw).socketId;
                } catch (error) {
                    socketId = null;
                }
            }
            await redisClient.del(getPlayerQueueKey(playerId));
            await redisClient.del(getQueueEntryKey(playerId));
            if (socketId) {
                await redisClient.del(getSocketQueueKey(socketId));
            }
        }
    }

    if (!removed) {
        for (const { gameType, mode } of QUEUE_KEYS) {
            const key = getQueueKey(gameType, mode);
            if (await removeFromQueueKey(key, playerId)) {
                removed = true;
                break;
            }
        }
    }

    return removed;
}

async function cleanupStaleEntries() {
    const now = Date.now();

    const endedKeys = await redisClient.keys('ended_game:*');
    for (const key of endedKeys) {
        const ttl = await redisClient.pTTL(key);
        if (ttl === -1) {
            await redisClient.pExpire(key, DB_ENTRY_TTL_MS);
        }
    }

    const rateKeys = await redisClient.keys('rate_limit:*');
    for (const key of rateKeys) {
        const ttl = await redisClient.pTTL(key);
        if (ttl === -1) {
            await redisClient.pExpire(key, DB_ENTRY_TTL_MS);
        }
    }

    for (const { gameType, mode } of QUEUE_KEYS) {
        const queueKey = getQueueKey(gameType, mode);
        const playerIds = await redisClient.lRange(queueKey, 0, -1);
        for (const playerId of playerIds) {
            const entryRaw = await redisClient.get(getQueueEntryKey(playerId));
            if (!entryRaw) {
                await redisClient.lRem(queueKey, 0, playerId);
                continue;
            }
            try {
                const entry = JSON.parse(entryRaw);
                const queuedAt = entry.queuedAt ? new Date(entry.queuedAt).getTime() : 0;
                if (queuedAt && now - queuedAt > DB_ENTRY_TTL_MS) {
                    await redisClient.lRem(queueKey, 0, playerId);
                    await redisClient.del(getQueueEntryKey(playerId));
                    await redisClient.del(getPlayerQueueKey(playerId));
                    if (entry.socketId) {
                        await redisClient.del(getSocketQueueKey(entry.socketId));
                    }
                }
            } catch (error) {
                await redisClient.lRem(queueKey, 0, playerId);
                await redisClient.del(getQueueEntryKey(playerId));
                await redisClient.del(getPlayerQueueKey(playerId));
            }
        }
    }

    const lobbyKeys = await redisClient.keys('private_lobby:lobby:*');
    for (const key of lobbyKeys) {
        const raw = await redisClient.get(key);
        if (!raw) {
            await redisClient.del(key);
            continue;
        }

        let lobby = null;
        try {
            lobby = JSON.parse(raw);
        } catch (error) {
            await redisClient.del(key);
            continue;
        }

        if (!lobby?.lobbyId) {
            await redisClient.del(key);
            continue;
        }

        if (lobby.inGame) {
            await touchPrivateLobbyKeys(lobby.lobbyId);
            continue;
        }

        const lobbyId = lobby.lobbyId;
        const playerMap = await redisClient.hGetAll(getPrivateLobbyPlayersKey(lobbyId));
        const connectedIds = new Set(await redisClient.sMembers(getPrivateLobbyConnectedKey(lobbyId)));
        const connectedCount = connectedIds.size;

        for (const playerId of Object.keys(playerMap)) {
            if (connectedIds.has(playerId)) {
                await redisClient.del(getPrivateLobbyDisconnectKey(playerId));
                continue;
            }
            const disconnectKey = getPrivateLobbyDisconnectKey(playerId);
            const raw = await redisClient.get(disconnectKey);
            if (!raw) {
                await redisClient.set(disconnectKey, String(now), { PX: DB_ENTRY_TTL_MS });
                continue;
            }
            const disconnectedAt = parseInt(raw, 10);
            if (disconnectedAt && now - disconnectedAt > PRIVATE_LOBBY_DISCONNECT_GRACE_MS) {
                await removePlayerFromLobby(lobbyId, playerId);
                await redisClient.del(disconnectKey);
            }
        }

        if (connectedCount === 0) {
            const emptySince = lobby.emptySince ? new Date(lobby.emptySince).getTime() : 0;
            if (!emptySince) {
                lobby.emptySince = new Date().toISOString();
                await persistLobby(lobby);
            } else if (now - emptySince > PRIVATE_LOBBY_EMPTY_GRACE_MS) {
                await closePrivateLobby(lobbyId, 'empty');
                continue;
            }
        } else if (lobby.emptySince) {
            lobby.emptySince = null;
            await persistLobby(lobby);
        }

        const lastActivity = lobby.lastActivityAt ? new Date(lobby.lastActivityAt).getTime() : 0;
        if (lastActivity && now - lastActivity > PRIVATE_LOBBY_IDLE_MS) {
            await closePrivateLobby(lobbyId, 'idle');
        }
    }
}

async function popQueueItems(queueKey, count) {
    if (count <= 0) return [];
    const items = await redisClient.eval(POP_N_SCRIPT, {
        keys: [queueKey],
        arguments: [String(count)]
    });
    return Array.isArray(items) ? items : [];
}

function scheduleRetry(gameType, mode) {
    const key = `${gameType}:${mode}`;
    if (retryTimers.has(key)) return;
    const handle = setTimeout(() => {
        retryTimers.delete(key);
        attemptMatchmaking(gameType, mode);
    }, SESSION_CREATION_RETRY_DELAY_MS);
    retryTimers.set(key, handle);
}

async function createSessionForMatch(gameType, mode) {
    const url = gameType === 'dice'
        ? DICE_GAME_SERVER_URL
        : gameType === 'tictactoe'
            ? TICTACTOE_GAME_SERVER_URL
            : CARD_GAME_SERVER_URL;
    const body =
        gameType === 'dice'
            ? { playerCount: mode, turnTimeMs: DICE_TURN_TIME_MS }
            : gameType === 'tictactoe'
                ? { turnDurationSec: TICTACTOE_TURN_DURATION_SEC }
                : { playerCount: mode, turnDurationSec: CARD_TURN_DURATION_SEC };

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

async function createSessionFromConfig(gameType, config) {
    const url = gameType === 'dice'
        ? DICE_GAME_SERVER_URL
        : gameType === 'tictactoe'
            ? TICTACTOE_GAME_SERVER_URL
            : CARD_GAME_SERVER_URL;

    const body =
        gameType === 'dice'
            ? { playerCount: config.playerCount, turnTimeMs: config.turnTimeMs }
            : gameType === 'tictactoe'
                ? { turnDurationSec: config.turnDurationSec }
                : { playerCount: config.playerCount, turnDurationSec: config.turnDurationSec };

    for (let attempt = 1; attempt <= MAX_SESSION_CREATION_ATTEMPTS; attempt++) {
        try {
            console.log(`[Game Server] Attempt ${attempt} to create ${gameType} private session`);
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
        const requiredPlayers = mode;
        const queueKey = getQueueKey(gameType, mode);

        while ((await redisClient.lLen(queueKey)) >= requiredPlayers) {
            const candidateIds = await popQueueItems(queueKey, requiredPlayers);
            if (candidateIds.length < requiredPlayers) {
                break;
            }

            const candidates = [];
            for (const playerId of candidateIds) {
                const entryRaw = await redisClient.get(getQueueEntryKey(playerId));
                if (!entryRaw) {
                    await redisClient.del(getPlayerQueueKey(playerId));
                    continue;
                }
                let entry = null;
                try {
                    entry = JSON.parse(entryRaw);
                } catch (error) {
                    await redisClient.del(getQueueEntryKey(playerId));
                    await redisClient.del(getPlayerQueueKey(playerId));
                    continue;
                }

                const socket = io.sockets.sockets.get(entry.socketId);
                if (!socket || socket.disconnected) {
                    console.log(`[State] Dropping queued player ${entry.playerId} (socket offline).`);
                    await redisClient.del(getQueueEntryKey(playerId));
                    await redisClient.del(getPlayerQueueKey(playerId));
                    continue;
                }

                candidates.push(entry);
            }

            if (candidates.length < requiredPlayers) {
                for (let i = candidates.length - 1; i >= 0; i -= 1) {
                    await redisClient.lPush(queueKey, candidates[i].playerId);
                }
                break;
            }

            const sessionResult = await createSessionForMatch(gameType, mode);
            if (!sessionResult.ok) {
                console.error(`[Fatal] Failed to create ${gameType} session: ${sessionResult.message}`);
                for (let i = candidates.length - 1; i >= 0; i -= 1) {
                    await redisClient.lPush(queueKey, candidates[i].playerId);
                }
                for (const entry of candidates) {
                    io.to(entry.playerId)?.emit('match-error', { message: 'Could not create game session.' });
                }
                scheduleRetry(gameType, mode);
                break;
            }

            const { sessionId, joinUrl } = sessionResult;
            const voiceChannel = generateVoiceChannel(sessionId);
            const sessionKey = getActiveGameSessionKey(sessionId);
            for (const entry of candidates) {
                const activeKey = getActiveGamePlayerKey(entry.playerId);
                await redisClient.set(activeKey, JSON.stringify({
                    sessionId,
                    joinUrl,
                    gameType,
                    mode,
                    voiceChannel,
                    createdAt: new Date().toISOString()
                }), { PX: ACTIVE_GAMES_TTL_MS });
                await redisClient.sAdd(sessionKey, entry.playerId);
                await redisClient.pExpire(sessionKey, ACTIVE_GAMES_TTL_MS);
                await resetRateLimit(entry.playerId, entry.ip, entry.deviceId);
                await redisClient.del(getQueueEntryKey(entry.playerId));
                await redisClient.del(getPlayerQueueKey(entry.playerId));
                await redisClient.del(getSocketQueueKey(entry.socketId));
            }

            for (const entry of candidates) {
                io.to(entry.playerId).emit('match-found', { sessionId, joinUrl, gameType, mode, voiceChannel });
            }
        }

        await broadcastQueueStatus();
    } finally {
        matchingLocks.delete(key);
    }
}

// --- Main Application Logic ---

async function main() {
    await initializeRedis();
    setInterval(() => {
        cleanupStaleEntries().catch((error) => {
            console.error('[Cleanup] Failed to cleanup stale entries:', error.message);
        });
    }, CLEANUP_INTERVAL_MS);

    // --- HTTP ROUTES ---
    app.post('/session-closed', verifyWebhookSignature, async (req, res) => {
        const { sessionId } = req.body;
        console.log(`[Webhook] Received session-closed event for session: ${sessionId}`);

        if (!sessionId) {
            console.warn('[Webhook] Received session-closed event with no sessionId.');
            return res.status(400).send('Bad Request: sessionId is required.');
        }

        try {
            const sessionKey = getActiveGameSessionKey(sessionId);
            const playerIdsInSession = await redisClient.sMembers(sessionKey);

            if (!playerIdsInSession || playerIdsInSession.length === 0) {
                console.log(`[Webhook] No active players found for session ${sessionId}. It might have already been cleared.`);
                return res.status(200).send('Session already cleared or unknown.');
            }

            console.log(`[State] Clearing active session ${sessionId} for players: ${playerIdsInSession.join(', ')}`);

            const fallbackGameType = normalizeGameType(
                req.body?.gameType || req.body?.game_type || req.body?.game?.type
            );

            for (const playerId of playerIdsInSession) {
                console.log(`[Socket] Notifying player ${playerId} that session ${sessionId} has ended.`);
                let gameType = fallbackGameType || null;
                const activeRaw = await redisClient.get(getActiveGamePlayerKey(playerId));
                if (activeRaw) {
                    try {
                        const activeGame = JSON.parse(activeRaw);
                        if (activeGame?.gameType) {
                            gameType = normalizeGameType(activeGame.gameType) || gameType;
                        }
                    } catch (error) {
                    }
                }
                io.to(playerId).emit('session-ended', {
                    sessionId,
                    gameType,
                    outcome: resolveOutcome(req.body, playerId)
                });
                await redisClient.del(getActiveGamePlayerKey(playerId));
            }

            await redisClient.del(sessionKey);
            await redisClient.set(getEndedGameKey(sessionId), JSON.stringify({ ended_at: new Date().toISOString() }), {
                PX: DB_ENTRY_TTL_MS
            });

            const lobbyId = await redisClient.get(getPrivateLobbySessionKey(sessionId));
            if (lobbyId) {
                const lobby = await loadLobby(lobbyId);
                if (lobby) {
                    lobby.inGame = false;
                    lobby.sessionId = null;
                    lobby.lastActivityAt = new Date().toISOString();
                    if (!lobby.inGame) {
                        const connectedCount = await redisClient.sCard(getPrivateLobbyConnectedKey(lobbyId));
                        if (connectedCount === 0) {
                            lobby.emptySince = lobby.emptySince || new Date().toISOString();
                        }
                    }
                    await persistLobby(lobby);
                    await emitLobbyUpdate(lobbyId);
                }
                await redisClient.del(getPrivateLobbySessionKey(sessionId));
            }

            await broadcastQueueStatus();

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

        buildQueueStatus()
            .then((status) => socket.emit('queue-status', status))
            .catch((err) => {
                console.error('[Socket] Failed to send initial queue status:', err.message);
            });

        const handshakePlayerId =
            socket.handshake.auth?.playerId
            || socket.handshake.query?.playerId
            || socket.handshake.headers['x-player-id'];
        if (handshakePlayerId) {
            hydrateLobbyForSocket(socket, handshakePlayerId)
                .catch((err) => console.error('[Socket] Lobby hydrate failed:', err.message));
        }

        socket.on('request-match', async (data) => {
            try {
                const { playerId, playerName, gameType: rawGameType, mode: rawMode, deviceId } = data || {};
                if (!playerId || !playerName) {
                    return socket.emit('match-error', { message: 'playerId and playerName are required.' });
                }

                const gameType = normalizeGameType(rawGameType);
                if (!gameType) {
                    return socket.emit('match-error', { message: 'Invalid gameType. Use dice, tictactoe, or card.' });
                }

                const mode = normalizeMode(gameType, rawMode);
                if (!mode) {
                    return socket.emit('match-error', { message: 'Invalid mode. Dice: 2,4,6,15. Card: 2-6.' });
                }

                console.log(`[Socket] Match requested by PlayerID: ${playerId} (${gameType} ${mode})`);
                socket.join(playerId);

                const ip = getClientIp(socket);
                const activeRaw = await redisClient.get(getActiveGamePlayerKey(playerId));
                if (activeRaw) {
                    let activeGame = null;
                    try {
                        activeGame = JSON.parse(activeRaw);
                    } catch (error) {
                        await redisClient.del(getActiveGamePlayerKey(playerId));
                    }

                    if (activeGame) {
                        const { sessionId, joinUrl, gameType: activeGameType, mode: activeMode } = activeGame;
                        const resolvedGameType = activeGameType || 'tictactoe';
                        const resolvedMode = activeMode || 2;
                        const ended = await redisClient.exists(getEndedGameKey(sessionId));
                        if (ended) {
                            console.log(`[State] Player ${playerId} was in session ${sessionId}, but it has ended. Clearing and allowing to re-queue.`);
                            await redisClient.del(getActiveGamePlayerKey(playerId));
                            await redisClient.sRem(getActiveGameSessionKey(sessionId), playerId);
                        } else {
                            console.log(`[State] Player ${playerId} is already in an active game. Resending session details.`);
                            return socket.emit('match-found', { sessionId, joinUrl, gameType: resolvedGameType, mode: resolvedMode });
                        }
                    }
                }

                const privateLobbyId = await redisClient.get(getPrivateLobbyPlayerKey(playerId));
                if (privateLobbyId) {
                    return socket.emit('match-error', { message: 'You are already in a private lobby. Leave it before queueing.' });
                }

                const rateCheck = await registerQueueAction(playerId, ip, deviceId, { blockOnLimit: true });
                if (rateCheck.blocked) {
                    return socket.emit('match-error', {
                        message: 'Cooldown active. Please wait before re-queueing.',
                        cooldownUntil: rateCheck.cooldownUntil
                    });
                }

                await removeFromQueues(playerId);

                const queueKey = getQueueKey(gameType, mode);
                const entry = {
                    playerId,
                    playerName,
                    socketId: socket.id,
                    gameType,
                    mode,
                    queuedAt: new Date().toISOString(),
                    ip,
                    deviceId: deviceId || null
                };

                await redisClient.set(getQueueEntryKey(playerId), JSON.stringify(entry), { PX: DB_ENTRY_TTL_MS });
                await redisClient.set(getPlayerQueueKey(playerId), queueKey, { PX: DB_ENTRY_TTL_MS });
                await redisClient.set(getSocketQueueKey(socket.id), playerId, { PX: DB_ENTRY_TTL_MS });
                await redisClient.rPush(queueKey, playerId);

                await broadcastQueueStatus();
                await attemptMatchmaking(gameType, mode);
            } catch (err) {
                console.error('[FATAL] Unhandled error in request-match handler:', err);
                socket.emit('match-error', { message: 'An unexpected server error occurred.' });
            }
        });

        socket.on('cancel-match', async (data) => {
            try {
                const { playerId, deviceId } = data || {};
                if (!playerId) {
                    return socket.emit('match-error', { message: 'playerId is required to cancel.' });
                }

                const ip = getClientIp(socket);
                const removed = await removeFromQueues(playerId);
                await registerQueueAction(playerId, ip, deviceId, { blockOnLimit: false });
                await redisClient.del(getSocketQueueKey(socket.id));

                if (removed) {
                    socket.emit('queue-cancelled', { playerId });
                }
                await broadcastQueueStatus();
            } catch (err) {
                console.error('[FATAL] Unhandled error in cancel-match handler:', err);
                socket.emit('match-error', { message: 'An unexpected server error occurred while cancelling.' });
            }
        });

        socket.on('create-private-lobby', async (data) => {
            try {
                const { playerId, playerName, gameType: rawGameType, config, deviceId } = data || {};
                if (!playerId || !playerName) {
                    return socket.emit('match-error', { message: 'playerId and playerName are required.' });
                }

                const gameType = normalizeGameType(rawGameType);
                if (!gameType) {
                    return socket.emit('match-error', { message: 'Invalid gameType. Use dice, tictactoe, or card.' });
                }

                const parsed = parseLobbyConfig(gameType, config);
                if (parsed.error) {
                    return socket.emit('match-error', { message: parsed.error });
                }

                socket.join(playerId);

                const activeRaw = await redisClient.get(getActiveGamePlayerKey(playerId));
                if (activeRaw) {
                    let activeGame = null;
                    try {
                        activeGame = JSON.parse(activeRaw);
                    } catch (error) {
                        await redisClient.del(getActiveGamePlayerKey(playerId));
                    }
                    if (activeGame) {
                        return socket.emit('match-error', { message: 'You are already in an active game.' });
                    }
                }

                const existingLobbyId = await redisClient.get(getPrivateLobbyPlayerKey(playerId));
                if (existingLobbyId) {
                    return socket.emit('match-error', { message: 'You are already in a private lobby.' });
                }

                await removeFromQueues(playerId);

                const lobbyId = createLobbyId();
                const now = new Date().toISOString();
                const lobby = {
                    lobbyId,
                    adminPlayerId: playerId,
                    gameType,
                    mode: parsed.mode,
                    playerCount: parsed.mode,
                    config: parsed.config,
                    inGame: false,
                    sessionId: null,
                    voiceChannel: generateVoiceChannel(null, lobbyId),
                    createdAt: now,
                    updatedAt: now,
                    lastActivityAt: now,
                    emptySince: null
                };

                await persistLobby(lobby);

                const playerData = {
                    playerId,
                    playerName,
                    joinedAt: now,
                    ip: getClientIp(socket),
                    deviceId: deviceId || null
                };

                const previousSocketId = await redisClient.get(getPrivateLobbyPlayerSocketKey(playerId));
                if (previousSocketId && previousSocketId !== socket.id) {
                    await redisClient.del(getPrivateLobbySocketKey(previousSocketId));
                }

                await redisClient.hSet(getPrivateLobbyPlayersKey(lobbyId), playerId, JSON.stringify(playerData));
                await redisClient.sAdd(getPrivateLobbyConnectedKey(lobbyId), playerId);
                await redisClient.set(getPrivateLobbyPlayerKey(playerId), lobbyId, { PX: DB_ENTRY_TTL_MS });
                await redisClient.set(getPrivateLobbyPlayerSocketKey(playerId), socket.id, { PX: DB_ENTRY_TTL_MS });
                await redisClient.set(getPrivateLobbySocketKey(socket.id), JSON.stringify({ lobbyId, playerId }), { PX: DB_ENTRY_TTL_MS });
                await redisClient.del(getPrivateLobbyDisconnectKey(playerId));
                await redisClient.del(getPrivateLobbyDisconnectKey(playerId));

                await touchPrivateLobbyKeys(lobbyId);

                socket.join(getPrivateLobbyRoom(lobbyId));

                const state = await buildLobbyState(lobbyId);
                socket.emit('private-lobby-created', state);
                io.to(getPrivateLobbyRoom(lobbyId)).emit('private-lobby-updated', state);
            } catch (err) {
                console.error('[FATAL] Unhandled error in create-private-lobby handler:', err);
                socket.emit('match-error', { message: 'An unexpected server error occurred while creating a lobby.' });
            }
        });

        socket.on('join-private-lobby', async (data) => {
            try {
                const { lobbyId, playerId, playerName, deviceId } = data || {};
                if (!lobbyId || !playerId || !playerName) {
                    return socket.emit('match-error', { message: 'lobbyId, playerId, and playerName are required.' });
                }

                const lobby = await loadLobby(lobbyId);
                if (!lobby) {
                    return socket.emit('match-error', { message: 'Private lobby not found.' });
                }

                const activeRaw = await redisClient.get(getActiveGamePlayerKey(playerId));
                if (activeRaw) {
                    let activeGame = null;
                    try {
                        activeGame = JSON.parse(activeRaw);
                    } catch (error) {
                        await redisClient.del(getActiveGamePlayerKey(playerId));
                    }
                    if (activeGame) {
                        return socket.emit('match-error', { message: 'You are already in an active game.' });
                    }
                }

                const existingLobbyId = await redisClient.get(getPrivateLobbyPlayerKey(playerId));
                if (existingLobbyId && existingLobbyId !== lobbyId) {
                    return socket.emit('match-error', { message: 'You are already in another private lobby.' });
                }

                // Ignore client gameType/config; lobby settings are the source of truth.

                const playerMap = await redisClient.hGetAll(getPrivateLobbyPlayersKey(lobbyId));
                const isMember = Object.prototype.hasOwnProperty.call(playerMap, playerId);
                if (!isMember && Object.keys(playerMap).length >= lobby.playerCount) {
                    return socket.emit('match-error', { message: 'Private lobby is full.' });
                }

                socket.join(playerId);

                const now = new Date().toISOString();
                let joinedAt = now;
                if (isMember) {
                    try {
                        joinedAt = JSON.parse(playerMap[playerId]).joinedAt || joinedAt;
                    } catch (error) {
                        joinedAt = joinedAt;
                    }
                }
                const playerData = {
                    playerId,
                    playerName,
                    joinedAt,
                    ip: getClientIp(socket),
                    deviceId: deviceId || null
                };

                const previousSocketId = await redisClient.get(getPrivateLobbyPlayerSocketKey(playerId));
                if (previousSocketId && previousSocketId !== socket.id) {
                    await redisClient.del(getPrivateLobbySocketKey(previousSocketId));
                }

                await removeFromQueues(playerId);

                await redisClient.hSet(getPrivateLobbyPlayersKey(lobbyId), playerId, JSON.stringify(playerData));
                await redisClient.sAdd(getPrivateLobbyConnectedKey(lobbyId), playerId);
                await redisClient.set(getPrivateLobbyPlayerKey(playerId), lobbyId, { PX: DB_ENTRY_TTL_MS });
                await redisClient.set(getPrivateLobbyPlayerSocketKey(playerId), socket.id, { PX: DB_ENTRY_TTL_MS });
                await redisClient.set(getPrivateLobbySocketKey(socket.id), JSON.stringify({ lobbyId, playerId }), { PX: DB_ENTRY_TTL_MS });

                lobby.lastActivityAt = now;
                lobby.emptySince = null;
                await persistLobby(lobby);

                socket.join(getPrivateLobbyRoom(lobbyId));
                const state = await buildLobbyState(lobbyId);
                socket.emit('private-lobby-joined', state);
                io.to(getPrivateLobbyRoom(lobbyId)).emit('private-lobby-updated', state);
            } catch (err) {
                console.error('[FATAL] Unhandled error in join-private-lobby handler:', err);
                socket.emit('match-error', { message: 'An unexpected server error occurred while joining a lobby.' });
            }
        });

        socket.on('leave-private-lobby', async (data) => {
            try {
                const { lobbyId: requestedLobbyId, playerId } = data || {};
                if (!playerId) {
                    return socket.emit('match-error', { message: 'playerId is required.' });
                }

                const currentLobbyId = await redisClient.get(getPrivateLobbyPlayerKey(playerId));
                const lobbyId = requestedLobbyId || currentLobbyId;
                if (!lobbyId || !currentLobbyId || currentLobbyId !== lobbyId) {
                    return socket.emit('match-error', { message: 'You are not in that private lobby.' });
                }

                await removePlayerFromLobby(lobbyId, playerId);
                await redisClient.del(getPrivateLobbyDisconnectKey(playerId));
                socket.leave(getPrivateLobbyRoom(lobbyId));
                socket.emit('private-lobby-left', { lobbyId, playerId });
            } catch (err) {
                console.error('[FATAL] Unhandled error in leave-private-lobby handler:', err);
                socket.emit('match-error', { message: 'An unexpected server error occurred while leaving a lobby.' });
            }
        });

        socket.on('kick-private-lobby', async (data) => {
            try {
                const { lobbyId, playerId, targetPlayerId } = data || {};
                if (!lobbyId || !playerId || !targetPlayerId) {
                    return socket.emit('match-error', { message: 'lobbyId, playerId, and targetPlayerId are required.' });
                }

                const lobby = await loadLobby(lobbyId);
                if (!lobby) {
                    return socket.emit('match-error', { message: 'Private lobby not found.' });
                }
                if (lobby.adminPlayerId !== playerId) {
                    return socket.emit('match-error', { message: 'Only the lobby admin can kick players.' });
                }
                if (playerId === targetPlayerId) {
                    return socket.emit('match-error', { message: 'Admin cannot kick themselves.' });
                }

                const playerMap = await redisClient.hGetAll(getPrivateLobbyPlayersKey(lobbyId));
                if (!Object.prototype.hasOwnProperty.call(playerMap, targetPlayerId)) {
                    return socket.emit('match-error', { message: 'Target player is not in the lobby.' });
                }

                await removePlayerFromLobby(lobbyId, targetPlayerId, { kicked: true });
            } catch (err) {
                console.error('[FATAL] Unhandled error in kick-private-lobby handler:', err);
                socket.emit('match-error', { message: 'An unexpected server error occurred while kicking a player.' });
            }
        });

        socket.on('start-private-lobby', async (data) => {
            try {
                const { lobbyId, playerId } = data || {};
                if (!lobbyId || !playerId) {
                    return socket.emit('match-error', { message: 'lobbyId and playerId are required.' });
                }

                const lobby = await loadLobby(lobbyId);
                if (!lobby) {
                    return socket.emit('match-error', { message: 'Private lobby not found.' });
                }
                if (lobby.adminPlayerId !== playerId) {
                    return socket.emit('match-error', { message: 'Only the lobby admin can start the match.' });
                }
                if (lobby.inGame) {
                    return socket.emit('match-error', { message: 'Lobby is already in a game.' });
                }

                const playerMap = await redisClient.hGetAll(getPrivateLobbyPlayersKey(lobbyId));
                const playerIds = Object.keys(playerMap);
                const connectedCount = await redisClient.sCard(getPrivateLobbyConnectedKey(lobbyId));
                if (playerIds.length !== lobby.playerCount || connectedCount !== lobby.playerCount) {
                    return socket.emit('match-error', { message: 'Lobby must be full and all players connected before starting.' });
                }

                const sessionResult = await createSessionFromConfig(lobby.gameType, lobby.config);
                if (!sessionResult.ok) {
                    return socket.emit('match-error', { message: `Could not create game session: ${sessionResult.message}` });
                }

                const { sessionId, joinUrl } = sessionResult;
                const voiceChannel = lobby.voiceChannel || generateVoiceChannel(sessionId, lobby.lobbyId);
                const sessionKey = getActiveGameSessionKey(sessionId);
                const now = new Date().toISOString();

                for (const playerIdInLobby of playerIds) {
                    const activeKey = getActiveGamePlayerKey(playerIdInLobby);
                    await redisClient.set(activeKey, JSON.stringify({
                        sessionId,
                        joinUrl,
                        gameType: lobby.gameType,
                        mode: lobby.mode,
                        voiceChannel,
                        createdAt: now
                    }), { PX: ACTIVE_GAMES_TTL_MS });
                    await redisClient.sAdd(sessionKey, playerIdInLobby);
                    await redisClient.pExpire(sessionKey, ACTIVE_GAMES_TTL_MS);

                    try {
                        const stored = JSON.parse(playerMap[playerIdInLobby]);
                        await resetRateLimit(playerIdInLobby, stored?.ip, stored?.deviceId);
                    } catch (error) {
                        await resetRateLimit(playerIdInLobby, null, null);
                    }
                }

                lobby.inGame = true;
                lobby.sessionId = sessionId;
                lobby.voiceChannel = voiceChannel;
                lobby.lastActivityAt = now;
                lobby.emptySince = null;
                await persistLobby(lobby);
                await redisClient.set(getPrivateLobbySessionKey(sessionId), lobbyId, { PX: ACTIVE_GAMES_TTL_MS });

                for (const playerIdInLobby of playerIds) {
                    io.to(playerIdInLobby).emit('match-found', {
                        sessionId,
                        joinUrl,
                        gameType: lobby.gameType,
                        mode: lobby.mode
                    });
                }

                await emitLobbyUpdate(lobbyId);
            } catch (err) {
                console.error('[FATAL] Unhandled error in start-private-lobby handler:', err);
                socket.emit('match-error', { message: 'An unexpected server error occurred while starting the lobby.' });
            }
        });

        socket.on('disconnect', async () => {
            console.log(`[Socket] Client disconnected: ${socket.id}`);
            try {
                const queuedPlayerId = await redisClient.get(getSocketQueueKey(socket.id));
                if (!queuedPlayerId) {
                    // continue to lobby cleanup
                } else {
                    const removed = await removeFromQueues(queuedPlayerId);
                    await redisClient.del(getSocketQueueKey(socket.id));
                    if (removed) {
                        console.log(`[State] Player ${queuedPlayerId} removed from queue due to disconnect.`);
                        await broadcastQueueStatus();
                    }
                }

                const lobbySocketRaw = await redisClient.get(getPrivateLobbySocketKey(socket.id));
                if (!lobbySocketRaw) {
                    return;
                }

                let lobbySocket = null;
                try {
                    lobbySocket = JSON.parse(lobbySocketRaw);
                } catch (error) {
                    lobbySocket = null;
                }

                if (!lobbySocket?.lobbyId || !lobbySocket?.playerId) {
                    await redisClient.del(getPrivateLobbySocketKey(socket.id));
                    return;
                }

                const currentSocketId = await redisClient.get(getPrivateLobbyPlayerSocketKey(lobbySocket.playerId));
                if (currentSocketId && currentSocketId !== socket.id) {
                    await redisClient.del(getPrivateLobbySocketKey(socket.id));
                    return;
                }

                await redisClient.del(getPrivateLobbySocketKey(socket.id));
                await redisClient.del(getPrivateLobbyPlayerSocketKey(lobbySocket.playerId));
                await redisClient.sRem(getPrivateLobbyConnectedKey(lobbySocket.lobbyId), lobbySocket.playerId);
                await redisClient.set(getPrivateLobbyDisconnectKey(lobbySocket.playerId), String(Date.now()), { PX: DB_ENTRY_TTL_MS });

                const lobby = await loadLobby(lobbySocket.lobbyId);
                if (lobby && !lobby.inGame) {
                    const connectedCount = await redisClient.sCard(getPrivateLobbyConnectedKey(lobbySocket.lobbyId));
                    if (connectedCount === 0) {
                        lobby.emptySince = lobby.emptySince || new Date().toISOString();
                    }
                    await persistLobby(lobby);
                    await emitLobbyUpdate(lobbySocket.lobbyId);
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

                const activeRaw = await redisClient.get(getActiveGamePlayerKey(playerId));
                let activeGame = null;
                if (activeRaw) {
                    try {
                        activeGame = JSON.parse(activeRaw);
                    } catch (error) {
                        await redisClient.del(getActiveGamePlayerKey(playerId));
                    }
                }

                if (activeGame && activeGame.sessionId === sessionId) {
                    console.log(`[State] Player ${playerId} reported invalid session ${sessionId}. Clearing active game entry.`);

                    await redisClient.del(getActiveGamePlayerKey(playerId));
                    const sessionKey = getActiveGameSessionKey(sessionId);
                    await redisClient.sRem(sessionKey, playerId);
                    const remaining = await redisClient.sCard(sessionKey);
                    if (remaining === 0) {
                        await redisClient.del(sessionKey);
                    }
                    const removedFromQueue = await removeFromQueues(playerId);

                    const lobbyId = await redisClient.get(getPrivateLobbySessionKey(sessionId));
                    if (lobbyId) {
                        const lobby = await loadLobby(lobbyId);
                        if (lobby) {
                            lobby.inGame = false;
                            lobby.sessionId = null;
                            lobby.lastActivityAt = new Date().toISOString();
                            await persistLobby(lobby);
                            await emitLobbyUpdate(lobbyId);
                        }
                        await redisClient.del(getPrivateLobbySessionKey(sessionId));
                    }

                    socket.emit('session-cleared', { playerId, sessionId, removedFromQueue });
                    await broadcastQueueStatus();
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
