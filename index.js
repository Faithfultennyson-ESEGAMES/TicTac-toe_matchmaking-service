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
const DB_ENTRY_TTL_MS = parseInt(process.env.DB_ENTRY_TTL_MS, 10) || 3600000;
const MAX_SESSION_CREATION_ATTEMPTS = parseInt(process.env.MAX_SESSION_CREATION_ATTEMPTS, 10) || 3;
const SESSION_CREATION_RETRY_DELAY_MS = parseInt(process.env.SESSION_CREATION_RETRY_DELAY_MS, 10) || 1500;

if (!DLQ_PASSWORD || !HMAC_SECRET) {
    console.error('FATAL ERROR: DLQ_PASSWORD and HMAC_SECRET must be defined in .env file.');
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
    db.data = db.data || {
        queue: [],
        active_games: {},
        ended_games: {}
    };
    await db.write();
}

// --- Helper Functions ---
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

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

        socket.on('request-match', async (data) => {
            try {
                const { playerId, playerName } = data;
                if (!playerId) {
                    return socket.emit('match-error', { message: 'PlayerId is required.' });
                }
                console.log(`[Socket] Match requested by PlayerID: ${playerId}`);

                socket.join(playerId);

                await db.read();

                if (db.data.active_games[playerId]) {
                    const { sessionId, joinUrl } = db.data.active_games[playerId];
                    if (db.data.ended_games[sessionId]) {
                        console.log(`[State] Player ${playerId} was in session ${sessionId}, but it has ended. Clearing and allowing to re-queue.`);
                        delete db.data.active_games[playerId];
                        await db.write();
                    } else {
                        console.log(`[State] Player ${playerId} is already in an active game. Resending session details.`);
                        return socket.emit('match-found', { sessionId, joinUrl });
                    }
                }

                if (!db.data.queue.some(p => p.playerId === playerId)) {
                    db.data.queue.push({ playerId, playerName, socketId: socket.id });
                    await db.write();
                    console.log(`[State] Player ${playerId} added to queue. Queue size: ${db.data.queue.length}`);
                }

                if (db.data.queue.length >= 2) {
                    const [player1, player2] = db.data.queue.splice(0, 2);
                    await db.write();
                    console.log(`[Match] Found a match between ${player1.playerId} and ${player2.playerId}.`);

                    for (let attempt = 1; attempt <= MAX_SESSION_CREATION_ATTEMPTS; attempt++) {
                        try {
                            console.log(`[Game Server] Attempt ${attempt} to create session for players: ${player1.playerId}, ${player2.playerId}`);
                            const response = await fetch(`${GAME_SERVER_URL}/start`, {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                    'Authorization': `Bearer ${DLQ_PASSWORD}`
                                }
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
                            
                            const body = JSON.parse(rawBody);
                            const { sessionId, joinUrl } = body;

                            if (!sessionId || !joinUrl) {
                                throw new Error('Invalid response payload from game server');
                            }

                            console.log(`[Game Server] Successfully created and verified session ${sessionId}`);

                            db.data.active_games[player1.playerId] = { sessionId, joinUrl };
                            db.data.active_games[player2.playerId] = { sessionId, joinUrl };
                            await db.write();

                            io.to(player1.playerId).emit('match-found', { sessionId, joinUrl });
                            io.to(player2.playerId).emit('match-found', { sessionId, joinUrl });

                            break;

                        } catch (error) {
                            console.error(`[Error] Attempt ${attempt} failed:`, error.message);
                            if (attempt < MAX_SESSION_CREATION_ATTEMPTS) {
                                await delay(SESSION_CREATION_RETRY_DELAY_MS);
                            } else {
                                console.error('[Fatal] All attempts to create a game session failed.');
                                await db.read();
                                if (!db.data.queue.some(p => p.playerId === player1.playerId)) { db.data.queue.unshift(player1); }
                                if (!db.data.queue.some(p => p.playerId === player2.playerId)) { db.data.queue.unshift(player2); }
                                await db.write();

                                io.to(player1.playerId)?.emit('match-error', { message: 'Could not create game session.' });
                                io.to(player2.playerId)?.emit('match-error', { message: 'Could not create game session.' });
                            }
                        }
                    }
                }
            } catch (err) {
                console.error('[FATAL] Unhandled error in request-match handler:', err);
                socket.emit('match-error', { message: 'An unexpected server error occurred.' });
            }
        });

        socket.on('disconnect', async () => {
            console.log(`[Socket] Client disconnected: ${socket.id}`);
            try {
                await db.read();
                const index = db.data.queue.findIndex(p => p.socketId === socket.id);
                if (index !== -1) {
                    const { playerId } = db.data.queue.splice(index, 1)[0];
                    console.log(`[State] Player ${playerId} removed from queue due to disconnect.`);
                    await db.write();
                }
            } catch (err) {
                console.error('[FATAL] Unhandled error in disconnect handler:', err);
            }
        });

        socket.on('report-invalid-session', async (data) => {
            try {
                const { playerId, playerName, sessionId } = data;
                if (!playerId || !sessionId) {
                    return socket.emit('match-error', { message: 'PlayerId and SessionId are required to report an invalid session.' });
                }

                await db.read();
                
                const activeGame = db.data.active_games[playerId];

                if (activeGame && activeGame.sessionId === sessionId) {
                    console.log(`[State] Player ${playerId} reported invalid session ${sessionId}. Removing from active games and re-queuing.`);
                    
                    delete db.data.active_games[playerId];
                    
                    if (!db.data.queue.some(p => p.playerId === playerId)) {
                        db.data.queue.push({ playerId, playerName: playerName || 'Unknown', socketId: socket.id });
                    }
                    
                    await db.write();
                    
                    socket.emit('requeued-successfully');

                    // Immediately try to matchmake again
                    if (db.data.queue.length >= 2) {
                        // This part is already handled by the 'request-match' logic, let's keep it simple
                        // and let the next 'request-match' from a client trigger the check.
                        // For simplicity, we can just check if we can form a match now.
                        console.log('[State] Checking for new match after re-queue...');
                        // The logic to start a new match is complex, we'll let the natural flow handle it
                        // when another player requests a match. This is safer than re-implementing it here.
                    }
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
