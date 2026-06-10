// ============================================================
// HACKER CLASS - Full Backend Server
// Node.js + Express + Socket.IO + MySQL + WebRTC Signaling
// ============================================================

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
require('dotenv').config();

// --- Configuration ---
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: '*',
        methods: ['GET', 'POST']
    },
    maxHttpBufferSize: 50 * 1024 * 1024 // 50MB for file uploads via socket
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'hacker-class-secret-key-2026';
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// Ensure upload directories exist
['images', 'videos', 'audio', 'files', 'thumbnails'].forEach(dir => {
    const p = path.join(UPLOAD_DIR, dir);
    if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
});

// --- MySQL Connection Pool ---
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'hacker_class_db',
    waitForConnections: true,
    connectionLimit: 20,
    queueLimit: 0,
    charset: 'utf8mb4'
});

// Test database connection
(async () => {
    try {
        const conn = await pool.getConnection();
        console.log('[DB] Connected to MySQL database');
        conn.release();
    } catch (err) {
        console.error('[DB] Failed to connect:', err.message);
        process.exit(1);
    }
})();

// --- Middleware ---
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(express.static(path.join(__dirname, 'public')));

// --- Multer Configuration for File Uploads ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        let subdir = 'files';
        if (file.mimetype.startsWith('image/')) subdir = 'images';
        else if (file.mimetype.startsWith('video/')) subdir = 'videos';
        else if (file.mimetype.startsWith('audio/')) subdir = 'audio';
        cb(null, path.join(UPLOAD_DIR, subdir));
    },
    filename: (req, file, cb) => {
        const uniqueName = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
    fileFilter: (req, file, cb) => {
        const allowed = [
            'image/jpeg', 'image/png', 'image/gif', 'image/webp',
            'video/mp4', 'video/webm', 'video/ogg',
            'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/webm',
            'application/pdf', 'application/zip', 'text/plain'
        ];
        if (allowed.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('File type not allowed'), false);
        }
    }
});

// --- JWT Authentication Middleware ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// ============================================================
// REST API ENDPOINTS
// ============================================================

// --- AUTH ---

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, displayName } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }
        
        if (username.length < 3 || username.length > 50) {
            return res.status(400).json({ error: 'Username must be 3-50 characters' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        // Check if user exists
        const [existing] = await pool.query(
            'SELECT id FROM users WHERE username = ?',
            [username]
        );
        
        if (existing.length > 0) {
            return res.status(409).json({ error: 'Username already taken' });
        }

        const passwordHash = await bcrypt.hash(password, 12);
        
        const [result] = await pool.query(
            'INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)',
            [username, passwordHash, displayName || username]
        );

        const token = jwt.sign(
            { id: result.insertId, username },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            message: 'User registered successfully',
            user: { id: result.insertId, username, displayName: displayName || username },
            token
        });
    } catch (err) {
        console.error('[AUTH] Register error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        const [users] = await pool.query(
            'SELECT id, username, password_hash, display_name, avatar_url FROM users WHERE username = ?',
            [username]
        );
        
        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update status
        await pool.query(
            'UPDATE users SET status = ? WHERE id = ?',
            ['online', user.id]
        );

        const token = jwt.sign(
            { id: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            user: {
                id: user.id,
                username: user.username,
                displayName: user.display_name,
                avatarUrl: user.avatar_url
            },
            token
        });
    } catch (err) {
        console.error('[AUTH] Login error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Verify token / get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const [users] = await pool.query(
            'SELECT id, username, display_name, avatar_url, status, last_seen FROM users WHERE id = ?',
            [req.user.id]
        );
        
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ user: users[0] });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// --- ROOMS ---

// Create or get room
app.post('/api/rooms/join', authenticateToken, async (req, res) => {
    try {
        const { roomCode, password } = req.body;
        
        if (!roomCode) {
            return res.status(400).json({ error: 'Room code required' });
        }

        // Check if room exists
        let [rooms] = await pool.query(
            'SELECT * FROM rooms WHERE room_code = ?',
            [roomCode]
        );

        let roomId;
        
        if (rooms.length === 0) {
            // Create new room
            const [result] = await pool.query(
                'INSERT INTO rooms (room_code, room_name, created_by) VALUES (?, ?, ?)',
                [roomCode, roomCode, req.user.id]
            );
            roomId = result.insertId;
            
            // Creator is owner
            await pool.query(
                'INSERT INTO room_members (room_id, user_id, role) VALUES (?, ?, ?)',
                [roomId, req.user.id, 'owner']
            );
        } else {
            roomId = rooms[0].id;
            
            // Check password if room is private
            if (rooms[0].password_hash) {
                if (!password) {
                    return res.status(403).json({ error: 'Room code is password protected' });
                }
                const valid = await bcrypt.compare(password, rooms[0].password_hash);
                if (!valid) {
                    return res.status(403).json({ error: 'Invalid room password' });
                }
            }

            // Check if user is already a member
            const [members] = await pool.query(
                'SELECT id FROM room_members WHERE room_id = ? AND user_id = ?',
                [roomId, req.user.id]
            );

            if (members.length === 0) {
                // Check max members
                const [memberCount] = await pool.query(
                    'SELECT COUNT(*) as count FROM room_members WHERE room_id = ?',
                    [roomId]
                );
                
                if (memberCount[0].count >= (rooms[0].max_members || 50)) {
                    return res.status(403).json({ error: 'Room is full' });
                }

                // Join room
                await pool.query(
                    'INSERT INTO room_members (room_id, user_id, role) VALUES (?, ?, ?)',
                    [roomId, req.user.id, 'member']
                );
            }
        }

        res.json({
            message: 'Joined room successfully',
            room: {
                id: roomId,
                roomCode,
                roomName: rooms[0]?.room_name || roomCode
            }
        });
    } catch (err) {
        console.error('[ROOMS] Join error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get room members
app.get('/api/rooms/:roomCode/members', authenticateToken, async (req, res) => {
    try {
        const [members] = await pool.query(
            `SELECT u.id, u.username, u.display_name, u.avatar_url, u.status, 
                    rm.role, rm.joined_at
             FROM room_members rm
             JOIN users u ON rm.user_id = u.id
             JOIN rooms r ON rm.room_id = r.id
             WHERE r.room_code = ?`,
            [req.params.roomCode]
        );
        
        res.json({ members });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// --- MESSAGES ---

// Get message history for a room
app.get('/api/rooms/:roomCode/messages', authenticateToken, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const offset = parseInt(req.query.offset) || 0;
        const before = req.query.before; // timestamp for infinite scroll

        let query = `
            SELECT m.*, u.username AS sender_username, u.avatar_url AS sender_avatar
            FROM messages m
            JOIN rooms r ON m.room_id = r.id
            JOIN users u ON m.sender_id = u.id
            WHERE r.room_code = ? AND m.is_deleted = 0
        `;
        const params = [req.params.roomCode];

        if (before) {
            query += ' AND m.created_at < ?';
            params.push(before);
        }

        query += ' ORDER BY m.created_at DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);

        const [messages] = await pool.query(query, params);
        
        res.json({ messages: messages.reverse() }); // reverse for chronological order
    } catch (err) {
        console.error('[MESSAGES] Get error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete a message
app.delete('/api/messages/:messageId', authenticateToken, async (req, res) => {
    try {
        const [messages] = await pool.query(
            'SELECT sender_id FROM messages WHERE id = ?',
            [req.params.messageId]
        );
        
        if (messages.length === 0) {
            return res.status(404).json({ error: 'Message not found' });
        }

        if (messages[0].sender_id !== req.user.id) {
            return res.status(403).json({ error: 'Not authorized to delete this message' });
        }

        await pool.query(
            'UPDATE messages SET is_deleted = 1 WHERE id = ?',
            [req.params.messageId]
        );

        res.json({ message: 'Message deleted' });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// --- FILE UPLOAD (HTTP) ---
app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const file = req.file;
        const roomCode = req.body.roomCode;

        // Save file metadata to database
        const [result] = await pool.query(
            `INSERT INTO uploaded_files 
             (original_name, stored_name, file_path, file_size, mime_type, uploaded_by, room_id)
             VALUES (?, ?, ?, ?, ?, ?, 
                (SELECT id FROM rooms WHERE room_code = ?))`,
            [file.originalname, file.filename, file.path, file.size, file.mimetype,
             req.user.id, roomCode]
        );

        // Create a system message for the file
        const fileUrl = `/uploads/${file.destination.split('/').pop()}/${file.filename}`;
        
        let messageType = 'file';
        if (file.mimetype.startsWith('image/')) messageType = 'image';
        else if (file.mimetype.startsWith('video/')) messageType = 'video';
        else if (file.mimetype.startsWith('audio/')) messageType = 'audio';

        const [msgResult] = await pool.query(
            `INSERT INTO messages (room_id, sender_id, message_type, content, file_url, file_name, file_size, file_mime_type)
             VALUES ((SELECT id FROM rooms WHERE room_code = ?), ?, ?, ?, ?, ?, ?, ?)`,
            [roomCode, req.user.id, messageType, file.originalname, fileUrl,
             file.originalname, file.size, file.mimetype]
        );

        // Update file record with message ID
        await pool.query(
            'UPDATE uploaded_files SET message_id = ? WHERE id = ?',
            [msgResult.insertId, result.insertId]
        );

        res.json({
            message: 'File uploaded successfully',
            file: {
                id: result.insertId,
                messageId: msgResult.insertId,
                url: fileUrl,
                name: file.originalname,
                size: file.size,
                type: file.mimetype
            }
        });
    } catch (err) {
        console.error('[UPLOAD] Error:', err);
        res.status(500).json({ error: 'Upload failed' });
    }
});

// --- CALL LOGS ---
app.post('/api/calls/log', authenticateToken, async (req, res) => {
    try {
        const { roomCode, calleeId, callType, status, duration } = req.body;
        
        const [result] = await pool.query(
            `INSERT INTO call_logs (room_id, caller_id, callee_id, call_type, status, duration_seconds)
             VALUES ((SELECT id FROM rooms WHERE room_code = ?), ?, ?, ?, ?, ?)`,
            [roomCode, req.user.id, calleeId, callType || 'audio', status || 'ended', duration || 0]
        );

        res.json({ callLogId: result.insertId });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ============================================================
// SOCKET.IO - Real-time Communication
// ============================================================

// Track online users per room
const onlineUsers = new Map(); // roomCode => Map(userId => { socketId, username, peerId })

io.on('connection', (socket) => {
    console.log(`[SOCKET] New connection: ${socket.id}`);

    let currentUser = null;
    let currentRoom = null;

    // --- HANDLE JOIN ROOM ---
    socket.on('join-room', async (data) => {
        try {
            const { roomCode, username, userId, peerId } = data;
            
            if (!roomCode || !username) {
                socket.emit('error', { message: 'Room code and username required' });
                return;
            }

            currentUser = { id: userId, username, peerId };
            currentRoom = roomCode;

            // Join Socket.IO room
            socket.join(roomCode);

            // Track online users
            if (!onlineUsers.has(roomCode)) {
                onlineUsers.set(roomCode, new Map());
            }
            
            const roomUsers = onlineUsers.get(roomCode);
            roomUsers.set(userId || socket.id, {
                socketId: socket.id,
                username,
                peerId,
                joinedAt: new Date()
            });

            // Store socket-to-user mapping
            socket.data.user = { userId, username, peerId };
            socket.data.room = roomCode;

            // Update DB: user status
            if (userId) {
                await pool.query('UPDATE users SET status = ? WHERE id = ?', ['online', userId]);
                
                // Save peer session
                await pool.query(
                    `INSERT INTO peer_sessions (user_id, peer_id, socket_id, is_active)
                     VALUES (?, ?, ?, 1)
                     ON DUPLICATE KEY UPDATE socket_id = ?, is_active = 1, disconnected_at = NULL`,
                    [userId, peerId || socket.id, socket.id, socket.id]
                );
            }

            // Notify others in room
            socket.to(roomCode).emit('user-joined', {
                userId: userId || socket.id,
                username,
                peerId,
                onlineUsers: Array.from(roomUsers.values()).map(u => ({
                    userId: u.userId,
                    username: u.username,
                    peerId: u.peerId
                }))
            });

            // Send current online users to the joining user
            socket.emit('room-users', {
                onlineUsers: Array.from(roomUsers.values()).map(u => ({
                    userId: u.userId,
                    username: u.username,
                    peerId: u.peerId
                }))
            });

            // Insert system message
            if (userId) {
                const [rooms] = await pool.query('SELECT id FROM rooms WHERE room_code = ?', [roomCode]);
                if (rooms.length > 0) {
                    // Store system message for join
                    await pool.query(
                        `INSERT INTO messages (room_id, sender_id, message_type, content)
                         VALUES (?, ?, 'system', ?)`,
                        [rooms[0].id, userId, `${username} joined the room`]
                    );
                }
            }

            console.log(`[ROOM] ${username} joined ${roomCode} (${roomUsers.size} online)`);
            
            // Send updated online count
            io.to(roomCode).emit('online-count', { count: roomUsers.size });

        } catch (err) {
            console.error('[JOIN] Error:', err);
            socket.emit('error', { message: 'Failed to join room' });
        }
    });

    // --- HANDLE CHAT MESSAGES ---
    socket.on('chat-message', async (data) => {
        try {
            const { roomCode, content, messageType = 'text' } = data;
            
            if (!roomCode || !content || !currentUser) return;

            const messageData = {
                id: `msg-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
                type: messageType,
                content,
                sender: currentUser.username,
                senderId: currentUser.id,
                timestamp: new Date().toISOString()
            };

            // Broadcast to room (including sender via callback)
            io.to(roomCode).emit('new-message', messageData);

            // Persist to database
            if (currentUser.id) {
                const [rooms] = await pool.query('SELECT id FROM rooms WHERE room_code = ?', [roomCode]);
                if (rooms.length > 0) {
                    await pool.query(
                        `INSERT INTO messages (room_id, sender_id, message_type, content)
                         VALUES (?, ?, ?, ?)`,
                        [rooms[0].id, currentUser.id, messageType, content]
                    );
                }
            }

        } catch (err) {
            console.error('[MESSAGE] Error:', err);
        }
    });

    // --- HANDLE FILE/MEDIA SHARING ---
    socket.on('share-media', async (data) => {
        try {
            const { roomCode, fileUrl, fileName, fileSize, fileType, thumbnailUrl } = data;
            
            if (!roomCode || !currentUser) return;

            const messageData = {
                id: `media-${Date.now()}`,
                type: fileType.startsWith('image/') ? 'image' : 
                      fileType.startsWith('video/') ? 'video' :
                      fileType.startsWith('audio/') ? 'audio' : 'file',
                content: fileName,
                fileUrl,
                fileName,
                fileSize,
                fileMimeType: fileType,
                thumbnailUrl,
                sender: currentUser.username,
                senderId: currentUser.id,
                timestamp: new Date().toISOString()
            };

            io.to(roomCode).emit('new-message', messageData);

            // Persist
            if (currentUser.id) {
                const [rooms] = await pool.query('SELECT id FROM rooms WHERE room_code = ?', [roomCode]);
                if (rooms.length > 0) {
                    await pool.query(
                        `INSERT INTO messages (room_id, sender_id, message_type, content, file_url, file_name, file_size, file_mime_type)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                        [rooms[0].id, currentUser.id, messageData.type, fileName, fileUrl, fileName, fileSize, fileType]
                    );
                }
            }

        } catch (err) {
            console.error('[MEDIA] Error:', err);
        }
    });

    // --- WEBRTC SIGNALING ---

    // Offer
    socket.on('webrtc-offer', (data) => {
        const { targetUserId, offer } = data;
        const roomUsers = onlineUsers.get(currentRoom);
        if (roomUsers) {
            for (const [uid, user] of roomUsers) {
                if (uid === targetUserId || user.userId === targetUserId) {
                    io.to(user.socketId).emit('webrtc-offer', {
                        offer,
                        from: currentUser?.username || 'unknown',
                        fromPeerId: currentUser?.peerId,
                        fromSocketId: socket.id
                    });
                    break;
                }
            }
        }
    });

    // Answer
    socket.on('webrtc-answer', (data) => {
        const { targetSocketId, answer } = data;
        io.to(targetSocketId).emit('webrtc-answer', {
            answer,
            from: currentUser?.username || 'unknown'
        });
    });

    // ICE Candidate
    socket.on('webrtc-ice', (data) => {
        const { targetUserId, candidate } = data;
        const roomUsers = onlineUsers.get(currentRoom);
        if (roomUsers) {
            for (const [uid, user] of roomUsers) {
                if (uid === targetUserId || user.userId === targetUserId) {
                    io.to(user.socketId).emit('webrtc-ice', {
                        candidate,
                        from: currentUser?.username || 'unknown'
                    });
                    break;
                }
            }
        }
    });

    // Call initiation
