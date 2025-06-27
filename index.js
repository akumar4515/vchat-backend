import express from 'express';
import cors from 'cors';
import { Server } from 'socket.io';
import http from 'http';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import pool from './db.js';
import jwt from 'jsonwebtoken';

dotenv.config();
const app = express();
app.use('/uploads', express.static(path.join(process.cwd(), 'uploads')));

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: 'http://localhost:3000', // Restrict to frontend origin
    methods: ['GET', 'POST'],
  },
});

const JWT_SECRET = process.env.BACKEND_JWT_SECRET;

app.use(cors({ origin: 'http://localhost:3000' })); // Restrict CORS for Express
app.use(express.json());

const Authenticate = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('JWT Error:', err.message);
    return res.status(403).json({
      message: err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token',
    });
  }
};

app.get('/api/auth/verify', Authenticate, (req, res) => {
  res.json({ valid: true, user: req.user });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, {
      expiresIn: '1h', // Add token expiration
    });

    res.status(200).json({ message: 'Login successful', token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const [existUser] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (existUser.length !== 0) {
      return res.status(400).json({ message: 'User email already exists' });
    }

    const hashPass = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [
      name,
      email,
      hashPass,
    ]);

    res.status(200).json({ message: 'User created successfully' });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/api/me', Authenticate, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, email, profile_picture FROM users WHERE id = ?', [
      req.user.id,
    ]);
    if (rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json({ user: rows[0] });
  } catch (err) {
    console.error('User fetch error:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/api/search-users', Authenticate, async (req, res) => {
  const { name } = req.query;
  const currentUser = req.user.id;

  try {
    const [users] = await pool.query(
      'SELECT id, name, email, profile_picture FROM users WHERE name LIKE ? AND id != ?',
      [`%${name}%`, currentUser]
    );
    res.status(200).json({ users });
  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({ message: 'Search failed', error: err.message });
  }
});

app.post('/api/friend-requests', Authenticate, async (req, res) => {
  const senderId = req.user.id;
  const { receiverId } = req.body;

  try {
    if (!receiverId) {
      return res.status(400).json({ message: 'Receiver ID required' });
    }
    if (receiverId === senderId) {
      return res.status(400).json({ message: 'Cannot send request to self' });
    }

    const [existing] = await pool.query('SELECT * FROM friend_request WHERE s_id = ? AND r_id = ?', [
      senderId,
      receiverId,
    ]);
    if (existing.length > 0) {
      return res.status(409).json({ message: 'Request already sent' });
    }

    await pool.query('INSERT INTO friend_request (s_id, r_id, status) VALUES (?, ?, ?)', [
      senderId,
      receiverId,
      'pending',
    ]);

    res.status(200).json({ message: 'Friend request sent successfully' });
  } catch (err) {
    console.error('Friend request error:', err);
    res.status(500).json({ message: 'Failed to send friend request', error: err.message });
  }
});

app.get('/api/friends', Authenticate, async (req, res) => {
  const userId = req.user.id;
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;

  try {
    const [friends] = await pool.query(
      `SELECT u.id, u.name, u.email, u.profile_picture
       FROM users u
       JOIN friend_request fr
         ON ((fr.s_id = ? AND fr.r_id = u.id) OR (fr.r_id = ? AND fr.s_id = u.id))
       WHERE fr.status = 'accepted'
       LIMIT ? OFFSET ?`,
      [userId, userId, limit, offset]
    );

    const [count] = await pool.query(
      `SELECT COUNT(*) as total
       FROM friend_request fr
       WHERE fr.status = 'accepted' AND (fr.s_id = ? OR fr.r_id = ?)`,
      [userId, userId]
    );

    res.status(200).json({ friends, total: count[0].total, page, limit });
  } catch (err) {
    console.error('Friend list error:', err);
    res.status(500).json({ message: 'Failed to fetch friends list', error: err.message });
  }
});

app.get('/api/friend-requests-list', Authenticate, async (req, res) => {
  const userId = req.user.id;

  try {
    const [requests] = await pool.query(
      `SELECT fr.id, u.name AS sender_username, u.email
       FROM friend_request fr
       JOIN users u ON fr.s_id = u.id
       WHERE fr.r_id = ? AND fr.status = 'pending'`,
      [userId]
    );

    res.status(200).json({ requests });
  } catch (err) {
    console.error('Friend request fetch error:', err);
    res.status(500).json({ message: 'Failed to fetch friend requests', error: err.message });
  }
});

app.put('/api/change-password', Authenticate, async (req, res) => {
  const userId = req.user.id;
  const { password } = req.body;

  if (!password || password.trim().length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId]);
    res.status(200).json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('Password change error:', err);
    res.status(500).json({ message: 'Failed to update password', error: err.message });
  }
});

app.put('/api/friend-requests/:id', Authenticate, async (req, res) => {
  const userId = req.user.id;
  const requestId = req.params.id;
  const { action } = req.body;

  if (!['accept', 'reject'].includes(action)) {
    return res.status(400).json({ message: 'Invalid action' });
  }

  try {
    const [request] = await pool.query(
      'SELECT * FROM friend_request WHERE id = ? AND r_id = ? AND status = ?',
      [requestId, userId, 'pending']
    );

    if (!request.length) {
      return res.status(404).json({ message: 'Friend request not found' });
    }

    if (action === 'accept') {
      await pool.query('UPDATE friend_request SET status = ? WHERE id = ?', ['accepted', requestId]);
    } else {
      await pool.query('DELETE FROM friend_request WHERE id = ?', [requestId]);
    }

    res.status(200).json({ message: `Friend request ${action}ed successfully` });
  } catch (err) {
    console.error('Friend request action error:', err);
    res.status(500).json({ message: `Failed to ${action} friend request`, error: err.message });
  }
});

app.get('/api/dashboard', Authenticate, async (req, res) => {
  const userId = req.user.id;
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;

  try {
    // Fetch user
    const [userRows] = await pool.query(
      'SELECT id, name, email, profile_picture FROM users WHERE id = ?',
      [userId]
    );
    if (userRows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Fetch friends with pagination
    const [friends] = await pool.query(
      `SELECT u.id, u.name, u.email, u.profile_picture
       FROM users u
       JOIN friend_request fr
         ON ((fr.s_id = ? AND fr.r_id = u.id) OR (fr.r_id = ? AND fr.s_id = u.id))
       WHERE fr.status = 'accepted'
       LIMIT ? OFFSET ?`,
      [userId, userId, limit, offset]
    );

    // Count total friends
    const [count] = await pool.query(
      `SELECT COUNT(*) as total
       FROM friend_request fr
       WHERE fr.status = 'accepted' AND (fr.s_id = ? OR fr.r_id = ?)`,
      [userId, userId]
    );

    // Fetch pending friend requests
    const [requests] = await pool.query(
      `SELECT fr.id, u.name AS sender_username, u.email
       FROM friend_request fr
       JOIN users u ON fr.s_id = u.id
       WHERE fr.r_id = ? AND fr.status = 'pending'`,
      [userId]
    );

    res.status(200).json({
      user: userRows[0],
      friends,
      requests,
      total: count[0].total,
      page,
      limit,
    });
  } catch (err) {
    console.error('Dashboard fetch error:', err);
    res.status(500).json({ message: 'Failed to fetch dashboard data', error: err.message });
  }
});

app.get('/api/messages/:friendId', Authenticate, async (req, res) => {
  const userId = req.user.id;
  const friendId = req.params.friendId;

  try {
    const [friend] = await pool.query('SELECT name FROM users WHERE id = ?', [friendId]);
    if (friend.length === 0) {
      return res.status(404).json({ message: 'Friend not found' });
    }

    const [messages] = await pool.query(
      `SELECT sender_id AS senderId, content AS message, timestamp
       FROM messages
       WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
       ORDER BY timestamp ASC`,
      [userId, friendId, friendId, userId]
    );

    res.status(200).json({
      messages,
      friendName: friend[0].name,
    });
  } catch (err) {
    console.error('Messages fetch error:', err);
    res.status(500).json({ message: 'Failed to fetch messages', error: err.message });
  }
});

// At top of your file
import multer from 'multer';
import path from 'path';
import fs from 'fs';

// Setup multer for file uploads
const uploadDir = 'uploads/profile_pics';
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `user-${req.user.id}-${Date.now()}${ext}`);
  },
});
const upload = multer({ storage });

// PUT: Update profile
app.put('/api/profile', Authenticate, upload.single('profile_picture'), async (req, res) => {
  const { name } = req.body;
  const userId = req.user.id;
const profilePic = req.file
  ? `/uploads/profile_pics/${path.basename(req.file.path)}`
  : null;

  try {
    const fields = [];
    const values = [];

    if (name) {
      fields.push('name = ?');
      values.push(name);
    }

    if (profilePic) {
      fields.push('profile_picture = ?');
      values.push(profilePic);
    }

    if (!fields.length) return res.status(400).json({ message: 'No fields provided to update' });

    values.push(userId);
    const sql = `UPDATE users SET ${fields.join(', ')} WHERE id = ?`;
    await pool.query(sql, values);

    res.status(200).json({ message: 'Profile updated successfully' });
  } catch (err) {
    console.error('Edit profile error:', err);
    res.status(500).json({ message: 'Failed to update profile', error: err.message });
  }
});


// Socket.IO chat handlers
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // 📦 Join chat room
  socket.on('joinChat', ({ userId, friendId }) => {
    const room = [userId, friendId].sort().join('-');
    socket.join(room);
    console.log(`User ${userId} joined chat room ${room}`);
  });

  // ✉️ Message handling
  socket.on('sendMessage', async ({ userId, friendId, message }) => {
    const room = [userId, friendId].sort().join('-');
    try {
      const [result] = await pool.query(
        'INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)',
        [userId, friendId, message]
      );
      const timestamp = new Date();
      io.to(room).emit('receiveMessage', { senderId: userId, message, timestamp });
    } catch (err) {
      console.error('Message save error:', err);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  // 📞 WebRTC signaling
  socket.on('startCall', ({ room }) => {
    socket.join(room);
    console.log(`User joined call room: ${room}`);
  });

  socket.on('offer', ({ room, offer, from }) => {
    socket.to(room).emit('offer', { offer, from });
  });

  socket.on('answer', ({ room, answer }) => {
    socket.to(room).emit('answer', { answer });
  });

  socket.on('ice-candidate', ({ room, candidate }) => {
    socket.to(room).emit('ice-candidate', { candidate });
  });

  // ❌ Call declined
  socket.on('call-declined', ({ room }) => {
    io.to(room).emit('call-declined');
    setTimeout(() => {
      io.to(room).emit('toast', { message: 'Call was declined', type: 'info' });
      io.to(room).emit('call-ended'); // 👈 Ensure both sides close
    }, 500);
  });

  // ⛔ Call manually ended
  socket.on('call-ended', ({ room }) => {
    io.to(room).emit('call-ended');
    setTimeout(() => {
      io.to(room).emit('toast', { message: 'Call ended', type: 'info' });
    }, 500);
  });

  // ❓ Call missed
  socket.on('call-missed', ({ room }) => {
    io.to(room).emit('toast', { message: 'Call not answered', type: 'warning' });
    io.to(room).emit('call-ended'); // 👈 Force end on both sides
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

server.listen(8000, () => console.log(`✅ Server running on port 8000`));