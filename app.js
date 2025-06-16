// app.js
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const redis = require('redis');
const serverless = require('serverless-http');
const { v4: uuidv4 } = require('uuid'); // Untuk membuat ID unik

// --- Inisialisasi Klien Redis ---
let redisClient;

const REDIS_HOST = process.env.REDIS_HOST;
const REDIS_PORT = process.env.REDIS_PORT;
const REDIS_PASSWORD = process.env.REDIS_PASSWORD;

if (!REDIS_HOST || !REDIS_PORT || !REDIS_PASSWORD || !process.env.JWT_SECRET) {
    console.error('ERROR: Missing required environment variables (REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, JWT_SECRET)!');
    process.exit(1); // Ini penting di produksi agar tidak jalan tanpa kredensial
}

async function connectRedis() {
    if (redisClient && redisClient.isReady) {
        console.log('Redis client already connected.');
        return redisClient;
    }

    try {
        redisClient = redis.createClient({
            password: REDIS_PASSWORD,
            socket: {
                host: REDIS_HOST,
                port: REDIS_PORT
            }
        });

        redisClient.on('error', (err) => console.error('Redis Client Error', err));
        redisClient.on('connect', () => console.log('Redis client connecting...'));
        redisClient.on('ready', () => console.log('Redis client ready!'));
        redisClient.on('end', () => console.log('Redis client connection closed.'));

        await redisClient.connect();
        console.log('Redis connected successfully!');
        return redisClient;
    } catch (error) {
        console.error('Failed to connect to Redis:', error);
        // Penting: Jika gagal connect ke DB utama, kita tidak bisa melanjutkan.
        process.exit(1);
    }
}

// Panggil connectRedis di awal, pastikan terhubung sebelum endpoint dieksekusi
// Di Netlify Functions, ini akan dipanggil setiap cold-start.
// Gunakan pattern untuk memastikan koneksi ada di setiap request.
// (opsi 1: panggil await connectRedis() di setiap endpoint, opsi 2: menggunakan middleware untuk koneksi)
// Untuk kesederhanaan, kita akan menggunakan opsi 1 di sini.

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

// --- Middleware Autentikasi JWT (Tetap sama) ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ message: 'Akses ditolak: Token tidak ditemukan' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT Verification Error:', err);
            return res.status(403).json({ message: 'Token tidak valid atau kadaluarsa' });
        }
        req.user = user;
        next();
    });

    // app.js - Lanjutan dari kode di atas

// --- Endpoint Register (POST /register) ---
app.post('/register', async (req, res) => {
    const client = await connectRedis(); // Pastikan Redis terhubung
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Semua field (username, email, password) harus diisi' });
    }

    try {
        // Cek apakah email sudah terdaftar (menggunakan indeks sekunder)
        const existingEmailId = await client.get(`email:${email}`);
        if (existingEmailId) {
            return res.status(409).json({ message: 'Email sudah terdaftar' });
        }

        // Cek apakah username sudah terdaftar (menggunakan indeks sekunder)
        const existingUsernameId = await client.get(`username:${username}`);
        if (existingUsernameId) {
            return res.status(409).json({ message: 'Username sudah terdaftar' });
        }

        // Hashing password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const userId = uuidv4(); // Buat ID unik untuk user

        // Simpan user sebagai Redis Hash
        await client.hSet(`user:${userId}`, {
            id: userId,
            username: username,
            email: email,
            password: hashedPassword,
            createdAt: new Date().toISOString()
        });

        // Buat indeks sekunder untuk email dan username
        await client.set(`email:${email}`, userId);
        await client.set(`username:${username}`, userId);

        // Buat token JWT
        const token = jwt.sign(
            { id: userId, username: username, email: email },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(201).json({
            message: 'Registrasi berhasil',
            user: {
                id: userId,
                username: username,
                email: email
            },
            token: token
        });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'Registrasi gagal', error: error.message });
    }
});

// --- Endpoint Login (POST /login) ---
app.post('/login', async (req, res) => {
    const client = await connectRedis(); // Pastikan Redis terhubung
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email dan password harus diisi' });
    }

    try {
        // 1. Dapatkan userId dari indeks email
        const userId = await client.get(`email:${email}`);
        if (!userId) {
            return res.status(400).json({ message: 'Email atau password salah' });
        }

        // 2. Dapatkan data user dari hash user
        const user = await client.hGetAll(`user:${userId}`);
        if (!user || Object.keys(user).length === 0) { // Cek jika hash kosong
            return res.status(400).json({ message: 'Email atau password salah' });
        }

        // Bandingkan password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Email atau password salah' });
        }

        // Buat token JWT
        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({
            message: 'Login berhasil',
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            },
            token: token
        });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Login gagal', error: error.message });
    }
});

// --- Endpoint Profile (GET /profile) ---
app.get('/profile', authenticateToken, async (req, res) => {
    const client = await connectRedis(); // Pastikan Redis terhubung
    try {
        const userId = req.user.id; // ID user dari token JWT

        // Dapatkan data user dari hash user
        const user = await client.hGetAll(`user:${userId}`);

        if (!user || Object.keys(user).length === 0) { // Cek jika hash user tidak ditemukan atau kosong
            return res.status(404).json({ message: 'Pengguna tidak ditemukan.' });
        }

        // Hapus password sebelum mengirim ke client
        const { password, ...userWithoutPassword } = user;

        res.status(200).json({
            message: 'Data profil berhasil diambil',
            user: {
                id: userWithoutPassword.id,
                username: userWithoutPassword.username,
                email: userWithoutPassword.email
            }
        });
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ message: 'Gagal mengambil data profil.' });
    }
});

// --- Endpoint Forgot Password (POST /forgot-password) ---
app.post('/forgot-password', async (req, res) => {
    const client = await connectRedis(); // Pastikan Redis terhubung
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: 'Email harus diisi' });
    }

    try {
        // Dapatkan userId dari indeks email
        const userId = await client.get(`email:${email}`);
        if (!userId) {
            return res.status(200).json({ message: 'Jika email terdaftar, tautan reset password akan dikirim.' });
        }

        // Anda bisa mendapatkan detail user jika perlu
        const user = await client.hGetAll(`user:${userId}`);
        if (user && Object.keys(user).length > 0) {
            console.log(`Mengirim email reset password ke: ${user.email}`);
        } else {
            console.log(`Email ${email} tidak ditemukan di database.`);
        }

        res.status(200).json({ message: 'Jika email terdaftar, tautan reset password akan dikirim.' });
    } catch (error) {
        console.error('Error during forgot password:', error);
        res.status(500).json({ message: 'Terjadi kesalahan saat memproses permintaan.' });
    }
});

// --- Endpoint Contoh Update Profile (PATCH /profile) ---
app.patch('/profile', authenticateToken, async (req, res) => {
    const client = await connectRedis();
    const userId = req.user.id;
    const { username, email } = req.body; // Hanya izinkan update ini

    if (!username && !email) {
        return res.status(400).json({ message: 'Setidaknya satu field (username atau email) harus disediakan untuk update.' });
    }

    try {
        const user = await client.hGetAll(`user:${userId}`);
        if (!user || Object.keys(user).length === 0) {
            return res.status(404).json({ message: 'Pengguna tidak ditemukan.' });
        }

        const updates = {};
        let needsIndexUpdate = false;

        if (username && username !== user.username) {
            const existingUsernameId = await client.get(`username:${username}`);
            if (existingUsernameId) {
                return res.status(409).json({ message: 'Username baru sudah terdaftar.' });
            }
            updates.username = username;
            needsIndexUpdate = true;
            await client.del(`username:${user.username}`); // Hapus indeks lama
        }

        if (email && email !== user.email) {
            const existingEmailId = await client.get(`email:${email}`);
            if (existingEmailId) {
                return res.status(409).json({ message: 'Email baru sudah terdaftar.' });
            }
            updates.email = email;
            needsIndexUpdate = true;
            await client.del(`email:${user.email}`); // Hapus indeks lama
        }

        if (Object.keys(updates).length > 0) {
            await client.hSet(`user:${userId}`, updates);

            if (needsIndexUpdate) {
                if (updates.username) {
                    await client.set(`username:${updates.username}`, userId); // Buat indeks baru
                }
                if (updates.email) {
                    await client.set(`email:${updates.email}`, userId); // Buat indeks baru
                }
            }
            res.status(200).json({ message: 'Profil berhasil diperbarui.', user: { ...user, ...updates } });
        } else {
            res.status(200).json({ message: 'Tidak ada perubahan yang diminta.' });
        }
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ message: 'Gagal memperbarui profil.', error: error.message });
    }
});

// --- Route Default ---
app.get('/', (req, res) => {
    res.status(200).json({ message: 'Selamat datang di API Autentikasi Express Anda dengan Redis sebagai Database Utama!' });
});

// --- Menjalankan Server Lokal ---
if (process.env.NODE_ENV !== 'production') {
    const port = process.env.PORT || 3000;
    app.listen(port, () => {
        console.log(`Server lokal berjalan di http://localhost:${port}`);
    });
}

// --- Ekspor Aplikasi untuk Serverless (Netlify Functions) ---
module.exports.handler = serverless(app);
}