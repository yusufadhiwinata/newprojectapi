// app.js
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin'); // Import admin SDK

// --- Inisialisasi Firebase Admin SDK (Seperti di atas) ---
let db;
try {
    if (process.env.NODE_ENV === 'production') {
        const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
        admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    } else {
        const serviceAccount = require('./serviceAccountKey.json');
        admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    }
    db = admin.firestore(); // Inisialisasi Firestore database instance
    console.log('Firestore connected successfully!');
} catch (error) {
    console.error('ERROR: Failed to initialize Firebase:', error);
    process.exit(1);
}

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('ERROR: JWT_SECRET is not defined!');
    process.exit(1);
}

// --- Middleware Autentikasi JWT (Tetap sama) ---
function authenticateToken(req, res, next) {
    // ... (kode yang sama seperti sebelumnya) ...
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
}

// --- Endpoint Register (POST /register) ---
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Semua field (username, email, password) harus diisi' });
    }

    try {
        // Cek apakah email atau username sudah terdaftar
        const usersRef = db.collection('users'); // Firestore collection reference
        const emailSnapshot = await usersRef.where('email', '==', email).get();
        if (!emailSnapshot.empty) {
            return res.status(409).json({ message: 'Email sudah terdaftar' });
        }
        const usernameSnapshot = await usersRef.where('username', '==', username).get();
        if (!usernameSnapshot.empty) {
            return res.status(409).json({ message: 'Username sudah terdaftar' });
        }

        // Hashing password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Buat user baru di Firestore
        const newUserRef = await usersRef.add({ // .add() akan membuat ID dokumen otomatis
            username: username,
            email: email,
            password: hashedPassword,
            createdAt: admin.firestore.FieldValue.serverTimestamp() // Timestamp dari Firestore
        });

        const newUserDoc = await newUserRef.get(); // Dapatkan dokumen yang baru ditambahkan
        const newUser = { id: newUserDoc.id, ...newUserDoc.data() }; // Sertakan ID dokumen

        // Buat token JWT
        const token = jwt.sign(
            { id: newUser.id, username: newUser.username, email: newUser.email },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(201).json({
            message: 'Registrasi berhasil',
            user: {
                id: newUser.id,
                username: newUser.username,
                email: newUser.email
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
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email dan password harus diisi' });
    }

    try {
        const usersRef = db.collection('users');
        const snapshot = await usersRef.where('email', '==', email).get();

        if (snapshot.empty) {
            return res.status(400).json({ message: 'Email atau password salah' });
        }

        const userDoc = snapshot.docs[0]; // Dapatkan dokumen user
        const user = { id: userDoc.id, ...userDoc.data() }; // Sertakan ID dokumen

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
    try {
        const userId = req.user.id; // ID user dari token JWT

        const userDoc = await db.collection('users').doc(userId).get();

        if (!userDoc.exists) {
            return res.status(404).json({ message: 'Pengguna tidak ditemukan.' });
        }

        const user = { id: userDoc.id, ...userDoc.data() };

        res.status(200).json({
            message: 'Data profil berhasil diambil',
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ message: 'Gagal mengambil data profil.' });
    }
});

// --- Endpoint Forgot Password (POST /forgot-password) ---
// Logika ini tetap sama karena tidak ada interaksi database langsung yang diubah
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: 'Email harus diisi' });
    }

    try {
        const usersRef = db.collection('users');
        const snapshot = await usersRef.where('email', '==', email).get();

        if (snapshot.empty) {
            return res.status(200).json({ message: 'Jika email terdaftar, tautan reset password akan dikirim.' });
        }

        console.log(`Mengirim email reset password ke: ${email}`);
        res.status(200).json({ message: 'Jika email terdaftar, tautan reset password akan dikirim.' });
    } catch (error) {
        console.error('Error during forgot password:', error);
        res.status(500).json({ message: 'Terjadi kesalahan saat memproses permintaan.' });
    }
});

// --- Route Default ---
app.get('/', (req, res) => {
    res.status(200).json({ message: 'Selamat datang di API Autentikasi Express Anda dengan Firestore!' });
});

// --- Menjalankan Server Lokal ---
if (process.env.NODE_ENV !== 'production') {
    const port = process.env.PORT || 3000;
    app.listen(port, () => {
        console.log(`Server lokal berjalan di http://localhost:${port}`);
    });
}

// --- Ekspor Aplikasi untuk Serverless (Netlify Functions) ---
const serverless = require('serverless-http');
module.exports.handler = serverless(app); // Mengubah export agar sesuai dengan Netlify Functions