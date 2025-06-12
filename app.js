require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose'); // Import Mongoose
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;

// --- Koneksi MongoDB ---
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
    console.error('ERROR: MONGO_URI is not defined in .env or environment variables!');
    // Hentikan aplikasi jika tidak ada URI, terutama penting untuk produksi
    process.exit(1); 
}

mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB connected successfully!'))
    .catch(err => {
        console.error('MongoDB connection error:', err);
        // Penting: Keluar dari proses jika koneksi database gagal
        process.exit(1); 
    });

// --- Model User Mongoose ---
const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minlength: 3
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        match: /^\S+@\S+\.\S+$/ // Regex sederhana untuk validasi email
    },
    password: {
        type: String,
        required: true,
        minlength: 6 // Contoh: minimal panjang password
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Middleware Mongoose: Hash password sebelum menyimpan
UserSchema.pre('save', async function(next) {
    if (!this.isModified('password')) {
        return next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

const User = mongoose.model('User', UserSchema);

// --- Pengaturan Middleware Express ---
app.use(express.json()); // Middleware untuk parsing body JSON

// --- JWT Secret Key (Pastikan ini sangat kuat dan disimpan di .env) ---
const JWT_SECRET = process.env.JWT_SECRET; // Tidak perlu fallback karena kita akan exit jika tidak ada

// --- Middleware Autentikasi JWT ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: Bearer TOKEN

    if (token == null) {
        return res.status(401).json({ message: 'Akses ditolak: Token tidak ditemukan' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT Verification Error:', err);
            return res.status(403).json({ message: 'Token tidak valid atau kadaluarsa' });
        }
        req.user = user; // Menyimpan payload user dari token ke objek request
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
        let userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(409).json({ message: 'Email sudah terdaftar' });
        }
        userExists = await User.findOne({ username });
        if (userExists) {
            return res.status(409).json({ message: 'Username sudah terdaftar' });
        }

        // Buat user baru (password akan di-hash oleh middleware UserSchema.pre('save'))
        const newUser = await User.create({ username, email, password });

        // Buat token JWT untuk pengguna baru yang terdaftar
        const token = jwt.sign(
            { id: newUser._id, username: newUser.username, email: newUser.email },
            JWT_SECRET,
            { expiresIn: '1h' } // Token berlaku selama 1 jam
        );

        res.status(201).json({
            message: 'Registrasi berhasil',
            user: {
                id: newUser._id, // Menggunakan _id dari MongoDB
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
        // Cari pengguna berdasarkan email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Email atau password salah' });
        }

        // Bandingkan password yang diinput dengan password yang di-hash
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Email atau password salah' });
        }

        // Buat token JWT
        const token = jwt.sign(
            { id: user._id, username: user.username, email: user.email },
            JWT_SECRET,
            { expiresIn: '1h' } // Token berlaku selama 1 jam
        );

        res.status(200).json({
            message: 'Login berhasil',
            user: {
                id: user._id,
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

// --- Endpoint Forgot Password (POST /forgot-password) ---
// CATATAN: Implementasi sebenarnya akan melibatkan pengiriman email dengan tautan reset
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: 'Email harus diisi' });
    }

    try {
        const user = await User.findOne({ email });

        if (!user) {
            // Penting: Untuk keamanan, selalu berikan pesan yang sama apakah email ditemukan atau tidak
            return res.status(200).json({ message: 'Jika email terdaftar, tautan reset password akan dikirim.' });
        }

        console.log(`Mengirim email reset password ke: ${email}`);
        // Di sini Anda akan mengintegrasikan layanan pengiriman email (mis. Nodemailer, SendGrid)
        // dan membuat tautan reset unik yang mengarah ke halaman reset password di frontend Anda.
        // Tautan ini akan berisi token yang sudah dienkripsi.

        res.status(200).json({ message: 'Jika email terdaftar, tautan reset password akan dikirim.' });
    } catch (error) {
        console.error('Error during forgot password:', error);
        res.status(500).json({ message: 'Terjadi kesalahan saat memproses permintaan.' });
    }
});

// --- Endpoint Mendapatkan Data Username (GET /profile) ---
// Endpoint ini memerlukan autentikasi JWT
app.get('/profile', authenticateToken, async (req, res) => {
    try {
        // Cari user berdasarkan ID dari token
        const user = await User.findById(req.user.id).select('-password'); // Jangan kirim password
        if (!user) {
            return res.status(404).json({ message: 'Pengguna tidak ditemukan.' });
        }

        // Data pengguna tersedia di req.user dari middleware authenticateToken
        res.status(200).json({
            message: 'Data profil berhasil diambil',
            user: {
                id: user._id,
                username: user.username,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ message: 'Gagal mengambil data profil.' });
    }
});

// --- Route Default untuk Vercel (penting untuk serverless) ---
// Ini adalah "catch-all" route jika tidak ada route lain yang cocok
app.get('/', (req, res) => {
    res.status(200).json({ message: 'Selamat datang di API Autentikasi Express Anda dengan MongoDB!' });
});


// --- Menjalankan Server Lokal (Hanya saat development) ---
if (process.env.NODE_ENV !== 'production') {
    app.listen(port, () => {
        console.log(`Server lokal berjalan di http://localhost:${port}`);
    });
}

// --- Ekspor Aplikasi untuk Vercel ---
// Ini sangat penting agar Vercel dapat menggunakan aplikasi Express Anda sebagai Serverless Function
module.exports = app;