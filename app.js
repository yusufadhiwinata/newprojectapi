// netlify/functions/api.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const serverless = require('serverless-http');

const app = express();
app.use(express.json());

// --- Variabel Lingkungan ---
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// Validasi variabel lingkungan
if (!MONGODB_URI || !JWT_SECRET) {
    console.error('ERROR: Missing required environment variables (MONGODB_URI, JWT_SECRET)!');
    // Di lingkungan produksi, ini akan menghentikan cold start fungsi
    // Untuk pengembangan lokal, kita mungkin ingin menghentikan proses
    if (process.env.NODE_ENV !== 'production') {
        process.exit(1);
    }
}

// --- Koneksi MongoDB ---
let conn = null; // Gunakan variabel ini untuk menyimpan koneksi
const MONGO_OPTIONS = {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000, // Timeout setelah 5s jika tidak dapat menemukan server
    socketTimeoutMS: 45000, // Tutup koneksi setelah 45s tidak aktif
};

// Fungsi untuk menghubungkan ke MongoDB (akan dipanggil di setiap request jika conn null)
async function connectToDatabase() {
    if (conn) {
        console.log('Using existing database connection.');
        return conn;
    }

    try {
        console.log('Connecting to database...');
        conn = await mongoose.connect(MONGODB_URI, MONGO_OPTIONS);
        console.log('Database connected successfully!');
        return conn;
    } catch (error) {
        console.error('Database connection failed:', error);
        conn = null; // Pastikan conn direset jika gagal
        throw new Error('Failed to connect to database.'); // Lempar error untuk ditangkap di handler
    }
}

// --- Skema Mongoose (User Model) ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// --- Middleware Autentikasi JWT ---
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
}

// --- Routes ---

// Route Default
app.get('/', (req, res) => {
    res.status(200).json({ message: 'Selamat datang di API Autentikasi Express Anda dengan MongoDB!' });
});

// Register User
app.post('/register', async (req, res) => {
    try {
        await connectToDatabase(); // Pastikan terhubung ke DB

        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ message: 'Semua field (username, email, password) harus diisi' });
        }

        // Cek jika user sudah ada
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(409).json({ message: 'Email atau username sudah terdaftar' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            username,
            email,
            password: hashedPassword
        });

        await newUser.save();

        // Buat token JWT
        const token = jwt.sign(
            { id: newUser._id, username: newUser.username, email: newUser.email },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(201).json({
            message: 'Registrasi berhasil',
            user: {
                id: newUser._id,
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

// Login User
app.post('/login', async (req, res) => {
    try {
        await connectToDatabase(); // Pastikan terhubung ke DB

        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email dan password harus diisi' });
        }

        // Cari user berdasarkan email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Email atau password salah' });
        }

        // Bandingkan password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Email atau password salah' });
        }

        // Buat token JWT
        const token = jwt.sign(
            { id: user._id, username: user.username, email: user.email },
            JWT_SECRET,
            { expiresIn: '1h' }
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

// Get User Profile (Protected Route)
app.get('/profile', authenticateToken, async (req, res) => {
    try {
        await connectToDatabase(); // Pastikan terhubung ke DB

        // ID user diambil dari token JWT yang sudah diverifikasi oleh middleware
        const userId = req.user.id;

        const user = await User.findById(userId).select('-password'); // Jangan kirim password

        if (!user) {
            return res.status(404).json({ message: 'Pengguna tidak ditemukan.' });
        }

        res.status(200).json({
            message: 'Data profil berhasil diambil',
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                createdAt: user.createdAt
            }
        });
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ message: 'Gagal mengambil data profil.' });
    }
});

// --- Menjalankan Server Lokal (untuk pengembangan) ---
// Jika NODE_ENV bukan 'production', jalankan server Express biasa
if (process.env.NODE_ENV !== 'production') {
    const port = process.env.PORT || 3000;
    app.listen(port, () => {
        console.log(`Server lokal berjalan di http://localhost:${port}`);
        connectToDatabase().catch(err => {
            console.error("Gagal terhubung ke database saat startup lokal:", err);
            process.exit(1);
        });
    });
}

// --- Ekspor Aplikasi untuk Netlify Functions ---
// Ini adalah entry point untuk serverless
module.exports.handler = serverless(app);