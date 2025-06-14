// netlify/functions/api.js
// Ini adalah Netlify Function yang akan membungkus aplikasi Express Anda

const serverless = require('serverless-http');
const app = require('../../app'); // Sesuaikan path ini ke app.js Express Anda

// Mengekspor handler fungsi
exports.handler = serverless(app);