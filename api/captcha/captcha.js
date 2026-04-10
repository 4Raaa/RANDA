const crypto = require("crypto");

const database = new Map();
const rateLimit = new Map(); // 🔹 anti-spam

// 🔹 Rate limit config
const RATE_LIMIT_WINDOW = 60000; // 1 menit
const RATE_LIMIT_MAX = 10; // maks 10 request per menit per IP

// 🔹 CORS whitelist (sesuaikan dengan domain frontend)
const ALLOWED_ORIGINS = [
  "http://localhost:3000",
  "https://website-anda.com",
  // tambahkan domain lain yang diizinkan
];

// 🔹 bersihin captcha expired tiap 5 menit
setInterval(() => {
  const sekarang = Date.now();
  for (const [id, data] of database) {
    if (sekarang > data.waktu) {
      database.delete(id);
    }
  }
}, 300000); // 5 menit

// 🔹 helper: cek rate limit
function cekRateLimit(ip) {
  const sekarang = Date.now();
  const data = rateLimit.get(ip) || { count: 0, resetTime: sekarang + RATE_LIMIT_WINDOW };
  
  if (sekarang > data.resetTime) {
    data.count = 1;
    data.resetTime = sekarang + RATE_LIMIT_WINDOW;
  } else {
    data.count++;
  }
  
  rateLimit.set(ip, data);
  return data.count <= RATE_LIMIT_MAX;
}

// 🔹 helper: CORS headers
function setCORS(res, origin) {
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : "";
  
  res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Max-Age", "86400");
  
  // 🔹 Security headers tambahan
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
}

// 🔹 buat teks captcha
function buatCaptcha(panjang = 5) {
  const huruf = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let hasil = "";
  for (let i = 0; i < panjang; i++) {
    hasil += huruf[Math.floor(Math.random() * huruf.length)];
  }
  return hasil;
}

// 🔹 hash biar aman
function enkripsi(teks) {
  return crypto.createHash("sha256").update(teks).digest("hex");
}

// 🔹 buat gambar SVG (dengan proteksi XSS)
function buatGambar(teks) {
  // 🔹 Escape karakter spesial biar gak kena XSS via SVG
  const escapeXml = (str) => {
    return str.replace(/[<>&'"]/g, (c) => ({
      "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;"
    })[c]);
  };

  let garis = "";
  for (let i = 0; i < 10; i++) {
    const x1 = Math.floor(Math.random() * 200);
    const y1 = Math.floor(Math.random() * 80);
    const x2 = Math.floor(Math.random() * 200);
    const y2 = Math.floor(Math.random() * 80);
    garis += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="gray" stroke-width="1"/>`;
  }

  const tulisan = teks.split("").map((h, i) => {
    const x = 20 + i * 30;
    const y = 40 + Math.floor(Math.random() * 20);
    const rotasi = Math.floor(Math.random() * 30) - 15;
    const char = escapeXml(h);
    return `<text x="${x}" y="${y}" transform="rotate(${rotasi} ${x},${y})" font-size="30" fill="#333" font-family="Arial, sans-serif">${char}</text>`;
  }).join("");

  // 🔹 Tambah noise dots
  let dots = "";
  for (let i = 0; i < 30; i++) {
    const cx = Math.floor(Math.random() * 200);
    const cy = Math.floor(Math.random() * 80);
    dots += `<circle cx="${cx}" cy="${cy}" r="1" fill="#999"/>`;
  }

  return `<?xml version="1.0" encoding="UTF-8"?>
<svg width="200" height="80" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 80">
  <rect width="100%" height="100%" fill="#f0f0f0"/>
  ${dots}
  ${garis}
  ${tulisan}
</svg>`;
}

// 🔥 MAIN HANDLER
module.exports = (req, res) => {
  const origin = req.headers.origin || "";
  const clientIP = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || 
                   req.socket?.remoteAddress || 
                   "unknown";
  
  // 🔹 Set CORS & security headers
  setCORS(res, origin);
  
  // Handle preflight
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  // 🔹 Rate limit check
  if (!cekRateLimit(clientIP)) {
    res.status(429);
    return res.json({ 
      sukses: false, 
      pesan: "Terlalu banyak request, coba lagi nanti" 
    });
  }

  const { aksi, id, jawaban } = req.query;

  // ✅ ambil captcha baru
  if (aksi === "ambil") {
    const teks = buatCaptcha();
    const idCaptcha = crypto.randomBytes(16).toString("hex"); // 🔹 lebih panjang (32 char)

    database.set(idCaptcha, {
      hash: enkripsi(teks),
      waktu: Date.now() + 300000, // 🔹 5 menit (lebih aman dari 1 menit)
      attempts: 0 // 🔹 track percobaan
    });

    // 🔹 Set content-type yang aman untuk SVG
    return res.json({
      sukses: true,
      id: idCaptcha,
      gambar: buatGambar(teks),
      expiresIn: 300 // detik
    });
  }

  // ✅ cek jawaban
  if (aksi === "cek") {
    // 🔹 validasi input
    if (!id || typeof id !== "string") {
      return res.json({ sukses: false, pesan: "ID captcha diperlukan" });
    }

    if (!jawaban || typeof jawaban !== "string") {
      return res.json({ sukses: false, pesan: "Jawaban diperlukan" });
    }

    if (!database.has(id)) {
      return res.json({ sukses: false, pesan: "Captcha tidak ditemukan atau sudah kadaluarsa" });
    }

    const data = database.get(id);

    // 🔹 cek expired
    if (Date.now() > data.waktu) {
      database.delete(id);
      return res.json({ sukses: false, pesan: "Captcha kadaluarsa, silakan ambil yang baru" });
    }

    // 🔹 limit percobaan (max 3x)
    data.attempts++;
    if (data.attempts > 3) {
      database.delete(id);
      return res.json({ sukses: false, pesan: "Terlalu banyak percobaan, silakan ambil captcha baru" });
    }

    // 🔹 sanitize & compare
    const jawabanBersih = jawaban.toUpperCase().trim();
    
    // 🔹 validasi karakter (hanya alphanumeric)
    if (!/^[A-Z0-9]+$/.test(jawabanBersih)) {
      return res.json({ sukses: false, pesan: "Format jawaban tidak valid" });
    }

    if (enkripsi(jawabanBersih) === data.hash) {
      database.delete(id);
      return res.json({ 
        sukses: true, 
        pesan: "Verifikasi berhasil",
        token: crypto.randomBytes(32).toString("hex") // 🔹 optional: token untuk session
      });
    } else {
      const sisaPercobaan = 3 - data.attempts;
      return res.json({ 
        sukses: false, 
        pesan: "Jawaban salah",
        sisaPercobaan: sisaPercobaan > 0 ? sisaPercobaan : 0
      });
    }
  }

  // default
  res.status(400);
  res.json({
    sukses: false,
    pesan: "Gunakan ?aksi=ambil atau ?aksi=cek"
  });
};
