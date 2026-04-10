const crypto = require("crypto");

const database = new Map();

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

// 🔹 buat gambar SVG
function buatGambar(teks) {
  let garis = "";
  for (let i = 0; i < 10; i++) {
    garis += `<line x1="${Math.random()*200}" y1="${Math.random()*80}" x2="${Math.random()*200}" y2="${Math.random()*80}" stroke="gray"/>`;
  }

  let tulisan = teks.split("").map((h, i) => {
    const x = 20 + i * 30;
    const y = 40 + Math.random() * 10;
    const rotasi = Math.random() * 30 - 15;
    return `<text x="${x}" y="${y}" transform="rotate(${rotasi} ${x},${y})" font-size="30">${h}</text>`;
  }).join("");

  return `
  <svg width="200" height="80" xmlns="http://www.w3.org/2000/svg">
    <rect width="100%" height="100%" fill="#eee"/>
    ${garis}
    ${tulisan}
  </svg>`;
}

// 🔥 1 FILE SEMUA
module.exports = (req, res) => {
  const { aksi, id, jawaban } = req.query;

  // ✅ ambil captcha
  if (aksi === "ambil") {
    const teks = buatCaptcha();
    const idCaptcha = crypto.randomBytes(6).toString("hex");

    database.set(idCaptcha, {
      hash: enkripsi(teks),
      waktu: Date.now() + 60000 // 1 menit
    });

    return res.json({
      id: idCaptcha,
      gambar: buatGambar(teks)
    });
  }

  // ✅ cek jawaban
  if (aksi === "cek") {
    if (!database.has(id)) {
      return res.json({ sukses: false, pesan: "Captcha tidak ditemukan" });
    }

    const data = database.get(id);

    if (Date.now() > data.waktu) {
      database.delete(id);
      return res.json({ sukses: false, pesan: "Captcha kadaluarsa" });
    }

    if (enkripsi(jawaban.toUpperCase()) === data.hash) {
      database.delete(id);
      return res.json({ sukses: true, pesan: "Benar" });
    } else {
      return res.json({ sukses: false, pesan: "Salah" });
    }
  }

  // default
  res.json({
    pesan: "Gunakan ?aksi=ambil atau ?aksi=cek"
  });
};
