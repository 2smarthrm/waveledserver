// index.js — mini API só com GET / a listar produtos
import express from "express";
import mongoose from "mongoose";

const app = express();

// 👉 define isto nas ENV da Vercel (Project → Settings → Environment Variables)
const MONGO_URI =
  process.env.MONGO_URI ||
  "mongodb+srv://USER:PASSWORD@cluster0.7p7g2qd.mongodb.net/waveled?retryWrites=true&w=majority&appName=waveled";

// Conecta 1x por execução (serverless-friendly)
let mongoPromise = null;
async function ensureDb() {
  if (mongoose.connection.readyState === 1) return;
  if (!mongoPromise) {
    mongoPromise = mongoose
      .connect(MONGO_URI, {
        serverSelectionTimeoutMS: 20000,
        socketTimeoutMS: 45000,
        maxPoolSize: 10,
        family: 4,
        tls: true,
        serverApi: { version: "1", strict: true, deprecationErrors: true },
      })
      .then(() => console.log("MongoDB ligado"))
      .catch((err) => {
        mongoPromise = null; // permite retry no próximo pedido
        throw err;
      });
  }
  return mongoPromise;
}

// Modelo mínimo compatível com a tua coleção existente
const ProductSchema = new mongoose.Schema(
  {
    wl_name: String,
    wl_category: mongoose.Schema.Types.ObjectId,
    wl_images: [String],
    wl_likes: Number,
    wl_created_at: Date,
  },
  { collection: "waveled_products" }
);
const WaveledProduct =
  mongoose.models.WaveledProduct ||
  mongoose.model("WaveledProduct", ProductSchema);

// Evita 500 no favicon na Vercel
app.get(["/favicon.ico", "/favicon.png"], (req, res) => res.status(204).end());

// ÚNICA ROTA: lista de produtos
app.get("/", async (req, res) => {
  try {
    await ensureDb();
    const items = await WaveledProduct.find({})
      .sort({ wl_created_at: -1, _id: -1 })
      .limit(50)
      .lean();

    // mapeia para um payload simples
    const data = items.map((p) => ({
      id: String(p._id),
      name: p.wl_name,
      images: p.wl_images || [],
      likes: p.wl_likes || 0,
      created_at: p.wl_created_at,
    }));

    res.status(200).json({ ok: true, data });
  } catch (e) {
    console.error("Erro a listar produtos:", e?.message || e);
    res.status(500).json({ ok: false, error: "Falha ao obter produtos" });
  }
});

// ❗️IMPORTANTE: exporta um handler serverless (NÃO usar app.listen)
export default async function handler(req, res) {
  return app(req, res);
}
