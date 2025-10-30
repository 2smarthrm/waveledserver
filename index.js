 
/*
 

*/

import path from "path";
import fs from "fs";
import os from "os";
import express from "express";
import mongoose from "mongoose";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cors from "cors"; 
import compression from "compression";
import mongoSanitize from "express-mongo-sanitize";
import { body, param, query, validationResult } from "express-validator";
import bcrypt from "bcrypt";
import multer from "multer";
import nodemailer from "nodemailer";
import crypto from "crypto";
import morgan from "morgan";
import { nanoid } from "nanoid";
import session from "express-session";
import MongoStore from "connect-mongo";
 const PHONE_PT = /^(\+?\d{2,3})?\s?\d{9,12}$/; // simples e permissivo
 

import dns from "dns";
dns.setDefaultResultOrder?.("ipv4first");

mongoose.set("bufferCommands", false);



// --------------------------------- ENV ---------------------------------------
const PORT =   4000;
const MONGO_URI =  "mongodb+srv://2smarthrm_db_user:afMz4WEnx9is1N3O@cluster0.7p7g2qd.mongodb.net/";
const SESSION_SECRET = crypto.randomBytes(48).toString("hex");
const COOKIE_NAME =  "wl_sid";
const COOKIE_DOMAIN =   "localhost";
const COOKIE_SECURE = String( "false") === "true";
const ALLOWED_ORIGINS = [
  "http://localhost:5173",
  "http://localhost:3001",
  "http://localhost:3000",
  "https://waveled.vercel.app",
  "https://waveled-pspo.vercel.app",
  "http://localhost:5174",
];
 
 
// Escolhe diretório gravável (env > /tmp em serverless > ./uploads em dev)
function resolveUploadDir() { 
  return  path.resolve("./uploads");
}

let UPLOAD_DIR = resolveUploadDir();

// Cria diretório com fallback seguro para /tmp/uploads
function ensureDir(p) {
  try {
    if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
    return p;
  } catch (err) {
    console.warn("[uploads] Falhou criar", p, "→", err.message);
    const fallback = path.join(os.tmpdir(), "uploads");
    if (!fs.existsSync(fallback)) fs.mkdirSync(fallback, { recursive: true });
    console.warn("[uploads] A usar fallback:", fallback);
    return fallback;
  }
}

UPLOAD_DIR = ensureDir(UPLOAD_DIR);
console.log("[uploads] Dir:", UPLOAD_DIR);

// mantém o teu ENC_KEY como está
const ENC_KEY = Buffer.from(  "b8wXnR8j6r5w2KphF5sOeYlM5wqF7X2+VnZWQprP7Ks=",
  "base64"
);

if (ENC_KEY.length !== 32) {
  console.error("ENC_KEY_BASE64 inválida (requer 32 bytes Base64).");
  process.exit(1);
}
// --- até aqui ---
 
 
let transporter;
const USE_SENDMAIL = false;
if (USE_SENDMAIL === "true") {
  transporter = nodemailer.createTransport({
    sendmail: true,
    newline: "unix",
    path: "/usr/sbin/sendmail",
  });
} else {
  transporter = nodemailer.createTransport({
    host: "",
    port: Number(587),
    secure: false,
    auth:""
      ? { user:"", pass:""}
      : undefined,
  });
}

// --------------------------------- APP ---------------------------------------
const app = express();
app.set("trust proxy", 1);
app.use(helmet({ crossOriginResourcePolicy: false }));

 
 
app.use(
  cors({
    origin: (origin, callback) => {
      // Permite requests de ferramentas internas (ex: Postman, curl)
      if (!origin) return callback(null, true);

      if (ALLOWED_ORIGINS.includes(origin)) {
        return callback(null, true);
      }

      console.warn(`🚫 CORS bloqueado para origem: ${origin}`);
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);

 


app.use(morgan("combined"));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));
 
// app.use(hpp()); // REMOVIDO (quebrava req.query em Express 5)
app.use(compression());
app.use("/uploads", express.static(path.resolve(UPLOAD_DIR)));

// -------------------------- Sanitização não invasiva -------------------------
const stripTags = (v) =>
  typeof v === "string" ? v.replace(/<[^>]*>/g, "") : v;

function deepSanitize(obj) {
  if (!obj || typeof obj !== "object") return obj;
  for (const k of Object.keys(obj)) {
    const val = obj[k];
    if (typeof val === "string") obj[k] = stripTags(val);
    else if (Array.isArray(val)) obj[k] = val.map((x) => deepSanitize(x));
    else if (val && typeof val === "object") obj[k] = deepSanitize(val);
  }
  return obj;
}

app.use((req, _res, next) => {
  // Não reatribuir req.query
  if (req.body) deepSanitize(req.body);
  if (req.params) deepSanitize(req.params);
  next();
});



app.use(
  session({
    name: COOKIE_NAME,
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: MONGO_URI,
      collectionName: "waveled_sessions",
      ttl: 60 * 60 * 8,
      touchAfter: 60 * 10,
    }),
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: COOKIE_SECURE,
      domain: COOKIE_DOMAIN === "localhost" ? undefined : COOKIE_DOMAIN,
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

// -------------------------------- Utils --------------------------------------
const ok = (res, data, code = 200) => res.status(code).json({ ok: true, data });
const errJson = (res, message = "Erro", code = 400, issues = null) =>
  res.status(code).json({ ok: false, error: message, issues });

// wrapper para try/catch em rotas async (com log)
const asyncH =
  (fn) =>
  (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch((e) => {
      console.error("Route error:", e && e.stack ? e.stack : e);
      next(e);
    });

const requireAuth =
  (roles = []) =>
  (req, res, next) => {
    if (!req.session.user) return errJson(res, "Não autenticado", 401);
    if (roles.length && !roles.includes(req.session.user.role))
      return errJson(res, "Sem permissões", 403);
    next();
  };

const limiterStrict = rateLimit({ windowMs: 10 * 60 * 1000*1000, max: 8550 });
const limiterAuth = rateLimit({ windowMs: 10 * 60 * 1000*1000, max: 5550 });
const limiterLogin = rateLimit({ windowMs: 15 * 60 * 1000*1000, max: 1555 });
const limiterPublicPost = rateLimit({ windowMs: 5 * 60 * 1000*1000, max: 4055 });

const audit =
  (action) =>
  (req, res, next) => {
    res.on("finish", () => {
      WaveledAudit.create({
        wl_actor: req.session?.user?.email || "public",
        wl_action: action,
        wl_details: {
          method: req.method,
          path: req.originalUrl,
          status: res.statusCode,
        },
        wl_ip: req.ip,
      }).catch((e) => {
        console.error("Audit error:", e);
      });
    });
    next();
  };

// AES-256-GCM helpers para PII
const encrypt = (obj) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
  const buf = Buffer.from(JSON.stringify(obj), "utf8");
  const enc = Buffer.concat([cipher.update(buf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: enc.toString("base64"),
  };
};
const decrypt = (blob) => {
  const iv = Buffer.from(blob.iv, "base64");
  const tag = Buffer.from(blob.tag, "base64");
  const data = Buffer.from(blob.data, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", ENC_KEY, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return JSON.parse(dec.toString("utf8"));
};

// Multer (uploads de imagem)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || "");
    cb(null, `${Date.now()}_${nanoid(8)}${ext}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024, files: 12 },
  fileFilter: (req, file, cb) => {
    if (/image\/(png|jpe?g|webp|gif|svg\+xml)/.test(file.mimetype))
      cb(null, true);
    else cb(new Error("Tipo de ficheiro inválido"));
  },
});

// -------------------------------- Schemas ------------------------------------
const { Schema } = mongoose;

const UserSchema = new Schema(
  {
    wl_name: { type: String, required: true },
    wl_email: { type: String, required: true, unique: true, index: true },
    wl_password_hash: { type: String, required: true },
    wl_role: {
      type: String,
      enum: ["admin", "editor", "viewer"],
      default: "viewer",
    },
    wl_created_at: { type: Date, default: Date.now },
    wl_active: { type: Boolean, default: true },
  },
  { collection: "waveled_users" }
);

const CategorySchema = new Schema(
  {
    wl_name: { type: String, required: true, unique: true },
    wl_slug: { type: String, required: true, unique: true },
    wl_name_norm: { type: String, index: true, unique: true }, // novo
    wl_order: { type: Number, default: 0, index: true },
    wl_created_at: { type: Date, default: Date.now },
  },
  { collection: "waveled_categories" }
);

// Antes de salvar, preenche wl_name_norm (lowercase, sem acentos, espaços colapsados)
CategorySchema.pre("save", function(next) {
  const norm = (s) =>
    String(s || "")
      .toLowerCase()
      .normalize("NFD").replace(/[\u0300-\u036f]/g, "") // remove acentos
      .replace(/\s+/g, " ")
      .trim();
  this.wl_name = this.wl_name.replace(/\s+/g, " ").trim();
  this.wl_slug = this.wl_slug.toLowerCase().trim();
  this.wl_name_norm = norm(this.wl_name);
  next();
});

// const WaveledCategory = mongoose.model("WaveledCategory", CategorySchema);

const ProductSchema = new Schema(
  {
    wl_name: { type: String, required: true },
    wl_category: {
      type: Schema.Types.ObjectId,
      ref: "WaveledCategory",
      required: true,
    },
    wl_description_html: { type: String, default: "" },
    wl_specs_text: { type: String, default: "" },
    wl_datasheet_url: { type: String, default: "" },
    wl_manual_url: { type: String, default: "" },
    wl_sku: { type: String, unique: true, sparse: true },
    wl_images: [{ type: String }],
    wl_featured_general: { type: Boolean, default: false },
    wl_likes: { type: Number, default: 0 },
    wl_created_at: { type: Date, default: Date.now },
    wl_updated_at: { type: Date, default: Date.now },
  },
  { collection: "waveled_products" }
);

ProductSchema.index({ wl_name: "text", wl_specs_text: "text" });

const FeaturedHomeSchema = new Schema(
  {
    wl_slots: [{ type: Schema.Types.ObjectId, ref: "WaveledProduct" }],
    wl_updated_at: { type: Date, default: Date.now },
  },
  { collection: "waveled_featured_home" }
);

const FeaturedProductSchema = new Schema(
  {
    wl_product: {
      type: Schema.Types.ObjectId,
      ref: "WaveledProduct",
      required: true,
      unique: true,
    },
    wl_order: { type: Number, default: 0 },
    wl_created_at: { type: Date, default: Date.now },
  },
  { collection: "waveled_featured_products" }
);

const TopListSchema = new Schema(
  {
    wl_scope: { type: String, enum: ["overall", "category"], required: true },
    wl_category: { type: Schema.Types.ObjectId, ref: "WaveledCategory" },
    wl_top10: [{ type: Schema.Types.ObjectId, ref: "WaveledProduct" }],
    wl_top3: [{ type: Schema.Types.ObjectId, ref: "WaveledProduct" }],
    wl_best: { type: Schema.Types.ObjectId, ref: "WaveledProduct" },
    wl_updated_at: { type: Date, default: Date.now },
  },
  { collection: "waveled_toplists" }
);

const SuccessCaseSchema = new Schema(
  {
    wl_company_name: { type: String, required: true },
    wl_title: { type: String, required: true },
    wl_description_html: { type: String, default: "" },
    wl_images: [{ type: String }],
    wl_created_at: { type: Date, default: Date.now },
  },
  { collection: "waveled_success_cases" }
);

const MessageSchema = new Schema(
  {
    wl_encrypted_blob: { type: Schema.Types.Mixed, required: true },
    wl_source: {
      type: String,
      enum: ["public_form", "admin_create"],
      default: "public_form",
    },
    wl_created_at: { type: Date, default: Date.now },
  },
  { collection: "waveled_messages" }
);

const AuditSchema = new Schema(
  {
    wl_actor: { type: String },
    wl_action: { type: String, required: true },
    wl_details: { type: Schema.Types.Mixed },
    wl_ip: { type: String },
    wl_at: { type: Date, default: Date.now },
  },
  { collection: "waveled_audit" }
);

// Models
const WaveledUser = mongoose.model("WaveledUser", UserSchema);
const WaveledCategory = mongoose.model("WaveledCategory", CategorySchema);
const WaveledProduct = mongoose.model("WaveledProduct", ProductSchema);
const WaveledFeaturedHome = mongoose.model(
  "WaveledFeaturedHome",
  FeaturedHomeSchema
);
const WaveledFeaturedProduct = mongoose.model(
  "WaveledFeaturedProduct",
  FeaturedProductSchema
);
const WaveledTopList = mongoose.model("WaveledTopList", TopListSchema);
const WaveledSuccessCase = mongoose.model(
  "WaveledSuccessCase",
  SuccessCaseSchema
);
const WaveledMessage = mongoose.model("WaveledMessage", MessageSchema);
const WaveledAudit = mongoose.model("WaveledAudit", AuditSchema);

// -------------------------------- Seed mínimo --------------------------------
 
// ------------------------------ Valid & Helpers ------------------------------
const validate = (req, res, next) => {
  const v = validationResult(req);
  if (!v.isEmpty()) return errJson(res, "Validação falhou", 422, v.array());
  next();
};

const ensureCategory = async (nameOrId) => {
  if (!nameOrId) throw new Error("Categoria inválida");

  // Se já vier um ObjectId, devolve direto
  if (mongoose.isValidObjectId(nameOrId)) {
    const byId = await WaveledCategory.findById(nameOrId);
    if (!byId) throw new Error("Categoria não encontrada");
    return byId;
  }

  // Normalização forte do nome (trim + collapse espaços) e slug
  const raw = String(nameOrId);
  const name = raw.replace(/\s+/g, " ").trim(); // evita "  |  " virar chaves diferentes
  const slug = makeSlug(name);

  // 1ª tentativa: upsert idempotente (evita corrida)
  try {
    const doc = await WaveledCategory.findOneAndUpdate(
      { $or: [{ wl_slug: slug }, { wl_name: name }] },
      { $setOnInsert: { wl_name: name, wl_slug: slug, wl_created_at: new Date() } },
      { new: true, upsert: true }
    );
    return doc;
  } catch (e) {
    // Se duas requisições baterem ao mesmo tempo, uma ganha e outra apanha E11000.
    if (e && e.code === 11000) {
      // Busca novamente e devolve o existente
      const again = await WaveledCategory.findOne({ $or: [{ wl_slug: slug }, { wl_name: name }] });
      if (again) return again;
    }
    throw e;
  }
};


// ============================== AUTH (SESSÕES) ===============================
app.post(
  "/api/auth/login",
  limiterLogin,
  body("email").isEmail(),
  body("password").isString().isLength({ min: 6 }),
  validate,
  audit("auth.login"),
  asyncH(async (req, res) => {
    const { email, password } = req.body;
    const user = await WaveledUser.findOne({
      wl_email: email,
      wl_active: true,
    });
    if (!user) return errJson(res, "Credenciais inválidas", 401);
    const okPass = await bcrypt.compare(password, user.wl_password_hash);
    if (!okPass) return errJson(res, "Credenciais inválidas", 401);
    req.session.user = {
      id: String(user._id),
      email: user.wl_email,
      role: user.wl_role,
      name: user.wl_name,
    };
    ok(res, { authenticated: true, role: user.wl_role, name: user.wl_name });
  })
);

app.post(
  "/api/auth/logout",
  limiterAuth,
  audit("auth.logout"),
  asyncH(async (req, res) => {
    req.session.destroy((e) => {
      if (e) console.error("Session destroy error:", e);
      res.clearCookie(COOKIE_NAME);
      ok(res, { authenticated: false });
    });
  })
);

app.get(
  "/api/auth/status",
  limiterStrict,
  asyncH(async (req, res) => {
    if (!req.session.user) return ok(res, { authenticated: false });
    ok(res, { authenticated: true, user: req.session.user });
  })
);

app.post(
  "/api/auth/users",
  limiterAuth,
  requireAuth(["admin"]),
  body("name").isString().isLength({ min: 2 }),
  body("email").isEmail(),
  body("password").isString().isLength({ min: 8 }),
  body("role").isIn(["admin", "editor", "viewer"]),
  validate,
  audit("users.create"),
  asyncH(async (req, res) => {
    const { name, email, password, role } = req.body;
    const exists = await WaveledUser.findOne({ wl_email: email });
    if (exists) return errJson(res, "Email já existe", 409);
    const hash = await bcrypt.hash(password, 12);
    const u = await WaveledUser.create({
      wl_name: name,
      wl_email: email,
      wl_password_hash: hash,
      wl_role: role,
    });
    ok(res, { id: u._id });
  })
);

app.get(
  "/api/users",
  limiterAuth,
  requireAuth(["admin"]),
  audit("users.list"),
  asyncH(async (req, res) => {
    const users = await WaveledUser.find({}, { wl_password_hash: 0 }).sort({
      wl_created_at: -1,
    });
    ok(res, users);
  })
);

// ========================== FORM PÚBLICO / MENSAGENS =========================
// POST /api/public/contact
app.post(
  "/api/public/contact",

  // tipo
  body("tipo")
    .isIn(["info", "quote"])
    .withMessage("Tipo inválido.")
    .bail(),

  // comuns
  body("nome").isString().isLength({ min: 2 }).trim().escape()
    .withMessage("Nome obrigatório."),
  body("telefone").isString().isLength({ min: 6 }).trim().escape()
    .withMessage("Telefone inválido."),
  body("email").isEmail().normalizeEmail()
    .withMessage("Email inválido."),
  body("mensagem").isString().isLength({ min: 5 })
    .withMessage("Mensagem muito curta."),

  // consent → converte e valida boolean true
  body("consent")
    .customSanitizer((v) => {
      if (v === true || v === "true" || v === 1 || v === "1") return true;
      return false;
    })
    .isBoolean()
    .custom((v) => v === true)
    .withMessage("É necessário consentimento."),

  // Campos apenas quando tipo === "quote"
  body("solucao")
    .if((value, { req }) => req.body.tipo === "quote")
    .isIn(["led-rental", "led-fixed", "led-iluminacao", "outro"])
    .withMessage("Solução inválida."),
  body("datas")
    .if((value, { req }) => req.body.tipo === "quote")
    .isString().isLength({ min: 2 }).trim().escape()
    .withMessage("Datas/Período obrigatório."),
  body("local")
    .if((value, { req }) => req.body.tipo === "quote")
    .isString().isLength({ min: 2 }).trim().escape()
    .withMessage("Local obrigatório."),
  body("dimensoes")
    .if((value, { req }) => req.body.tipo === "quote")
    .isString().isLength({ min: 1 }).trim().escape()
    .withMessage("Dimensões obrigatórias."),
  body("orcamentoPrevisto")
    .optional()
    .isString().trim().escape(),

  validate,
  audit("public.contact"),

  asyncH(async (req, res) => {
    const payload = {
      tipo: req.body.tipo,
      nome: req.body.nome,
      telefone: req.body.telefone,
      email: req.body.email, 
      solucao: req.body.solucao ?? "outro",
      datas: req.body.datas ?? "n/d",
      local: req.body.local ?? "n/d",
      dimensoes: req.body.dimensoes ?? "n/d",
      orcamentoPrevisto: req.body.orcamentoPrevisto || "",
      precisaMontagem: req.body.precisaMontagem === "nao" ? "nao" : "sim",
      mensagem: req.body.mensagem,
      consent: req.body.consent === true,
    };

    const blob = encrypt(payload);
    await WaveledMessage.create({
      wl_encrypted_blob: blob,
      wl_source: "public_form",
    });

    const html = `
      <h2>Novo pedido (${payload.tipo})</h2>
      <p><strong>Nome:</strong> ${payload.nome}</p>
      <p><strong>Email:</strong> ${payload.email}</p>
      <p><strong>Telefone:</strong> ${payload.telefone}</p>
      <p><strong>Solução:</strong> ${payload.solucao}</p>
      <p><strong>Datas:</strong> ${payload.datas}</p>
      <p><strong>Local:</strong> ${payload.local}</p>
      <p><strong>Dimensões:</strong> ${payload.dimensoes}</p>
      <p><strong>Orçamento:</strong> ${payload.orcamentoPrevisto || "-"}</p>
      <p><strong>Montagem:</strong> ${payload.precisaMontagem}</p>
      <p><strong>Mensagem:</strong></p>
      <pre>${payload.mensagem}</pre>
    `;

    try {
      await transporter.sendMail({
        from:'"Waveled" <no-reply@waveled.pt>',
        to: "comercial@waveled.pt, geral@waveled.pt",
        subject: `Waveled • Novo pedido (${payload.tipo}) de ${payload.nome}`,
        html,
      });
    } catch (e) {
      console.error("Email falhou:", e);
    }

    ok(res, { received: true });
  })
);


app.get(
  "/api/messages",
  limiterAuth,
  requireAuth(["admin", "editor"]),
  audit("messages.list"),
  asyncH(async (req, res) => {
    const rows = await WaveledMessage.find({})
      .sort({ wl_created_at: -1 })
      .limit(200);
    if (String(req.query.decrypt || "") === "1") {
      const out = rows.map((r) => ({
        id: r._id,
        created_at: r.wl_created_at,
        source: r.wl_source,
        payload: decrypt(r.wl_encrypted_blob),
      }));
      ok(res, out);
    } else {
      ok(
        res,
        rows.map((r) => ({
          id: r._id,
          created_at: r.wl_created_at,
          source: r.wl_source,
        }))
      );
    }
  })
);

 

  

function safeUnlinkUpload(removed) {
  try {
    if (removed && removed.startsWith("/uploads/")) {
      const full = path.join(UPLOAD_DIR, path.basename(removed));
      if (full.startsWith(path.resolve(UPLOAD_DIR))) {
        fs.unlink(full, (e) => {
          if (e && e.code !== "ENOENT") console.error("unlink fail:", e);
        });
      }
    }
  } catch (e) {
    console.error("safeUnlinkUpload error:", e);
  }
}

 

app.post(
  "/api/public/contact",
  limiterPublicPost,
  // \u201CHoneypot\u201D opcional (campo invisível que deve vir vazio no frontend)
  body("_hp").optional().isString().isLength({ max: 0 }).withMessage("honeypot not empty"),
  body("tipo").isIn(["info", "quote"]),
  body("nome").isString().isLength({ min: 2, max: 120 }).trim(),
  body("telefone").isString().matches(PHONE_PT).withMessage("Telefone inválido"),
  body("email").isEmail().normalizeEmail(),
  body("solucao").isIn(["led-rental", "led-fixed", "led-iluminacao", "outro"]).withMessage("Solução inválida"),
  body("datas").isString().isLength({ min: 2, max: 120 }).trim(),
  body("local").isString().isLength({ min: 2, max: 120 }).trim(),
  body("dimensoes").isString().isLength({ min: 1, max: 120 }).trim(),
  body("orcamentoPrevisto").optional().isString().isLength({ max: 120 }).trim(),
  body("precisaMontagem").isIn(["sim", "nao"]).withMessage("precisaMontagem inválido"),
  body("mensagem").isString().isLength({ min: 5, max: 4000 }),
  body("consent").equals(true).withMessage("Consentimento obrigatório"),
  // metadados opcionais
  body("utm").optional().isObject(),
  body("page").optional().isString().isLength({ max: 2048 }),
  validate,
  audit("public.contact"),
  asyncH(async (req, res) => {
    // Guard: bloqueia bots pelo honeypot
    if (req.body._hp !== undefined) return ok(res, { received: true });

    const payload = {
      tipo: req.body.tipo,
      nome: req.body.nome,
      telefone: req.body.telefone,
      email: req.body.email,
      solucao: req.body.solucao,
      datas: req.body.datas,
      local: req.body.local,
      dimensoes: req.body.dimensoes,
      orcamentoPrevisto: req.body.orcamentoPrevisto || "",
      precisaMontagem: req.body.precisaMontagem,
      mensagem: req.body.mensagem,
      consent: true,
      meta: {
        ip: req.ip,
        ua: req.get("user-agent") || "",
        referer: req.get("referer") || "",
        page: req.body.page || "",
        utm: req.body.utm || null,
      },
    };

    const blob = encrypt(payload);
    await WaveledMessage.create({ wl_encrypted_blob: blob, wl_source: "public_form" });

    // E-mail interno
    const html = `
      <h2>Novo pedido (${payload.tipo})</h2>
      <p><strong>Nome:</strong> ${payload.nome}</p>
      <p><strong>Email:</strong> ${payload.email}</p>
      <p><strong>Telefone:</strong> ${payload.telefone}</p>
      <p><strong>Solução:</strong> ${payload.solucao}</p>
      <p><strong>Datas:</strong> ${payload.datas}</p>
      <p><strong>Local:</strong> ${payload.local}</p>
      <p><strong>Dimensões:</strong> ${payload.dimensoes}</p>
      <p><strong>Orçamento:</strong> ${payload.orcamentoPrevisto || "-"}</p>
      <p><strong>Montagem:</strong> ${payload.precisaMontagem}</p>
      <p><strong>Mensagem:</strong></p>
      <pre>${payload.mensagem}</pre>
      <hr/>
      <small>IP: ${payload.meta.ip} | UA: ${payload.meta.ua}</small>
    `;
    try {
      await transporter.sendMail({
        from:'"Waveled" <no-reply@waveled.pt>',
        to:"comercial@waveled.pt, geral@waveled.pt",
        subject: `Waveled • Novo pedido (${payload.tipo}) de ${payload.nome}`,
        html,
      });
    } catch (e) {
      console.error("Email falhou:", e);
    }

    // Resposta consistente (para o teu form)
    return res.status(200).json({ ok: true, message: "Pedido recebido com sucesso." });
  })
);

 

// =============================== PRODUTOS (CRUD) =============================
app.post(
  "/api/products", 
  requireAuth(["admin", "editor"]),
  upload.array("images", 12),
  body("name").isString().isLength({ min: 2 }).trim(),
  body("category").isString().isLength({ min: 1 }).trim(),
  body("description_html").optional().isString(),
  body("specs_text").optional().isString(),
  body("datasheet_url").optional().isURL().isLength({ max: 2048 }),
  body("manual_url").optional().isURL().isLength({ max: 2048 }),
  body("sku").optional().isString().isLength({ max: 64 }),
  validate,
  audit("products.create"),
  asyncH(async (req, res) => {
    const cat = await ensureCategory(req.body.category);
    const images = (req.files || []).map(
      (f) => `/uploads/${path.basename(f.path)}`
    );
    const p = await WaveledProduct.create({
      wl_name: req.body.name,
      wl_category: cat._id,
      wl_description_html: req.body.description_html || "",
      wl_specs_text: req.body.specs_text || "",
      wl_datasheet_url: req.body.datasheet_url || "",
      wl_manual_url: req.body.manual_url || "",
      wl_sku: req.body.sku || undefined,
      wl_images: images,
    });
    ok(res, { id: p._id }, 201);
  })
);

app.get(
  "/api/products", 
  query("q").optional().isString(),
  query("category").optional().isString(),
  validate,
  audit("products.list"),
  asyncH(async (req, res) => {
    const { q, category } = req.query;
    const filter = {};
    if (q) filter.$text = { $search: q };
    if (category) {
      const cat = await ensureCategory(category);
      filter.wl_category = cat._id;
    }
    const items = await WaveledProduct.find(filter)
      .sort({ wl_created_at: -1 })
      .limit(200)
      .populate("wl_category");
    ok(res, items);
  })
);

app.get(
  "/api/products/:id", 
  param("id").isMongoId(),
  validate,
  audit("products.single"),
  asyncH(async (req, res) => {
    const p = await WaveledProduct.findById(req.params.id).populate(
      "wl_category"
    );
    if (!p) return errJson(res, "Produto não encontrado", 404);
    ok(res, p);
  })
);

app.put(
  "/api/products/:id", 
  requireAuth(["admin", "editor"]),
  upload.array("images", 12),
  param("id").isMongoId(),
  validate,
  audit("products.update"),
  asyncH(async (req, res) => {
    const p = await WaveledProduct.findById(req.params.id);
    if (!p) return errJson(res, "Produto não encontrado", 404);
    if (req.body.name) p.wl_name = req.body.name;
    if (req.body.category) {
      const cat = await ensureCategory(req.body.category);
      p.wl_category = cat._id;
    }
    if (req.body.description_html !== undefined)
      p.wl_description_html = req.body.description_html;
    if (req.body.specs_text !== undefined) p.wl_specs_text = req.body.specs_text;
    if (req.body.datasheet_url !== undefined)
      p.wl_datasheet_url = req.body.datasheet_url;
    if (req.body.manual_url !== undefined) p.wl_manual_url = req.body.manual_url;
    if (req.body.sku !== undefined) p.wl_sku = req.body.sku || undefined;
    if (req.files?.length)
      p.wl_images = p.wl_images.concat(
        req.files.map((f) => `/uploads/${path.basename(f.path)}`)
      );
    p.wl_updated_at = new Date();
    await p.save();
    ok(res, { updated: true });
  })
);

app.delete(
  "/api/products/:id", 
  requireAuth(["admin"]),
  param("id").isMongoId(),
  validate,
  audit("products.delete"),
  asyncH(async (req, res) => {
    const p = await WaveledProduct.findByIdAndDelete(req.params.id);
    if (!p) return errJson(res, "Produto não encontrado", 404);
    ok(res, { deleted: true });
  })
);

// Likes
app.post(
  "/api/products/:id/like", 
  requireAuth(["admin", "editor", "viewer"]),
  param("id").isMongoId(),
  validate,
  audit("products.like"),
  asyncH(async (req, res) => {
    const p = await WaveledProduct.findByIdAndUpdate(
      req.params.id,
      { $inc: { wl_likes: 1 } },
      { new: true }
    );
    if (!p) return errJson(res, "Produto não encontrado", 404);
    ok(res, { likes: p.wl_likes });
  })
);

app.post(
  "/api/products/:id/unlike", 
  requireAuth(["admin", "editor", "viewer"]),
  param("id").isMongoId(),
  validate,
  audit("products.unlike"),
  asyncH(async (req, res) => {
    const p = await WaveledProduct.findById(req.params.id);
    if (!p) return errJson(res, "Produto não encontrado", 404);
    const newLikes = Math.max(0, (p.wl_likes || 0) - 1);
    p.wl_likes = newLikes;
    await p.save();
    ok(res, { likes: p.wl_likes });
  })
);

/// pegar produtos por categoria
 
app.get(
  "/api/category/:categoryId/bundle", 
  param("categoryId").isString(),
  validate,
  audit("category.bundle.get"),
  asyncH(async (req, res) => {
    // 1) Garantir categoria (aceita ObjectId OU slug / nome)
    const cat = await ensureCategory(req.params.categoryId);
    if (!cat) return errJson(res, "Categoria não encontrada", 404);

    // 2) 3 últimos produtos dessa categoria
    const latest3 = await WaveledProduct.find({ wl_category: cat._id })
      .sort({ wl_created_at: -1, _id: -1 })
      .limit(300)
      .lean();

    // 3) Escolher UM produto da categoria que esteja nos TOPS
    let topDoc = await WaveledTopList.findOne({
      wl_scope: "category",
      wl_category: cat._id,
    }).lean();

    let topProduct = null;
    const pickFirstValidFrom = async (ids = []) => {
      for (const id of ids || []) {
        if (!id) continue;
        const p = await WaveledProduct.findOne({ _id: id, wl_category: cat._id }).lean();
        if (p) return p;
      }
      return null;
    };

    if (topDoc) {
      // prioridade: best -> top3 -> top10
      if (topDoc.wl_best) {
        topProduct = await WaveledProduct.findOne({
          _id: topDoc.wl_best,
          wl_category: cat._id,
        }).lean();
      }
      if (!topProduct && Array.isArray(topDoc.wl_top3)) {
        topProduct = await pickFirstValidFrom(topDoc.wl_top3);
      }
      if (!topProduct && Array.isArray(topDoc.wl_top10)) {
        topProduct = await pickFirstValidFrom(topDoc.wl_top10);
      }
    }

    // 4) “others”: todos os produtos da categoria, EXCLUINDO latest3 e topProduct
    const excludeIds = new Set(latest3.map((p) => String(p._id)));
    if (topProduct) excludeIds.add(String(topProduct._id));

    const others = await WaveledProduct.find({
      wl_category: cat._id,
      _id: { $nin: Array.from(excludeIds) },
    })
      .sort({ wl_created_at: -1, _id: -1 })
      .lean();

    return ok(res, {
      category: { _id: cat._id, wl_name: cat.wl_name, wl_slug: cat.wl_slug },
      latest3,
      topProduct, // pode ser null se não houver tops definidos para a categoria
      others,
      counts: {
        latest3: latest3.length,
        others: others.length,
        excluded: excludeIds.size,
      },
    });
  })
);




// ============================ FEATURED (HOME 4) ==============================
app.get("/api/featured/home", audit("featured.home.get"),
  asyncH(async (req, res) => {
    const doc = await WaveledFeaturedHome.findOne({}).populate("wl_slots");
    ok(res, doc || { wl_slots: [] });
  })
);

app.put(
  "/api/featured/home",
  limiterAuth,
  requireAuth(["admin"]),
  body("slots").isArray({ min: 0, max: 4 }),
  body("slots.*").isMongoId(),
  validate,
  audit("featured.home.set"),
  asyncH(async (req, res) => {
    const ids = req.body.slots;
    let doc = await WaveledFeaturedHome.findOne({});
    if (!doc) doc = new WaveledFeaturedHome({ wl_slots: [] });
    doc.wl_slots = ids;
    doc.wl_updated_at = new Date();
    await doc.save();
    ok(res, { saved: true });
  })
);

// ========================== FEATURED (LISTA GERAL) ===========================
app.post(
  "/api/featured",
  limiterAuth,
  requireAuth(["admin"]),
  body("productId").isMongoId(),
  body("order").optional().isInt({ min: 0, max: 999 }),
  validate,
  audit("featured.add"),
  asyncH(async (req, res) => {
    const exists = await WaveledFeaturedProduct.findOne({
      wl_product: req.body.productId,
    });
    if (exists) return errJson(res, "Já está em destaque", 409);
    await WaveledFeaturedProduct.create({
      wl_product: req.body.productId,
      wl_order: req.body.order || 0,
    });
    await WaveledProduct.findByIdAndUpdate(req.body.productId, {
      $set: { wl_featured_general: true },
    });
    ok(res, { added: true }, 201);
  })
);

app.get(
  "/api/featured", 
  audit("featured.list"),
  asyncH(async (req, res) => {
    const items = await WaveledFeaturedProduct.find({})
      .sort({ wl_order: 1 })
      .populate("wl_product");
    ok(res, items);
  })
);

app.delete(
  "/api/featured/:productId",
  limiterAuth,
  requireAuth(["admin"]),
  param("productId").isMongoId(),
  validate,
  audit("featured.remove"),
  asyncH(async (req, res) => {
    await WaveledFeaturedProduct.findOneAndDelete({
      wl_product: req.params.productId,
    });
    await WaveledProduct.findByIdAndUpdate(req.params.productId, {
      $set: { wl_featured_general: false },
    });
    ok(res, { removed: true });
  })
);

// ============================= RELACIONADOS ==================================
app.get(
  "/api/products/:id/related",
  limiterAuth,
  requireAuth(["admin", "editor", "viewer"]),
  param("id").isMongoId(),
  validate,
  audit("products.related"),
  asyncH(async (req, res) => {
    const p = await WaveledProduct.findById(req.params.id);
    if (!p) return errJson(res, "Produto não encontrado", 404);
    const tokens = (p.wl_specs_text || "")
      .toLowerCase()
      .split(/[^\w]+/g)
      .filter((t) => t.length > 2);
    const uniq = Array.from(new Set(tokens)).slice(0, 12);
    const q = uniq.length ? uniq.join(" ") : p.wl_name;
    const candidates = await WaveledProduct.find(
      {
        _id: { $ne: p._id },
        wl_category: p.wl_category,
        $text: { $search: q },
      },
      { score: { $meta: "textScore" } }
    )
      .sort({ score: { $meta: "textScore" } })
      .limit(5);
    ok(res, candidates);
  })
);

// ============================ CASOS DE SUCESSO ===============================
app.post(
  "/api/success-cases",
  limiterAuth,
  requireAuth(["admin", "editor"]),
  upload.array("images", 12),
  body("company_name").isString().isLength({ min: 2 }).trim(),
  body("title").isString().isLength({ min: 2 }).trim(),
  body("description_html").optional().isString(),
  validate,
  audit("success.create"),
  asyncH(async (req, res) => {
    const images = (req.files || []).map(
      (f) => `/uploads/${path.basename(f.path)}`
    );
    const c = await WaveledSuccessCase.create({
      wl_company_name: req.body.company_name,
      wl_title: req.body.title,
      wl_description_html: req.body.description_html || "",
      wl_images: images,
    });
    ok(res, { id: c._id }, 201);
  })
);

app.get(
  "/api/success-cases", 
  audit("success.list"),
  asyncH(async (req, res) => {
    const items = await WaveledSuccessCase.find({})
      .sort({ wl_created_at: -1 })
      .limit(200);
    ok(res, items);
  })
);

app.delete(
  "/api/success-cases/:id",
  limiterAuth,
  requireAuth(["admin"]),
  param("id").isMongoId(),
  validate,
  audit("success.delete"),
  asyncH(async (req, res) => {
    const c = await WaveledSuccessCase.findByIdAndDelete(req.params.id);
    if (!c) return errJson(res, "Registo não encontrado", 404);
    ok(res, { deleted: true });
  })
);

 
// GET one by id
app.get(
  "/api/success-cases/:id",
  audit("success.get"),
  param("id").isMongoId(),
  validate,
  asyncH(async (req, res) => {
    const c = await WaveledSuccessCase.findById(req.params.id);
    if (!c) return errJson(res, "Registo não encontrado", 404);
    ok(res, c);
  })
);

 

// --------------------------- SUCCESS CASES (CRUD+) ---------------------------
// 1) UPDATE/EDITAR caso de sucesso (texto + adicionar imagens)
app.put(
  "/api/success-cases/:id",
  limiterAuth,
  requireAuth(["admin", "editor"]),
  upload.array("images", 12), // permite anexar novas imagens
  param("id").isMongoId(),
  body("company_name").optional().isString().isLength({ min: 2 }).trim(),
  body("title").optional().isString().isLength({ min: 2 }).trim(),
  body("description_html").optional().isString(),
  validate,
  audit("success.update"),
  asyncH(async (req, res) => {
    const c = await WaveledSuccessCase.findById(req.params.id);
    if (!c) return errJson(res, "Registo não encontrado", 404);

    if (req.body.company_name) c.wl_company_name = req.body.company_name;
    if (req.body.title) c.wl_title = req.body.title;
    if (req.body.description_html !== undefined) c.wl_description_html = req.body.description_html;

    if (req.files?.length) {
      const imgs = req.files.map((f) => `/uploads/${path.basename(f.path)}`);
      c.wl_images = c.wl_images.concat(imgs);
    }

    await c.save();
    ok(res, { updated: true, id: c._id, images: c.wl_images });
  })
);

// 2) Remover UMA imagem específica do caso de sucesso (por src OU index)
app.delete(
  "/api/success-cases/:id/images",
  limiterAuth,
  requireAuth(["admin", "editor"]),
  param("id").isMongoId(),
  body("src").optional().isString(),
  body("index").optional().isInt({ min: 0 }),
  validate,
  audit("success.image.remove"),
  asyncH(async (req, res) => {
    const c = await WaveledSuccessCase.findById(req.params.id);
    if (!c) return errJson(res, "Registo não encontrado", 404);

    const src = (req.body?.src || req.query?.src || "").trim();
    const idxParam = req.body?.index ?? req.query?.index;
    const hasIndex = idxParam !== undefined && idxParam !== null && idxParam !== "";
    const index = hasIndex ? Number(idxParam) : null;

    let idx = -1;
    if (src) {
      const base = path.basename(src);
      idx = c.wl_images.findIndex((im) => im === src || path.basename(im) === base);
    } else if (hasIndex) {
      if (Number.isNaN(index) || index < 0 || index >= c.wl_images.length) {
        return errJson(res, "Index de imagem inválido", 422);
      }
      idx = index;
    } else {
      return errJson(res, "Informe 'src' ou 'index' para remover a imagem", 422);
    }

    if (idx < 0) return errJson(res, "Imagem não encontrada no caso", 404);

    const [removed] = c.wl_images.splice(idx, 1);
    await c.save();
    safeUnlinkUpload(removed);

    ok(res, { removed, images: c.wl_images, count: c.wl_images.length });
  })
);

// 3) (Opcional) Reordenar imagens do caso de sucesso
app.put(
  "/api/success-cases/:id/images/reorder",
  limiterAuth,
  requireAuth(["admin", "editor"]),
  param("id").isMongoId(),
  body("order").isArray({ min: 1 }), // array de novas posições por índice atual
  validate,
  audit("success.image.reorder"),
  asyncH(async (req, res) => {
    const c = await WaveledSuccessCase.findById(req.params.id);
    if (!c) return errJson(res, "Registo não encontrado", 404);

    const order = req.body.order.map(Number);
    if (order.some((n) => Number.isNaN(n) || n < 0 || n >= c.wl_images.length)) {
      return errJson(res, "Array de ordenação inválido", 422);
    }

    const newArr = new Array(c.wl_images.length);
    order.forEach((newPos, oldIndex) => { newArr[newPos] = c.wl_images[oldIndex]; });
    if (newArr.some((v) => v === undefined)) return errJson(res, "Ordenação incompleta", 422);

    c.wl_images = newArr;
    await c.save();
    ok(res, { reordered: true, images: c.wl_images });
  })
);


// ================================ TOP LISTS ==================================
app.get(
  "/api/top/overall",
  limiterAuth,
  requireAuth(["admin", "editor", "viewer"]),
  audit("top.overall.get"),
  asyncH(async (req, res) => {
    let doc = await WaveledTopList.findOne({ wl_scope: "overall" }).populate(
      "wl_top10 wl_best"
    );
    if (!doc)
      doc = await WaveledTopList.create({ wl_scope: "overall", wl_top10: [] });
    ok(res, doc);
  })
);

app.put(
  "/api/top/overall",
  limiterAuth,
  requireAuth(["admin"]),
  body("top10").isArray({ min: 0, max: 10 }),
  body("top10.*").isMongoId(),
  body("best").optional().isMongoId(),
  validate,
  audit("top.overall.set"),
  asyncH(async (req, res) => {
    let doc = await WaveledTopList.findOne({ wl_scope: "overall" });
    if (!doc) doc = new WaveledTopList({ wl_scope: "overall" });
    doc.wl_top10 = req.body.top10 || [];
    doc.wl_best = req.body.best || null;
    doc.wl_updated_at = new Date();
    await doc.save();
    ok(res, { saved: true });
  })
);

app.get(
  "/api/top/category/:categoryId",
  limiterAuth,
  requireAuth(["admin", "editor", "viewer"]),
  param("categoryId").isString(),
  validate,
  audit("top.category.get"),
  asyncH(async (req, res) => {
    const cat = await ensureCategory(req.params.categoryId);
    let doc = await WaveledTopList.findOne({
      wl_scope: "category",
      wl_category: cat._id,
    }).populate("wl_top10 wl_top3 wl_best");
    if (!doc)
      doc = await WaveledTopList.create({
        wl_scope: "category",
        wl_category: cat._id,
        wl_top10: [],
        wl_top3: [],
      });
    ok(res, doc);
  })
);

app.put(
  "/api/top/category/:categoryId",
  limiterAuth,
  requireAuth(["admin"]),
  param("categoryId").isString(),
  body("top3").optional().isArray({ min: 0, max: 3 }),
  body("top3.*").optional().isMongoId(),
  body("top10").optional().isArray({ min: 0, max: 10 }),
  body("top10.*").optional().isMongoId(),
  body("best").optional().isMongoId(),
  validate,
  audit("top.category.set"),
  asyncH(async (req, res) => {
    const cat = await ensureCategory(req.params.categoryId);
    let doc = await WaveledTopList.findOne({
      wl_scope: "category",
      wl_category: cat._id,
    });
    if (!doc) doc = new WaveledTopList({ wl_scope: "category", wl_category: cat._id });
    if (req.body.top3) doc.wl_top3 = req.body.top3;
    if (req.body.top10) doc.wl_top10 = req.body.top10;
    if (req.body.best !== undefined) doc.wl_best = req.body.best || null;
    doc.wl_updated_at = new Date();
    await doc.save();
    ok(res, { saved: true });
  })
);




// --- slug helper (coloca junto com os outros helpers) ---
const makeSlug = (name) =>
  String(name || "")
    .toLowerCase()
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "") // remove acentos
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");



// Remover UMA imagem do produto (por src ou index)
app.delete(
  "/api/products/:id/images",
  limiterAuth,
  requireAuth(["admin", "editor"]),
  param("id").isMongoId(),
  // Aceita src (string) OU index (int). DELETE pode vir sem body em alguns clientes,
  // por isso permitimos também querystring (?src=... ou ?index=1).
  body("src").optional().isString(),
  body("index").optional().isInt({ min: 0 }),
  validate,
  audit("products.image.remove"),
  asyncH(async (req, res) => {
    const p = await WaveledProduct.findById(req.params.id);
    if (!p) return errJson(res, "Produto não encontrado", 404);

    const src = (req.body?.src || req.query?.src || "").trim();
    const idxParam = req.body?.index ?? req.query?.index;
    const hasIndex = idxParam !== undefined && idxParam !== null && idxParam !== "";
    const index = hasIndex ? Number(idxParam) : null;

    let idx = -1;

    if (src) {
      const base = path.basename(src);
      idx = p.wl_images.findIndex(
        (im) => im === src || path.basename(im) === base
      );
    } else if (hasIndex) {
      if (Number.isNaN(index) || index < 0 || index >= p.wl_images.length) {
        return errJson(res, "Index de imagem inválido", 422);
      }
      idx = index;
    } else {
      return errJson(res, "Informe 'src' ou 'index' para remover a imagem", 422);
    }

    if (idx < 0) return errJson(res, "Imagem não encontrada no produto", 404);

    const [removed] = p.wl_images.splice(idx, 1);
    p.wl_updated_at = new Date();
    await p.save();

    // Tenta apagar o ficheiro local de forma segura (apenas se for do /uploads)
    // Ex.: wl_images guarda "/uploads/1699999999_abcd1234.jpg"
    try {
      if (removed && removed.startsWith("/uploads/")) {
        const fileOnDisk = path.join(UPLOAD_DIR, path.basename(removed));
        // Só apaga se estiver dentro do diretório UPLOAD_DIR
        if (fileOnDisk.startsWith(path.resolve(UPLOAD_DIR))) {
          fs.unlink(fileOnDisk, (e) => {
            if (e && e.code !== "ENOENT") {
              console.error("Falha ao apagar ficheiro:", e);
            }
          });
        }
      }
    } catch (e) {
      console.error("Erro ao tentar remover ficheiro:", e);
    }

    ok(res, {
      removed,
      images: p.wl_images,
      count: p.wl_images.length,
    });
  })
);


// ============================== “ CATEGORIAS ” ================================


 //   wl_order: { type: Number, default: 0, index: true }, // <— campo de ordenação

 



async function normalizeCategoryOrder(WaveledCategory) {
  const list = await WaveledCategory.find({}).sort({ wl_order: 1, wl_name: 1 });
  const ops = list.map((doc, i) => ({
    updateOne: {
      filter: { _id: doc._id },
      update: { $set: { wl_order: i } },
    },
  }));
  if (ops.length) await WaveledCategory.bulkWrite(ops);
}

/**
 * Próximo valor de ordem (fim da fila).
 */
async function nextOrder(WaveledCategory) {
  const last = await WaveledCategory.findOne({}).sort({ wl_order: -1 });
  return typeof last?.wl_order === "number" ? last.wl_order + 1 : 0;
}

/**
 * Reordena a lista completa de IDs.
 * Aceita ["id1","id2"] ou [{_id:"id1"}, ...].
 * Se orderedIds não tiver todos os docs, os não listados vão para o fim mantendo ordem atual.
 */
async function reorderFull(WaveledCategory, orderedIdsRaw) {
  const orderedIds = (orderedIdsRaw || [])
    .map((x) => (typeof x === "string" ? x : x?._id))
    .filter(Boolean)
    .map(String);

  // Sanidade: sem duplicados
  const uniq = [...new Set(orderedIds)];
  if (uniq.length !== orderedIds.length) {
    const err = new Error("IDs duplicados na ordenação");
    err.status = 400;
    throw err;
  }

  // Todos que existem
  const all = await WaveledCategory.find({}).sort({ wl_order: 1, wl_name: 1 });
  const allIds = all.map((d) => String(d._id));

  // Verifica se todos orderedIds existem (os que foram passados)
  const notFound = uniq.filter((id) => !allIds.includes(id));
  if (notFound.length) {
    const err = new Error(`Alguns IDs não existem: ${notFound.join(", ")}`);
    err.status = 400;
    throw err;
  }

  // Constrói nova ordem: primeiro os enviados, depois os restantes
  const remaining = allIds.filter((id) => !uniq.includes(id));
  const finalOrder = [...uniq, ...remaining];

  // Persiste SEMPRE com $set
  const bulkOps = finalOrder.map((id, idx) => ({
    updateOne: {
      filter: { _id: id },
      update: { $set: { wl_order: idx } },
    },
  }));
  if (bulkOps.length) await WaveledCategory.bulkWrite(bulkOps);
}

 
 
 

// =============================== CATEGORIES (CRUD + ORDER) ===============================

 
  app.get(
    "/api/categories",
    limiterAuth,
    requireAuth(["admin", "editor", "viewer"]),
    audit("categories.list"),
    asyncH(async (req, res) => {
      if (String(req.query.normalize || "0") === "1") {
        await normalizeCategoryOrder(WaveledCategory);
      }
      const items = await WaveledCategory.find({}).sort({ wl_order: 1, wl_name: 1 });
      ok(res, items);
    })
  );

  // GET /api/categories/:idOrSlug
  app.get(
    "/api/categories/:idOrSlug",
    limiterAuth,
    requireAuth(["admin", "editor", "viewer"]),
    audit("categories.single"),
    asyncH(async (req, res) => {
      const { idOrSlug } = req.params;
      let cat;
      if (mongoose.isValidObjectId(idOrSlug)) {
        cat = await WaveledCategory.findById(idOrSlug);
      } else {
        cat = await WaveledCategory.findOne({ wl_slug: String(idOrSlug).toLowerCase() });
      }
      if (!cat) return errJson(res, "Categoria não encontrada", 404);
      ok(res, cat);
    })
  );

  // POST /api/categories
  app.post(
    "/api/categories",
    limiterAuth,
    requireAuth(["admin", "editor"]),
    body("name").isString().isLength({ min: 2 }).trim(),
    body("slug").optional().isString().trim(),
    validate,
    audit("categories.create"),
    asyncH(async (req, res) => {
      const name = req.body.name.trim();
      const slug = (req.body.slug || makeSlug(name)).toLowerCase();

      const exists = await WaveledCategory.findOne({
        $or: [{ wl_name: name }, { wl_slug: slug }],
      });
      if (exists) return errJson(res, "Nome/slug já existente", 409);

      const order = await nextOrder(WaveledCategory);

      const created = await WaveledCategory.create({
        wl_name: name,
        wl_slug: slug,
        wl_order: order,
      });

      ok(res, { id: created._id }, 201);
    })
  );

  // PUT /api/categories/:id
  app.put(
    "/api/categories/:id",
    limiterAuth,
    requireAuth(["admin", "editor"]),
    param("id").isMongoId(),
    body("name").optional().isString().isLength({ min: 2 }).trim(),
    body("slug").optional().isString().trim(),
    validate,
    audit("categories.update"),
    asyncH(async (req, res) => {
      const cat = await WaveledCategory.findById(req.params.id);
      if (!cat) return errJson(res, "Categoria não encontrada", 404);

      if (req.body.name) cat.wl_name = req.body.name.trim();

      if (req.body.slug) {
        cat.wl_slug = req.body.slug.trim().toLowerCase();
      } else if (req.body.name) {
        cat.wl_slug = makeSlug(req.body.name);
      }

      // garantir unicidade
      const conflict = await WaveledCategory.findOne({
        _id: { $ne: cat._id },
        $or: [{ wl_name: cat.wl_name }, { wl_slug: cat.wl_slug }],
      });
      if (conflict) return errJson(res, "Nome/slug já em uso por outra categoria", 409);

      await cat.save();
      ok(res, { updated: true });
    })
  );

  // DELETE /api/categories/:id
  app.delete(
    "/api/categories/:id",
    limiterAuth,
    requireAuth(["admin"]),
    param("id").isMongoId(),
    validate,
    audit("categories.delete"),
    asyncH(async (req, res) => {
      const cat = await WaveledCategory.findById(req.params.id);
      if (!cat) return errJson(res, "Categoria não encontrada", 404);

      // Bloqueio se em uso (ajusta se não precisares disto)
      const inUseCount = await WaveledProduct.countDocuments({ wl_category: cat._id });
      if (inUseCount > 0) {
        return errJson(
          res,
          `Categoria está em uso por ${inUseCount} produto(s). Remova/realoque os produtos antes de apagar.`,
          409
        );
      }

      await WaveledCategory.findByIdAndDelete(cat._id);
      await normalizeCategoryOrder(WaveledCategory);

      ok(res, { deleted: true });
    })
  );

  // POST /api/categories/reorder  (ordem completa)
  app.post(
    "/api/categories/reorder",
    limiterAuth,
    requireAuth(["admin", "editor"]),
    body("orderedIds").isArray({ min: 1 }),
    validate,
    audit("categories.reorder"),
    asyncH(async (req, res) => {
      await reorderFull(WaveledCategory, req.body.orderedIds);
      ok(res, { reordered: true });
    })
  );

  // PATCH /api/categories/:id/reorder-step  (↑/↓ 1 passo)
  app.patch(
    "/api/categories/:id/reorder-step",
    limiterAuth,
    requireAuth(["admin", "editor"]),
    param("id").isMongoId(),
    body("direction").isIn(["up", "down"]),
    validate,
    audit("categories.reorder-step"),
    asyncH(async (req, res) => {
      const { id } = req.params;
      const { direction } = req.body;

      const list = await WaveledCategory.find({}).sort({ wl_order: 1, wl_name: 1 });
      const idx = list.findIndex((c) => String(c._id) === String(id));
      if (idx === -1) return errJson(res, "Categoria não encontrada", 404);

      const swapWith = direction === "up" ? idx - 1 : idx + 1;
      if (swapWith < 0 || swapWith >= list.length) return ok(res, { reordered: false });

      const a = list[idx];
      const b = list[swapWith];

      // swap seguro SEMPRE com $set
      await WaveledCategory.bulkWrite([
        { updateOne: { filter: { _id: a._id }, update: { $set: { wl_order: b.wl_order } } } },
        { updateOne: { filter: { _id: b._id }, update: { $set: { wl_order: a.wl_order } } } },
      ]);

      ok(res, { reordered: true });
    })
  );
 






















 


// ===== Mongo Schemas/Models (tudo num só ficheiro, um único mongoose)
const ExampleShowcaseSchema = new mongoose.Schema(
  {
    categoryId: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', index: true },
    productId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Product', index: true },
    title:      { type: String, required: true },
    description:{ type: String, default: '' },
    image:      { type: String, required: true }, // relative path or external URL
  },
  { timestamps: true }
);
ExampleShowcaseSchema.index({ categoryId: 1, productId: 1, createdAt: -1 });
const ExampleShowcase = mongoose.model('ExampleShowcase', ExampleShowcaseSchema);

const CategoryVideoSchema = new mongoose.Schema(
  {
    categoryId: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', unique: true, index: true },
    videoUrl:   { type: String, default: '' },
    videoText:  { type: String, default: '' }, // rich text (html)
  },
  { timestamps: true }
);
const CategoryVideo = mongoose.model('CategoryVideo', CategoryVideoSchema);

const CategoryStyleSchema = new mongoose.Schema(
  {
    categoryId: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', unique: true, index: true },
    color:      { type: String, default: '#1e293b' },
    subtitle:   { type: String, default: '' },
  },
  { timestamps: true }
);
const CategoryStyle = mongoose.model('CategoryStyle', CategoryStyleSchema);

// ===== Upload (images)
const uploadDir = path.join(process.cwd(), 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

 

app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Ficheiro ausente' });
  return res.json({ path: `/uploads/${req.file.filename}` });
});

// ===== Examples CRUD
app.get('/api/examples', async (req, res) => {
  try {
    const { categoryId, productId } = req.query;
    const q = {};
    if (categoryId) q.categoryId = categoryId;
    if (productId) q.productId = productId;
    const items = await ExampleShowcase.find(q).sort({ createdAt: -1 }).lean();
    res.json({ data: items });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/examples', async (req, res) => {
  try {
    const { categoryId, productId, items } = req.body || {};
    if (!categoryId && !productId) {
      return res.status(400).json({ error: 'categoryId ou productId é obrigatório' });
    }
    if (!Array.isArray(items) || !items.length) {
      return res.status(400).json({ error: 'items vazio' });
    }

    const docs = items.map(it => ({
      categoryId: categoryId || undefined,
      productId:  productId  || undefined,
      title:      it.title,
      description:it.description || '',
      image:      it.image,
    }));

    const created = await ExampleShowcase.insertMany(docs);
    res.json({ ok: true, data: created });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/examples/:id', async (req, res) => {
  try {
    await ExampleShowcase.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== Category Video















async function resolveCategoryId(idOrName) {
  const key = String(idOrName || "").trim();
  if (!key) return null;

  // 1) ObjectId
  if (Types.ObjectId.isValid(key)) {
    return key;
  }

  // 2) slug (lowercase exato)
  const slug = key.toLowerCase();
  let cat = await WaveledCategory.findOne({ wl_slug: slug }, { _id: 1 }).lean();
  if (cat?._id) return String(cat._id);

  // 3) nome normalizado (case/acento-insensitive)
  const norm = normalizeName(key);
  cat = await WaveledCategory.findOne({ wl_name_norm: norm }, { _id: 1 }).lean();
  if (cat?._id) return String(cat._id);

  // 4) opcional: match exato case-insensitive em wl_name (fallback)
  cat = await WaveledCategory.findOne(
    { wl_name: { $regex: `^${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, $options: "i" } },
    { _id: 1 }
  ).lean();
  if (cat?._id) return String(cat._id);

  return null; 
}

 
/* =========================
   ROUTES: STYLE
   Aceita :id como ObjectId, wl_slug ou wl_name
========================= */

// GET /api/categories/:id/style
app.get('/api/categories/:id/style', async (req, res) => {
  try {
    const cid = await resolveCategoryId(req.params.id);
    if (!cid) {
      // mantém resposta vazia se não encontrou
      return res.json({ data: {} });
    }
    const doc = await CategoryStyle.findOne({ categoryId: cid }).lean();
    res.json({ data: doc || {} });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PUT /api/categories/:id/style
app.put('/api/categories/:id/style', async (req, res) => {
  try {
    const cid = await resolveCategoryId(req.params.id);
    if (!cid) return res.status(404).json({ error: 'Categoria não encontrada para o identificador fornecido.' });

    const { color = '#1e293b', subtitle = '' } = req.body || {};
    const doc = await CategoryStyle.findOneAndUpdate(
      { categoryId: cid },
      { categoryId: cid, color, subtitle },
      { upsert: true, new: true }
    );
    res.json({ ok: true, data: doc });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* =========================
   ROUTES: VIDEO
   Aceita :id como ObjectId, wl_slug ou wl_name
========================= */

// GET /api/categories/:id/video
app.get('/api/categories/:id/video', async (req, res) => {
  try {
    const cid = await resolveCategoryId(req.params.id);
    if (!cid) {
      return res.json({ data: {} });
    }
    const doc = await CategoryVideo.findOne({ categoryId: cid }).lean();
    res.json({ data: doc || {} });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PUT /api/categories/:id/video
app.put('/api/categories/:id/video', async (req, res) => {
  try {
    const cid = await resolveCategoryId(req.params.id);
    if (!cid) return res.status(404).json({ error: 'Categoria não encontrada para o identificador fornecido.' });

    const { videoUrl = '', videoText = '' } = req.body || {};
    const doc = await CategoryVideo.findOneAndUpdate(
      { categoryId: cid },
      { categoryId: cid, videoUrl, videoText },
      { upsert: true, new: true }
    );
    res.json({ ok: true, data: doc });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

 
 

//================================ "SOLUÇÕES" ==================================






// backend/solutions.module.js
// Full Express + Mongoose backend for "Solutions" with:
// - CRUD de soluções (/api/solutions)
// - Produtos relacionados à solução
// - Kits (combinações de produtos) por solução
// - Exemplos (imagem+texto) por solução
//
// Compatível com o teu frontend (endpoints e payloads). Coloca este ficheiro no teu servidor
// Node/Express, garante que a conexão ao Mongo já está estabelecida noutro ponto da app
// (ex.: mongoose.connect(...)) e chama `registerSolutionsModule(app)` no bootstrap.

 
// ===================== Utils =====================
 

const ensureValid = (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: errors.array().map((e) => e.msg).join('; ') });
  }
};

// ===================== Schemas/Models =====================
// Product: assumimos que já existe no teu projeto.
// Aqui usamos apenas o _id e alguns campos comuns no populate.
// const Product = mongoose.model('Product');

const SolutionSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, index: 'text' },
    description: { type: String, default: '' },
    image: { type: String, default: '' },
  },
  { timestamps: true }
);
const Solution = mongoose.model('Solution', SolutionSchema);

const SolutionRelatedProductSchema = new mongoose.Schema(
  {
    solutionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Solution', required: true, index: true },
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true, index: true },
  },
  { timestamps: true }
);
SolutionRelatedProductSchema.index({ solutionId: 1, productId: 1 }, { unique: true });
const SolutionRelatedProduct = mongoose.model('SolutionRelatedProduct', SolutionRelatedProductSchema);

const SolutionKitSchema = new mongoose.Schema(
  {
    solutionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Solution', required: true, index: true },
    name: { type: String, required: true },
    productIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
  },
  { timestamps: true }
);
const SolutionKit = mongoose.model('SolutionKit', SolutionKitSchema);

const SolutionExampleSchema = new mongoose.Schema(
  {
    solutionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Solution', required: true, index: true },
    title: { type: String, required: true },
    description: { type: String, default: '' },
    image: { type: String, required: true },
  },
  { timestamps: true }
);
const SolutionExample = mongoose.model('SolutionExample', SolutionExampleSchema);

// ===================== Router/Module =====================


const { Types } = mongoose;
async function getProductsBasic(ids = []) {
  const col = mongoose.connection.collection('products');
  const objectIds = ids
    .filter(Boolean)
    .map((x) => (Types.ObjectId.isValid(x) ? new Types.ObjectId(String(x)) : null))
    .filter(Boolean);

  if (!objectIds.length) return [];
  const docs = await col
    .find({ _id: { $in: objectIds } }, { projection: { wl_name: 1, wl_images: 1 } })
    .toArray();

  return docs.map((d) => ({
    _id: d._id,
    wl_name: d.wl_name || '',
    wl_images: Array.isArray(d.wl_images) ? d.wl_images : [],
  }));
}





 
 

  // --------- /api/solutions (list) ---------
  app.get(
    '/api/solutions/',
    [query('q').optional().isString().withMessage('q inválido')],
    asyncH(async (req, res) => {
      const err = ensureValid(req, res); if (err) return err;
      const { q } = req.query;
      let filter = {};
      if (q && q.trim()) {
        // Pesquisa simples por título/descrição
        filter = { $or: [
          { title: { $regex: q.trim(), $options: 'i' } },
          { description: { $regex: q.trim(), $options: 'i' } },
        ]};
      }
      const items = await Solution.find(filter).sort({ createdAt: -1 }).lean();
      return res.json({ data: items });
    })
  );

  // --------- /api/solutions (create) ---------
  app.post(
    '/api/solutions/',
    [
      body('title').isString().trim().notEmpty().withMessage('title é obrigatório'),
      body('description').optional().isString(),
      body('image').optional().isString(),
    ],
    asyncH(async (req, res) => {
      const err = ensureValid(req, res); if (err) return err;
      const { title, description = '', image = '' } = req.body || {};
      const created = await Solution.create({ title, description, image });
      return res.json({ ok: true, data: created });
    })
  );

  // --------- /api/solutions/:id (update) ---------
  app.put(
    '/api/solutions/:id',
    [
      param('id').isMongoId().withMessage('id inválido'),
      body('title').optional().isString(),
      body('description').optional().isString(),
      body('image').optional().isString(),
    ],
    asyncH(async (req, res) => {
      const err = ensureValid(req, res); if (err) return err;
      const { id } = req.params;
      const { title, description, image } = req.body || {};
      const updated = await Solution.findByIdAndUpdate(
        id,
        { $set: { ...(title !== undefined && { title }), ...(description !== undefined && { description }), ...(image !== undefined && { image }) } },
        { new: true }
      );
      if (!updated) return res.status(404).json({ error: 'Solução não encontrada' });
      return res.json({ ok: true, data: updated });
    })
  );

  // --------- /api/solutions/:id (delete) ---------
  app.delete(
    '/api/solutions/:id',
    [param('id').isMongoId().withMessage('id inválido')],
    asyncH(async (req, res) => {
      const err = ensureValid(req, res); if (err) return err;
      const { id } = req.params;
      const removed = await Solution.findByIdAndDelete(id);
      if (!removed) return res.status(404).json({ error: 'Solução não encontrada' });
      // cascade: apaga vínculos/filhos
      await Promise.all([
        SolutionRelatedProduct.deleteMany({ solutionId: id }),
        SolutionKit.deleteMany({ solutionId: id }),
        SolutionExample.deleteMany({ solutionId: id }),
      ]);
      return res.json({ ok: true });
    })
  );

  // =============== Produtos relacionados ===============

 
 app.get(
  '/api/solutions/:id/products',
  [param('id').isMongoId().withMessage('id inválido')],
  asyncH(async (req, res) => {
    const err = ensureValid(req, res); if (err) return err;
    const { id } = req.params;

    const rels = await SolutionRelatedProduct.find({ solutionId: id }).lean();
    const productIds = rels.map((r) => r.productId);
    if (!productIds.length) return res.json({ data: [] });

    const products = await getProductsBasic(productIds);
    return res.json({ data: products });
  })
);
 
 
app.post(
  '/api/solutions/:id/products',
  [
    param('id').isMongoId().withMessage('id inválido'),
    body('productId').isMongoId().withMessage('productId inválido'),
  ],
  asyncH(async (req, res) => {
    const err = ensureValid(req, res); if (err) return err;
    const { id } = req.params;
    const { productId } = req.body || {};

    const exists = await Solution.exists({ _id: id });
    if (!exists) return res.status(404).json({ error: 'Solução não encontrada' });

    await SolutionRelatedProduct.updateOne(
      { solutionId: id, productId },
      { $setOnInsert: { solutionId: id, productId } },
      { upsert: true }
    );
 
    const prods = await getProductsBasic([productId]);
    const product = prods?.[0] || { _id: productId, wl_name: '(produto)', wl_images: [] };

    return res.json({ ok: true, data: product });
  })
);









  app.delete(
    '/api/solutions/:id/products/:productId',
    [
      param('id').isMongoId().withMessage('id inválido'),
      param('productId').isMongoId().withMessage('productId inválido'),
    ],
    asyncH(async (req, res) => {
      const err = ensureValid(req, res); if (err) return err;
      const { id, productId } = req.params;
      await SolutionRelatedProduct.deleteOne({ solutionId: id, productId });
      return res.json({ ok: true });
    })
  );

  // =============== Kits ===============


 

app.get(
  '/api/solutions/:id/kits',
  [param('id').isMongoId().withMessage('id inválido')],
  asyncH(async (req, res) => {
    const err = ensureValid(req, res); if (err) return err;
    const { id } = req.params;

    const kits = await SolutionKit.find({ solutionId: id })
      .sort({ createdAt: -1 })
      .lean();

    if (!kits.length) return res.json({ data: [] });

    const allIds = [...new Set(kits.flatMap(k => (k.productIds || []).map(String)))];
    const prodDocs = await getProductsBasic(allIds);
    const byId = new Map(prodDocs.map(p => [String(p._id), p]));

    const enriched = kits.map(k => ({
      ...k,
      products: (k.productIds || []).map(pid => byId.get(String(pid)) || { _id: pid, wl_name: '(produto removido)', wl_images: [] }),
    }));

    return res.json({ data: enriched });
  })
);


app.post(
  '/api/solutions/:id/kits',
  [
    param('id').isMongoId().withMessage('id inválido'),
    body('name').isString().trim().notEmpty().withMessage('name é obrigatório'),
    body('productIds').isArray({ min: 1 }).withMessage('productIds deve ser array com pelo menos 1 item'),
    body('productIds.*').isMongoId().withMessage('productIds contém id inválido'),
  ],
  asyncH(async (req, res) => {
    const err = ensureValid(req, res); if (err) return err;
    const { id } = req.params;
    const { name, productIds } = req.body || {};

    const exists = await Solution.exists({ _id: id });
    if (!exists) return res.status(404).json({ error: 'Solução não encontrada' });

    const created = await SolutionKit.create({ solutionId: id, name, productIds });

    const prodDocs = await getProductsBasic(productIds);
    const byId = new Map(prodDocs.map(p => [String(p._id), p]));
    const enriched = {
      ...created.toObject(),
      products: productIds.map(pid => byId.get(String(pid)) || { _id: pid, wl_name: '(produto removido)', wl_images: [] }),
    };

    return res.json({ ok: true, data: enriched });
  })
);




 
  app.delete(
    '/api/solutions/:id/kits/:kitId',
    [param('id').isMongoId().withMessage('id inválido'), param('kitId').isMongoId().withMessage('kitId inválido')],
    asyncH(async (req, res) => {
      const err = ensureValid(req, res); if (err) return err;
      const { id, kitId } = req.params;
      await SolutionKit.deleteOne({ _id: kitId, solutionId: id });
      return res.json({ ok: true });
    })
  );

  // =============== Exemplos ===============
  app.get(
    '/api/solutions/:id/examples',
    [param('id').isMongoId().withMessage('id inválido')],
    asyncH(async (req, res) => {
      const err = ensureValid(req, res); if (err) return err;
      const { id } = req.params;
      const items = await SolutionExample.find({ solutionId: id }).sort({ createdAt: -1 }).lean();
      return res.json({ data: items });
    })
  );

  app.put(
  '/api/solutions/:id/examples/:exampleId',
  [
    param('id').isMongoId().withMessage('id inválido'),
    param('exampleId').isMongoId().withMessage('exampleId inválido'),
    body('title').optional().isString().trim().notEmpty().withMessage('title inválido'),
    body('description').optional().isString(),
    body('image').optional().isString().trim().notEmpty().withMessage('image inválida'),
  ],
  asyncH(async (req, res) => {
    const err = ensureValid(req, res); if (err) return err;
    const { id, exampleId } = req.params;
    const { title, description, image } = req.body || {};

    // Verifica se a solução existe
    const solutionExists = await Solution.exists({ _id: id });
    if (!solutionExists) return res.status(404).json({ error: 'Solução não encontrada' });

    // Verifica se o exemplo pertence à solução
    const example = await SolutionExample.findOne({ _id: exampleId, solutionId: id });
    if (!example) return res.status(404).json({ error: 'Exemplo não encontrado' });

    // Atualiza apenas os campos enviados
    if (typeof title === 'string') example.title = title;
    if (typeof description === 'string') example.description = description;
    if (typeof image === 'string') example.image = image;

    await example.save();
    return res.json({ ok: true, data: example });
  })
);


  app.post(
    '/api/solutions/:id/examples',
    [
      param('id').isMongoId().withMessage('id inválido'),
      body('title').isString().trim().notEmpty().withMessage('title é obrigatório'),
      body('description').optional().isString(),
      body('image').isString().trim().notEmpty().withMessage('image é obrigatória'),
    ],
    asyncH(async (req, res) => {
      const err = ensureValid(req, res); if (err) return err;
      const { id } = req.params;
      const { title, description = '', image } = req.body || {};
      const exists = await Solution.exists({ _id: id });
      if (!exists) return res.status(404).json({ error: 'Solução não encontrada' });
      const created = await SolutionExample.create({ solutionId: id, title, description, image });
      return res.json({ ok: true, data: created });
    })
  );

  app.delete(
    '/api/solutions/:id/examples/:exampleId',
    [param('id').isMongoId().withMessage('id inválido'), param('exampleId').isMongoId().withMessage('exampleId inválido')],
    asyncH(async (req, res) => {
      const err = ensureValid(req, res); if (err) return err;
      const { id, exampleId } = req.params;
      await SolutionExample.deleteOne({ _id: exampleId, solutionId: id });
      return res.json({ ok: true });
    })
  );

 



// ============================== “MAIS AMADOS” ================================
app.get(
  "/api/products/top-liked", 
  limiterAuth,
  requireAuth(["admin", "editor", "viewer"]),
  audit("products.topLiked"),
  asyncH(async (req, res) => {
    const items = await WaveledProduct.find({})
      .sort({ wl_likes: -1, wl_created_at: -1 })
      .limit(10);
    ok(res, items);
  })
);

// =============================== HEALTHCHECK =================================
app.get(
  "/health",
  asyncH(async (req, res) =>
    ok(res, { up: true, ts: new Date().toISOString() })
  )
);


app.get("/", asyncH(async (req, res) =>
    ok(res, { up: true, ts: new Date().toISOString() })
  )
); 


// ================================= ERRORS ====================================

app.use((errMiddleware, req, res, next) => {
  // log completo
  console.error(
    "Middleware erro:",
    errMiddleware && errMiddleware.stack ? errMiddleware.stack : errMiddleware
  );
  return errJson(res, errMiddleware?.message || "Erro interno", 500);
});

 
async function start() {
  try {
    // aumenta tolerância e força IPv4 primeiro
    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 20000, // 20s para escolher nó
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      // family: 4 // alternativa ao dns.setDefaultResultOrder
    });

    console.log("MongoDB ligado");

    app.listen(PORT, () => {
      console.log(`Waveled API (sessões) em http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error("Falha na ligação ao Mongo:", err?.message || err);
    process.exit(1);
  }
}

// logs úteis
mongoose.connection.on("error", (e) => {
  console.error("Mongo connection error:", e?.message || e);
});
mongoose.connection.on("disconnected", () => {
  console.warn("Mongo desconectado");
});

start();
// --- FIM --- 
