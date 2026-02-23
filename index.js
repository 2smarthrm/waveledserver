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
import cmsRoutes from "./routes/waveledCmsRoutes.js";
import cmsServicesRouter from "./routes/WaveledServices.js";
import dns from "dns";

const PHONE_PT = /^(\+?\d{2,3})?\s?\d{9,12}$/; 
dns.setDefaultResultOrder?.("ipv4first"); 
mongoose.set("bufferCommands", false); 
import { v2 as cloudinary } from "cloudinary";

 
cloudinary.config({
  cloud_name: "dcl5uszfj",
  api_key: "117256428392281",
  api_secret: "3u79ceHUqqCwIipkJRjYk0aUNjs",
});  


const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024, files: 12 },  
  fileFilter: (req, file, cb) => {
    if (/image\/(png|jpe?g|webp|gif|svg\+xml)/.test(file.mimetype)) cb(null, true);
    else cb(new Error("Tipo de ficheiro inválido"));
  },
});

 
 
 
 
const PORT =   4000;
const MONGO_URI =  "mongodb+srv://2smarthrm_db_user:afMz4WEnx9is1N3O@cluster0.7p7g2qd.mongodb.net/";
const SESSION_SECRET =  "478974ifhklfhnlf.jolçi49oipru98jioy89io57yth8ioeydhnmuilkgyh874iil5uej89poiu5rgejfdiklghnfmiujklyghnuijkghvnuiolvuyj";
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
  "http://localhost:5176",
  "https://waveledadmin.vercel.app",
  "https://adminwave.waveled.com",
  "https://waveled.com"
];
 
  
function resolveUploadDir() { 
  return  path.resolve("./uploads");
}

let UPLOAD_DIR = resolveUploadDir();
 
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
 
const ENC_KEY = Buffer.from(  "b8wXnR8j6r5w2KphF5sOeYlM5wqF7X2+VnZWQprP7Ks=",
  "base64"
);

if (ENC_KEY.length !== 32) {
  console.error("ENC_KEY_BASE64 inválida (requer 32 bytes Base64).");
  process.exit(1);
} 
  

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
    service: "Gmail",
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: "2smarthrm@gmail.com",
      pass: "bguvbniphmcnxdrl",
    },
  });
}
 
const app = express();
app.set("trust proxy", 1);
app.use(helmet({ crossOriginResourcePolicy: false }));

 
 
app.use(
  cors({
    origin: (origin, callback) => { 
      if (!origin) return callback(null, true);

      if (ALLOWED_ORIGINS.includes(origin)) {
        return callback(null, true);
      }

      console.warn(` CORS bloqueado para origem: ${origin}`);
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);

 


app.use(morgan("combined"));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" })); 
app.use(compression());


 
app.use("/uploads", express.static(path.resolve(UPLOAD_DIR)));
 

async function uploadFilesToCloudinary(files, folder = "waveled/images") {
  if (!files?.length) return [];

  const toUrl = (file) =>
    new Promise((resolve, reject) => { 
      if (file.size > 4 * 1024 * 1024) {
        return reject(new Error("Imagem excede 4MB"));
      }

      const stream = cloudinary.uploader.upload_stream(
        {
          folder,
          resource_type: "image", 
          transformation: [{ quality: "auto", fetch_format: "auto" }],
        },
        (err, result) => (err ? reject(err) : resolve(result.secure_url))
      );

      stream.end(file.buffer);
    });

  console.log("files = ", files.map(toUrl));
  return Promise.all(files.map(toUrl));  
}



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
  if (req.body) deepSanitize(req.body);
  if (req.params) deepSanitize(req.params);
  next();
});



const PRODUCTION = process.env.NODE_ENV === "production";
 

app.use(session({
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
    sameSite: PRODUCTION ? "none" : "lax", 
    secure: PRODUCTION,      
    maxAge: 1000 * 60 * 60 * 8*5,            
    path: "/",                             
  },
  rolling: true,                      
}));



const ok = (res, data, code = 200) => res.status(code).json({ ok: true, data });
const errJson = (res, message = "Erro", code = 400, issues = null) =>
  res.status(code).json({ ok: false, error: message, issues });

 
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
app.use("/api/cms", cmsRoutes);

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
 
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || "");
    cb(null, `${Date.now()}_${nanoid(8)}${ext}`);
  },
});
 
 
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
    wl_name_norm: { type: String, index: true, unique: true },  
    wl_order: { type: Number, default: 0, index: true },
    wl_created_at: { type: Date, default: Date.now },
  },
  { collection: "waveled_categories" }
);

 
CategorySchema.pre("save", function(next) {
  const norm = (s) =>
    String(s || "")
      .toLowerCase()
      .normalize("NFD").replace(/[\u0300-\u036f]/g, "") 
      .replace(/\s+/g, " ")
      .trim();
  this.wl_name = this.wl_name.replace(/\s+/g, " ").trim();
  this.wl_slug = this.wl_slug.toLowerCase().trim();
  this.wl_name_norm = norm(this.wl_name);
  next();
});

 
 
const ProductCategoryOrderSchema = new mongoose.Schema(
  {
    category: { type: mongoose.Schema.Types.ObjectId, ref: "WaveledCategory", index: true },
    order: { type: Number, default: 0, index: true },
  },
  { _id: false }
);
 

const ProductSchema = new Schema(
  {
    wl_name: { type: String, required: true },
    wl_category: {
      type: Schema.Types.ObjectId,
      ref: "WaveledCategory",
      required: true,
    },
    wl_categories: [{ type: Schema.Types.ObjectId, ref: "WaveledCategory", index: true }],
    wl_description_html: { type: String, default: "" },
    wl_specs_text: { type: String, default: "" },
    wl_datasheet_url: { type: String, default: "" },
    wl_manual_url: { type: String, default: "" },
    wl_sku: { type: String, unique: true, sparse: true },
    wl_order: { type: Number, default: 0, index: true }, 
    wl_category_orders: { type: [ProductCategoryOrderSchema], default: [] },
    wl_images: [{ type: String }],
    wl_featured_general: { type: Boolean, default: false },
    wl_likes: { type: Number, default: 0 },
    wl_created_at: { type: Date, default: Date.now },
    wl_updated_at: { type: Date, default: Date.now },
    wl_subcategories: [{ type: Schema.Types.ObjectId, ref: "WaveledSubCategory", index: true }],
  },
  { collection: "waveled_products"}
);

ProductSchema.index({ wl_subcategories: 1, wl_updated_at: -1 });
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
    wl_category: { type: Schema.Types.ObjectId, ref:"WaveledCategory"},
    wl_top10: [{ type: Schema.Types.ObjectId, ref:"WaveledProduct"}],
    wl_top3: [{ type: Schema.Types.ObjectId, ref:"WaveledProduct"}],
    wl_best: { type: Schema.Types.ObjectId, ref:"WaveledProduct"},
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

 
const validate = (req, res, next) => {
  const v = validationResult(req);
  if (!v.isEmpty()) { 
    console.warn("Validation errors:", v.array());
    return errJson(res, "Validação falhou", 422, v.array());
  } 
  next();
};

const ensureCategory = async (nameOrId) => {
  if (!nameOrId) throw new Error("Categoria inválida"); 
  if (mongoose.isValidObjectId(nameOrId)) {
    const byId = await WaveledCategory.findById(nameOrId);
    if (!byId) throw new Error("Categoria não encontrada");
    return byId;
  }
 
  const raw = String(nameOrId);
  const name = raw.replace(/\s+/g, " ").trim(); 
  const slug = makeSlug(name);
 
  try {
    const doc = await WaveledCategory.findOneAndUpdate(
      { $or: [{ wl_slug: slug }, { wl_name: name }] },
      { $setOnInsert: { wl_name: name, wl_slug: slug, wl_created_at: new Date() } },
      { new: true, upsert: true }
    );
    return doc;
  } catch (e) { 
    if (e && e.code === 11000) { 
      const again = await WaveledCategory.findOne({ $or: [{ wl_slug: slug }, { wl_name: name }] });
      if (again) return again;
    }
    throw e;
  }
};



 
 
app.post("/api/auth/login",
  limiterLogin,
  body("email").isEmail(),
  body("password").isString().isLength({min:6}),
  validate,
  audit("auth.login"),
  asyncH(async (req, res) => {
    const { email, password } = req.body;
    const user = await WaveledUser.findOne({ wl_email: email, wl_active: true });
    if (!user) return errJson(res, "Credenciais inválidas", 401);

    const okPass = await bcrypt.compare(password, user.wl_password_hash);
    if (!okPass) return errJson(res, "Credenciais inválidas", 401);

    req.session.regenerate((err) => {
      if (err) {
        console.error("session.regenerate error:", err);
        return errJson(res, "Erro de sessão", 500);
      }
      req.session.user = {
        id: String(user._id),
        email: user.wl_email,
        role: user.wl_role,
        name: user.wl_name,
      };
      req.session.save((err2) => {
        if (err2) {
          console.error("session.save error:", err2);
          return errJson(res, "Erro de sessão", 500);
        }
        ok(res, { authenticated: true, role: user.wl_role, name: user.wl_name });
      });
    });
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


app.get("/api/me", (req, res) => {
  if (!req.session.user) return res.status(200).json({ ok: true, data: { authenticated: false } });
  return res.status(200).json({ ok: true, data: { authenticated: true, user: req.session.user } });
});

  
app.post(
  "/api/public/contact", 
  body("tipo")
    .isIn(["info", "quote"])
    .withMessage("Tipo inválido.")
    .bail(),
 
  body("nome").isString().isLength({ min: 2 }).trim().escape()
    .withMessage("Nome obrigatório."),
  body("telefone").isString().isLength({ min: 6 }).trim().escape()
    .withMessage("Telefone inválido."),
  body("email").isEmail().normalizeEmail()
    .withMessage("Email inválido."),
  body("mensagem").isString().isLength({ min: 5 })
    .withMessage("Mensagem muito curta."),
 
  body("consent")
    .customSanitizer((v) => {
      if (v === true || v === "true" || v === 1 || v === "1") return true;
      return false;
    })
    .isBoolean()
    .custom((v) => v === true)
    .withMessage("É necessário consentimento."),
 
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



 
 
const INTERNAL_RECIPIENTS = [ 
  {email:"fabio.catela@exportech.com.pt", name:"Fábio"}
];

 
function getSaudacaoPt(date = new Date()) {
  const h = date.getHours();
  if (h >= 6 && h < 12) return "Bom dia";
  if (h >= 12 && h < 20) return "Boa tarde";
  return "Boa noite";
}

 
function formatDateTimePt(date = new Date()) {
  const datePart = new Intl.DateTimeFormat("pt-PT", {
    day: "2-digit",
    month: "long",
    year: "numeric",
  }).format(date);

  const timePart = new Intl.DateTimeFormat("pt-PT", {
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);

  return `${datePart} às ${timePart}`;
}

 
function buildProjectRequestHtml(payload, destinatarioNome) {
  const saudacao = getSaudacaoPt();
  const dataStr = formatDateTimePt();

  const {
    nome,
    email,
    telefone,
    descricao,
    produtoNome,
    produtoCategoria,
    produtoImagem,
    produtoUrl,
  } = payload;

  return `
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office" lang="pt">
<head>
<title>Solicitação de projeto - Waveled</title>
<meta charset="UTF-8" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta http-equiv="X-UA-Compatible" content="IE=edge" />
<meta name="x-apple-disable-message-reformatting" content="" />
<meta content="target-densitydpi=device-dpi" name="viewport" />
<meta content="true" name="HandheldFriendly" />
<meta content="width=device-width" name="viewport" />
<meta name="format-detection" content="telephone=no, date=no, address=no, email=no, url=no" />
<style type="text/css">
table {
border-collapse: separate;
table-layout: fixed;
mso-table-lspace: 0pt;
mso-table-rspace: 0pt
}
table td {
border-collapse: collapse
}
.ExternalClass {
width: 100%
}
.ExternalClass,
.ExternalClass p,
.ExternalClass span,
.ExternalClass font,
.ExternalClass td,
.ExternalClass div {
line-height: 100%
}
body, a, li, p, h1, h2, h3 {
-ms-text-size-adjust: 100%;
-webkit-text-size-adjust: 100%;
}
html {
-webkit-text-size-adjust: none !important
}
body {
min-width: 100%;
Margin: 0px;
padding: 0px;
}
body, #innerTable {
-webkit-font-smoothing: antialiased;
-moz-osx-font-smoothing: grayscale
}
#innerTable img+div {
display: none;
display: none !important
}
img {
Margin: 0;
padding: 0;
-ms-interpolation-mode: bicubic
}
h1, h2, h3, p, a {
line-height: inherit;
overflow-wrap: normal;
white-space: normal;
word-break: break-word
}
a {
text-decoration: none
}
h1, h2, h3, p {
min-width: 100%!important;
width: 100%!important;
max-width: 100%!important;
display: inline-block!important;
border: 0;
padding: 0;
margin: 0
}
a[x-apple-data-detectors] {
color: inherit !important;
text-decoration: none !important;
font-size: inherit !important;
font-family: inherit !important;
font-weight: inherit !important;
line-height: inherit !important
}
u + #body a {
color: inherit;
text-decoration: none;
font-size: inherit;
font-family: inherit;
font-weight: inherit;
line-height: inherit;
}
a[href^="mailto"],
a[href^="tel"],
a[href^="sms"] {
color: inherit;
text-decoration: none
}
</style>
<style type="text/css">
@media (min-width: 481px) {
.hd { display: none!important }
}
</style>
<style type="text/css">
@media (max-width: 480px) {
.hm { display: none!important }
}
</style>
<style type="text/css">
@media (max-width: 480px) {
.t123{mso-line-height-alt:0px!important;line-height:0!important;display:none!important}.t124{padding-left:30px!important;padding-bottom:40px!important;padding-right:30px!important}.t28{padding-bottom:20px!important}.t27{line-height:28px!important;font-size:26px!important;letter-spacing:-1.04px!important}.t138{padding:40px 30px!important}.t72{text-align:left!important}.t12,.t55{display:revert!important}.t113,.t115,.t116{display:block!important}.t57{vertical-align:middle!important;width:211px!important}.t14,.t18{vertical-align:top!important}.t19{text-align:right!important}.t18{width:80px!important}.t16{padding-bottom:50px!important}.t14{width:380px!important}.t50{width:353px!important}.t71{vertical-align:middle!important;width:800px!important}.t59,.t65{padding-left:0!important}.t115{text-align:left!important}.t113{mso-line-height-alt:15px!important;line-height:15px!important}.t114{vertical-align:top!important;display:inline-block!important;width:100%!important;max-width:800px!important}.t111{padding-bottom:15px!important;padding-right:0!important}
}
</style>
<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700;800&amp;family=Albert+Sans:wght@500&amp;display=swap" rel="stylesheet" type="text/css" />
</head>
<body id="body" class="t144" style="min-width:100%;Margin:0px;padding:0px;background-color:#242424;">
<div class="t143" style="background-color:#242424;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" align="center">
<tr>
<td class="t142" style="font-size:0;line-height:0;mso-line-height-rule:exactly;background-color:#242424;" valign="top" align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" align="center" id="innerTable">
<tr><td><div class="t123" style="mso-line-height-rule:exactly;mso-line-height-alt:45px;line-height:45px;font-size:1px;display:block;">&nbsp;&nbsp;</div></td></tr>
<tr><td align="center">
<table class="t127" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
<tr><td width="600" class="t126" style="width:600px;">
<table class="t125" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="width:100%;">
<tr><td class="t124" style="background-color:#F8F8F8;padding:0 50px 60px 50px;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100% !important;">
<tr><td align="center">
<table class="t26" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
<tr><td width="500" class="t25" style="width:800px;">
<table class="t24" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="width:100%;">
<tr><td class="t23">
<div class="t22" style="width:100%;text-align:right;">
  <div class="t21" style="display:inline-block;">
    <table class="t20" role="presentation" cellpadding="0" cellspacing="0" align="right" valign="top">
      <tr class="t19"><td></td>
        <td class="t14" width="372.6" valign="top">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" class="t13" style="width:100%;">
            <tr><td class="t11" style="padding:35px 0 0 0;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100% !important;">
                <tr><td align="center">
                  <table class="t5" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
                    <tr><td width="362.6" class="t4" style="width:600px;">
                      <table class="t3" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="width:100%;">
                        <tr><td class="t2">
                          <p class="t1" style="margin:0;font-family:Roboto,BlinkMacSystemFont,Segoe UI,Helvetica Neue,Arial,sans-serif;line-height:22px;font-weight:400;font-size:16px;color:#333333;text-align:left;mso-line-height-rule:exactly;">
                            <span class="t0" style="font-weight:bold;">Solicitação de projeto - Waveled</span>
                          </p>
                        </td></tr>
                      </table>
                    </td></tr>
                  </table>
                </td></tr>
                <tr><td align="center">
                  <table class="t10" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
                    <tr><td width="362.6" class="t9" style="width:600px;">
                      <table class="t8" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="width:100%;">
                        <tr><td class="t7" style="padding:0 0 22px 0;">
                          <p class="t6" style="margin:0;font-family:Roboto,BlinkMacSystemFont,Segoe UI,Helvetica Neue,Arial,sans-serif;line-height:22px;font-weight:400;font-size:16px;color:#333333;text-align:left;mso-line-height-rule:exactly;">
                            Data: ${dataStr}
                          </p>
                        </td></tr>
                      </table>
                    </td></tr>
                  </table>
                </td></tr>
              </table>
            </td><td class="t12" style="width:10px;" width="10"></td></tr>
          </table>
        </td>
        <td class="t18" width="127.4" valign="top">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" class="t17" style="width:100%;">
            <tr><td class="t16" style="padding:0 0 60px 0;">
              <a href="${produtoUrl}" target="_blank">
                <div style="font-size:0px;">
                   <img class="t15" style="display:block;border:0;height:auto;width:100%;Margin:0;max-width:100%;" width="127" height="124" alt="Waveled" src="https://2d92baa0-eadf-4893-bec4-7a2b3fe14f31.b-cdn.net/e/e13b809b-5faa-4dcd-a6b7-a74ec6d3204b/0d487b61-1bae-4a60-8379-ce77291900f7.png"/>
                </div>
              </a>
            </td></tr>
          </table>
        </td>
        <td></td></tr>
    </table>
  </div>
</div>
</td></tr></table>
</td></tr></table>
</td></tr>

<tr><td align="center">
<table class="t31" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
<tr><td width="500" class="t30" style="width:600px;">
<table class="t29" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="width:100%;">
<tr><td class="t28" style="padding:0 0 15px 0;">
  <h1 class="t27" style="margin:0;font-family:Roboto,BlinkMacSystemFont,Segoe UI,Helvetica Neue,Arial,sans-serif;line-height:26px;font-weight:400;font-size:24px;color:#333333;text-align:left;mso-line-height-rule:exactly;">
    ${saudacao} ${destinatarioNome},
  </h1>
</td></tr>
</table>
</td></tr></table>
</td></tr>

<tr><td align="center">
<table class="t36" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
<tr><td width="500" class="t35" style="width:600px;">
<table class="t34" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="width:100%;">
<tr><td class="t33" style="padding:0 0 22px 0;">
  <p class="t32" style="margin:0;font-family:Roboto,BlinkMacSystemFont,Segoe UI,Helvetica Neue,Arial,sans-serif;line-height:22px;font-size:16px;color:#333333;text-align:left;mso-line-height-rule:exactly;">
     ${descricao}
  </p>
</td></tr>
</table>
</td></tr></table>
</td></tr>

<!-- Aqui poderias pôr mais texto se quiseres -->

<tr><td align="left">
<table class="t51" role="presentation" cellpadding="0" cellspacing="0" style="Margin-right:auto;">
<tr><td width="279" class="t50" style="width:279px;">
<table class="t49" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="width:100%;">
<tr><td class="t48" style="background-color:#f3f3f3;text-align:center;line-height:24px;mso-line-height-rule:exactly;padding:10px;">
  ${
    produtoUrl
      ? `<a href="${produtoUrl}" style="display:block;font-family:Roboto,Arial,sans-serif;font-size:14px;font-weight:700;color:#333333;text-decoration:none;">
           Ver produto no site da Waveled
         </a>`
      : `<span style="display:block;font-family:Roboto,Arial,sans-serif;font-size:14px;font-weight:700;color:#333333;">
           Link do produto não disponível
         </span>`
  }
</td></tr>
</table>
</td></tr></table>
</td></tr>

<tr><td><div class="t52" style="mso-line-height-rule:exactly;mso-line-height-alt:40px;line-height:40px;font-size:1px;display:block;">&nbsp;&nbsp;</div></td></tr>

<!-- BLOCO PRODUTO -->
<tr><td align="center">
<table class="t79" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
<tr><td width="500" class="t78" style="width:800px;">
<table class="t77" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="width:100%;">
<tr><td class="t76" style="background-color:#F0F0F0;padding:20px;">
<div class="t75" style="width:100%;text-align:left;">
  <div class="t74" style="display:inline-block;">
    <table class="t73" role="presentation" cellpadding="0" cellspacing="0" align="left" valign="middle">
      <tr class="t72"><td></td>
        <td class="t57" width="100.4" valign="middle">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" class="t56" style="width:100%;">
            <tr>
              <td class="t54">
                <div style="font-size:0px;">
                  ${
                    produtoImagem
                      ? `<img class="t53" style="display:block;border:0;height:auto;width:100%;Margin:0;max-width:100%;" width="90" alt="Imagem do produto" src="${produtoImagem}" />`
                      : `<div style="width:90px;height:90px;border:1px solid #ccc;background:#fafafa;font-size:11px;color:#777;display:flex;align-items:center;justify-content:center;">Sem imagem</div>`
                  }
                </div>
              </td>
              <td class="t55" style="width:10px;" width="10"></td>
            </tr>
          </table>
        </td>
        <td class="t71" width="359.6" valign="middle">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" class="t70" style="width:100%;">
            <tr><td class="t69">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100% !important;">
                <tr><td align="center">
                  <table class="t62" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
                    <tr><td width="359.6" class="t61" style="width:600px;">
                      <table class="t60" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="width:100%;">
                        <tr><td class="t59" style="padding:0 0 0 10px;">
                          <h1 class="t58" style="margin:0;font-family:Roboto,Arial,sans-serif;line-height:16px;font-weight:700;font-size:14px;text-transform:uppercase;color:#1A1A1A;text-align:left;">
                            ${produtoNome || "Nome do produto não especificado"}
                          </h1>
                        </td></tr>
                      </table>
                    </td></tr>
                  </table>
                </td></tr>
                <tr><td><div class="t63" style="mso-line-height-rule:exactly;mso-line-height-alt:10px;line-height:10px;font-size:1px;display:block;">&nbsp;&nbsp;</div></td></tr>
                
              </table>
            </td></tr>
          </table>
        </td>
        <td></td></tr>
    </table>
  </div>
</div>
</td></tr></table>
</td></tr></table>
</td></tr>

<tr><td><div class="t80" style="mso-line-height-rule:exactly;mso-line-height-alt:30px;line-height:30px;font-size:1px;display:block;">&nbsp;&nbsp;</div></td></tr>

<!-- DETALHES DO CLIENTE -->
<tr><td align="center">
<table class="t122" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
<tr><td width="500" class="t121" style="width:600px;">
<table class="t120" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="width:100%;">
<tr><td class="t119" style="background-color:#F0F0F0;padding:40px;">
<div class="t118" style="width:100%;text-align:left;">
  <div class="t117" style="display:inline-block;">
    <table class="t116" role="presentation" cellpadding="0" cellspacing="0" align="left" valign="top">
      <tr class="t115"><td></td>
        <td class="t114" width="420" valign="top">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" class="t112" style="width:100%;">
            <tr><td class="t111" style="padding:0 5px 0 0;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100% !important;">
                <tr><td align="center">
                  <table class="t110" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
                    <tr><td width="415" class="t109" style="width:800px;">
                      <table class="t108" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="width:100%;">
                        <tr><td class="t107">
                          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100% !important;">
                            <tr><td align="center">
                              <table class="t85" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
                                <tr><td width="415" class="t84" style="width:600px;">
                                  <table class="t83" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="width:100%;">
                                    <tr><td class="t82">
                                      <h1 class="t81" style="margin:0;font-family:Roboto,Arial,sans-serif;line-height:16px;font-weight:700;font-size:14px;text-transform:uppercase;color:#1A1A1A;text-align:left;">
                                        Detalhes do cliente
                                      </h1>
                                    </td></tr>
                                  </table>
                                </td></tr>
                              </table>
                            </td></tr>
                            <tr><td><div class="t86" style="mso-line-height-rule:exactly;mso-line-height-alt:10px;line-height:10px;font-size:1px;display:block;">&nbsp;&nbsp;</div></td></tr>
                            <tr><td align="center">
                              <table class="t91" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
                                <tr><td width="415" class="t90" style="width:600px;">
                                  <table class="t89" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="width:100%;">
                                    <tr><td class="t88">
                                      <p class="t87" style="margin:0;font-family:'Albert Sans',Arial,sans-serif;line-height:22px;font-weight:500;font-size:12px;color:#242424;text-align:left;mso-line-height-rule:exactly;">
                                        <strong>Nome:</strong> ${nome}
                                      </p>
                                    </td></tr>
                                  </table>
                                </td></tr>
                              </table>
                            </td></tr>
                            <tr><td align="center">
                              <table class="t96" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
                                <tr><td width="415" class="t95" style="width:600px;">
                                  <table class="t94" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="width:100%;">
                                    <tr><td class="t93">
                                      <p class="t92" style="margin:0;font-family:'Albert Sans',Arial,sans-serif;line-height:22px;font-weight:500;font-size:12px;color:#242424;text-align:left;">
                                        <strong>Email:</strong> ${email}
                                      </p>
                                    </td></tr>
                                  </table>
                                </td></tr>
                              </table>
                            </td></tr>
                            <tr><td align="center">
                              <table class="t101" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
                                <tr><td width="415" class="t100" style="width:600px;">
                                  <table class="t99" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="width:100%;">
                                    <tr><td class="t98">
                                      <p class="t97" style="margin:0;font-family:'Albert Sans',Arial,sans-serif;line-height:22px;font-weight:500;font-size:12px;color:#242424;text-align:left;">
                                        <strong>Telefone:</strong> ${telefone}
                                      </p>
                                    </td></tr>
                                  </table>
                                </td></tr>
                              </table>
                            </td></tr>
                            <tr><td align="center"> 
                                </td></tr>
                              </table>
                            </td></tr>
                          </table>
                        </td></tr>
                      </table>
                    </td></tr>
                  </table>
                </td></tr>
              </table>
            </td></tr>
          </table>
        </td>
        <td></td></tr>
    </table>
  </div>
</div>
</td></tr></table>
</td></tr></table>
</td></tr>

<tr><td align="center">
<table class="t141" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
<tr><td width="600" class="t140" style="width:600px;">
<table class="t139" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="width:100%;">
<tr><td class="t138" style="background-color:#242424;padding:48px 50px;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100% !important;">
<tr><td align="center">
  <table class="t132" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
    <tr><td width="500" class="t131" style="width:600px;">
      <table class="t130" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="width:100%;">
        <tr><td class="t129">
          <p class="t128" style="margin:0;font-family:Roboto,Arial,sans-serif;line-height:22px;font-weight:800;font-size:18px;letter-spacing:-0.9px;color:#757575;text-align:left;">
            Waveled é uma empresa inovadora especializada em soluções display LED, unindo eficiência, qualidade e design moderno.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</td></tr>
<tr><td align="center">
  <table class="t137" role="presentation" cellpadding="0" cellspacing="0" style="Margin-left:auto;Margin-right:auto;">
    <tr><td width="500" class="t136" style="width:600px;">
      <table class="t135" role="presentation" cellpadding="0" cellspacing="0" width="100%" style="width:100%;">
        <tr><td class="t134">
          <p class="t133" style="margin:0;font-family:Roboto,Arial,sans-serif;line-height:22px;font-size:12px;color:#888888;text-align:left;">
            Saiba mais em: <a href="https://waveled.com" style="color:#888888;text-decoration:none;">www.waveled.com</a>
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</td></tr>
</table>
</td></tr></table>
</td></tr></table>
</td></tr></table>
</div>
</body>
</html>
`;
}

 


 app.post(
  "/api/public/project-request",
  limiterPublicPost,
  body("_hp").optional().isString().isLength({ max: 0 }).withMessage("honeypot not empty"),
  body("nome").isString().isLength({ min: 2, max: 120 }).trim(),
  body("email").isEmail().normalizeEmail(),
  body("telefone").isString().isLength({ min: 5, max: 40 }).trim(),
  body("descricao").isString().isLength({ min: 5, max: 1500 }).trim(),
  body("produtoId").optional().isString().trim(),
  body("produtoNome").optional().isString().trim(),
  body("produtoCategoria").optional().isString().trim(),
  body("produtoImagem").optional().isString().trim(),
  body("produtoUrl").optional().isString().trim(),
  body("origem").optional().isString().isLength({ max: 120 }).trim(),
  body("page").optional().isString().isLength({ max: 2048 }),
  body("utm").optional().isObject(), 
  audit("public.project_request"),
  asyncH(async (req, res) => { 
    if (req.body._hp !== undefined) return ok(res, { received: true });

    const now = new Date();
 
    let produtoImagem = req.body.produtoImagem || "";
    function isHttpUrl(e) {
      return e.startsWith("https");
    }
 
    if (produtoImagem && !isHttpUrl(produtoImagem)) {
      try { 
        const filename = produtoImagem.replace(/^\/?uploads\/?/, "");
        const filePath = path.resolve(UPLOAD_DIR, filename);
 
        const buffer = await fs.readFile(filePath);
 
        const fakeFile = {
          buffer,
          size: buffer.length,
        };
 
        const [cloudUrl] = await uploadFilesToCloudinary(
          [fakeFile],
          "waveled/images" 
        );

        if (cloudUrl) {
          produtoImagem = cloudUrl; 
        }
      } catch (err) {
        console.error("Erro ao subir imagem do produto para Cloudinary:", err); 
      }
    }

    const payload = {
      tipo: "project-request",
      nome: req.body.nome,
      email: req.body.email,
      telefone: req.body.telefone,
      descricao: req.body.descricao,
      produtoId: req.body.produtoId || "",
      produtoNome: req.body.produtoNome || "",
      produtoCategoria: req.body.produtoCategoria || "",
      produtoImagem,  
      produtoUrl: req.body.produtoUrl || "",
      origem: req.body.origem || "modal-orcamento",
      requestedAt: now.toISOString(),
      meta: {
        ip: req.ip,
        ua: req.get("user-agent") || "",
        referer: req.get("referer") || "",
        page: req.body.page || "",
        utm: req.body.utm || null,
      },
    };
 
    const blob = encrypt(payload);
    await WaveledMessage.create({
      wl_encrypted_blob: blob,
      wl_source: "public_form",
    });
 
    try {
      await Promise.all(
        INTERNAL_RECIPIENTS.map(async (dest) => {
          const html = buildProjectRequestHtml(payload, dest.name);

        const result =   await transporter.sendMail({
            from: '"Waveled" <no-reply@waveled.pt>',
            to: dest.email,
            subject: `Waveled • Nova solicitação de projeto de ${payload.nome}`,
            html,
          });
 
          console.log(result); 

        })
      );
    } catch (e) {
      console.error("Email de solicitação de projeto falhou:", e); 
    }

    return res.status(200).json({
      ok: true,
      message: "Solicitação de projeto recebida com sucesso.",
    });
  })
);

 



 

app.post(
  "/api/public/contact",
  limiterPublicPost, 
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
  body("utm").optional().isObject(),
  body("page").optional().isString().isLength({ max: 2048 }),
  validate,
  audit("public.contact"),
  asyncH(async (req, res) => { 
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
 
    return res.status(200).json({ ok: true, message: "Pedido recebido com sucesso." });
  })
);

async function ensureCategories(maybeList) {
  const raw = Array.isArray(maybeList)
    ? maybeList
    : typeof maybeList === "string"
      ? maybeList.split(",").map(s => s.trim()).filter(Boolean)
      : [];

  const out = [];
  for (const v of raw) {
    const c = await ensureCategory(v);  
    if (c) out.push(c);
  } 
  const seen = new Set();
  return out.filter(c => {
    const id = String(c._id);
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}
 
 
async function resolveCategoryForQuery(nameOrId) {
  if (!nameOrId) return null; 
  if (mongoose.isValidObjectId(nameOrId)) {
    return await WaveledCategory.findById(nameOrId).lean();
  }

  const raw = String(nameOrId).trim();
  if (!raw) return null;

 
  const bySlug = await WaveledCategory.findOne({ wl_slug: raw.toLowerCase() }).lean();
  if (bySlug) return bySlug;

 
  const norm = raw
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\s+/g, " ")
    .trim();

  const byNorm = await WaveledCategory.findOne({ wl_name_norm: norm }).lean();
  if (byNorm) return byNorm;
 
  const byName = await WaveledCategory.findOne({ wl_name: raw }).lean();
  return byName || null;
}

 
function isObjId(v) {
  return mongoose.isValidObjectId(String(v || ""));
}

app.get(
  "/api/products",
  asyncH(async (req, res) => {
    const { q, category, order, subcategory } = req.query;
    const find = {};

    if (q && String(q).trim()) {
      find.wl_name = { $regex: String(q).trim(), $options: "i" };
    }

 
    let catDoc = null;
    if (category) {
      catDoc = await resolveCategoryForQuery(category);
      if (!catDoc) return errJson(res, "Categoria não encontrada.", 404);

      find.$or = [
        { wl_categories: { $elemMatch: { $eq: catDoc._id } } },
        { wl_category: catDoc._id },
      ];
    }
 
    if (subcategory) {
      if (!isObjId(subcategory)) return errJson(res, "subcategory inválida.", 422);
      find.wl_subcategories = { $elemMatch: { $eq: new mongoose.Types.ObjectId(subcategory) } };
    }

    const wantsUpdated = String(order || "").toLowerCase() === "updated";

 
    async function fetchSubcatsForCategoryIds(catObjectIds) {
      if (!Array.isArray(catObjectIds) || !catObjectIds.length) return [];

      return WaveledSubCategory.find({
        wl_categories: { $in: catObjectIds },
      })
        .select("_id wl_name wl_slug wl_categories")
        .lean();
    }
 
    async function attachSubcatsIntoCategoryObjects(items, forceCatDoc = null) {
      const arr = Array.isArray(items) ? items : [];
      const catIdsSet = new Set();
 
      if (forceCatDoc?._id) catIdsSet.add(String(forceCatDoc._id));

      arr.forEach((p) => {
        if (p?.wl_category?._id) catIdsSet.add(String(p.wl_category._id));
        if (Array.isArray(p?.wl_categories)) {
          p.wl_categories.forEach((c) => c?._id && catIdsSet.add(String(c._id)));
        }
      });

      const catIds = Array.from(catIdsSet);
      if (!catIds.length) return arr;
 
      const catObjectIds = catIds.map((id) => new mongoose.Types.ObjectId(id));

      const subs = await fetchSubcatsForCategoryIds(catObjectIds);

       
      const subMap = new Map();
      subs.forEach((s) => {
        const cats = Array.isArray(s.wl_categories) ? s.wl_categories : [];
        cats.forEach((cid) => {
          const key = String(cid);
          if (!subMap.has(key)) subMap.set(key, []);
          subMap.get(key).push({
            _id: s._id,
            wl_name: s.wl_name,
            wl_slug: s.wl_slug,
          });
        });
      });
 
      const injected = arr.map((p) => {
        const next = { ...p };

        if (next?.wl_category?._id) {
          const id = String(next.wl_category._id);
          next.wl_category = {
            ...next.wl_category,
            subcategories: subMap.get(id) || [],
          };
        }

        if (Array.isArray(next?.wl_categories)) {
          next.wl_categories = next.wl_categories.map((c) => {
            if (!c?._id) return c;
            const id = String(c._id);
            return { ...c, subcategories: subMap.get(id) || [] };
          });
        }

        return next;
      });

  
      const categoryMeta = forceCatDoc?._id
        ? {
            _id: forceCatDoc._id,
            wl_name: forceCatDoc.wl_name,
            wl_slug: forceCatDoc.wl_slug,
            wl_order: forceCatDoc.wl_order,
            subcategories: subMap.get(String(forceCatDoc._id)) || [],
          }
        : null;

      return { injected, categoryMeta };
    }

 
    let query = WaveledProduct.find(find)
      .populate({ path: "wl_categories", select: "_id wl_name wl_slug wl_order" })
      .populate({ path: "wl_category", select: "_id wl_name wl_slug wl_order" });

 
    if (!wantsUpdated) {
      if (catDoc?._id) {
        const itemsRaw = await query.lean();

        const catIdStr = String(catDoc._id);
        const withOrder = itemsRaw.map((p) => {
          const entry = (p.wl_category_orders || []).find(
            (x) => String(x.category) === catIdStr
          );
          return {
            ...p,
            __order: typeof entry?.order === "number" ? entry.order : 0,
          };
        });

        withOrder.sort((a, b) => {
          if (a.__order !== b.__order) return a.__order - b.__order;
          const au = a.wl_updated_at ? new Date(a.wl_updated_at).getTime() : 0;
          const bu = b.wl_updated_at ? new Date(b.wl_updated_at).getTime() : 0;
          if (bu !== au) return bu - au;
          return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
        });

        const { injected, categoryMeta } = await attachSubcatsIntoCategoryObjects(withOrder, catDoc);

        return res.status(200).json({
          data: injected.map(({ __order, ...p }) => p),
          category: categoryMeta,  
        });
      }

      const itemsRaw = await query
        .sort({ wl_order: 1, wl_updated_at: -1, createdAt: -1 })
        .lean();

      const { injected } = await attachSubcatsIntoCategoryObjects(itemsRaw, null);
      return res.status(200).json({ data: injected });
    }
 
    const itemsRaw = await query.sort({ wl_updated_at: -1, createdAt: -1 }).lean();

    if (catDoc?._id) {
      const { injected, categoryMeta } = await attachSubcatsIntoCategoryObjects(itemsRaw, catDoc);
      return res.status(200).json({ data: injected, category: categoryMeta });
    }

    const { injected } = await attachSubcatsIntoCategoryObjects(itemsRaw, null);
    return res.status(200).json({ data: injected });
  })
);

 
app.post(
  "/api/products",
  requireAuth(["admin", "editor"]),
  upload.array("images", 12),
  body("name").isString().isLength({ min: 2 }).trim(),
  body("category").optional().isString().isLength({ min: 1 }).trim(),
  body("categories").optional(),
 
  body("subcategories").optional(),

  body("description_html").optional().isString(),
  body("specs_text").optional().isString(),
  body("datasheet_url").optional({ checkFalsy: true }).isURL().isLength({ max: 2048 }),
  body("manual_url").optional({ checkFalsy: true }).isURL().isLength({ max: 2048 }),
  body("sku").optional().isString().isLength({ max: 64 }),
  body("link")
    .optional({ checkFalsy: true })
    .custom((v) => {
      if (typeof v !== "string") return false;
      const s = v.trim();
      return /^https?:\/\//i.test(s) || s.startsWith("/");
    })
    .withMessage('O "link" deve ser uma URL (http/https) ou um caminho relativo a começar por "/".')
    .isLength({ max: 2048 }),
  validate,
  audit("products.create"),
  asyncH(async (req, res) => {
    const images = await uploadFilesToCloudinary(req.files || []);

 
    const resolvedArray = await ensureCategories(req.body.categories);

 
    let principal = null;
    if (req.body.category) {
      principal = await ensureCategory(req.body.category);
      if (principal && !resolvedArray.find((c) => String(c._id) === String(principal._id))) {
        resolvedArray.unshift(principal);
      }
    }

 
    let subIds = [];
    try {
      subIds = await ensureSubCategories(req.body.subcategories);
    } catch (e) {
      return errJson(res, e.message || "Subcategorias inválidas", 422);
    }

    const p = await WaveledProduct.create({
      wl_name: req.body.name,

      wl_category: principal ? principal._id : (resolvedArray[0]?._id || undefined),
      wl_categories: resolvedArray.map((c) => c._id), 
      wl_subcategories: subIds,

      wl_description_html: req.body.description_html || "",
      wl_specs_text: req.body.specs_text || "",
      wl_datasheet_url: req.body.datasheet_url || "",
      wl_manual_url: req.body.manual_url || "",
      wl_sku: req.body.sku || undefined,
      wl_images: images,

      wl_link: (req.body.link || "").trim(),
      wl_updated_at: new Date(),
    });

    ok(res, { id: p._id }, 201);
  })
);

 
app.put(
  "/api/products/reorder",
  requireAuth(["admin", "editor"]),
  body("orderedIds").isArray({ min: 1 }),
  body("orderedIds.*").isMongoId(),
  body("category").optional().isString().trim(),
  validate,
  audit("products.reorder"),
  asyncH(async (req, res) => {
    const { orderedIds, category } = req.body;

    const ids = orderedIds.map(String);
    const unique = Array.from(new Set(ids));
    if (unique.length !== ids.length) return errJson(res, "IDs duplicados na lista.", 400);

    let catDoc = null;
    if (category) {
      catDoc = await ensureCategory(category);
      if (!catDoc) return errJson(res, "Categoria inválida.", 400);
    }
 
    const ops = unique.map((id, idx) => {
      if (!catDoc) {
        return {
          updateOne: {
            filter: { _id: id },
            update: { $set: { wl_order: idx, wl_updated_at: new Date() } },
          },
        };
      }
 
      return {
        updateOne: {
          filter: { _id: id },
          update: [
            {
              $set: {
                wl_category_orders: {
                  $let: {
                    vars: {
                      existing: { $ifNull: ["$wl_category_orders", []] },
                    },
                    in: {
                      $concatArrays: [ 
                        {
                          $filter: {
                            input: "$$existing",
                            as: "e",
                            cond: { $ne: ["$$e.category", catDoc._id] },
                          },
                        }, 
                        [{ category: catDoc._id, order: idx }],
                      ],
                    },
                  },
                },
                wl_updated_at: new Date(),
              },
            },
          ],
        },
      };
    });

    await WaveledProduct.bulkWrite(ops, { ordered: false });

    ok(res, {
      updated: true,
      scope: catDoc ? "category" : "global",
      category: catDoc?._id || null,
    });
  })
);


app.use("/api/cms", cmsServicesRouter);



function normalizeArrayInput(v) {
  if (v === undefined || v === null) return [];
  if (Array.isArray(v)) return v.flat();
  if (typeof v === "string") {
    if (v.includes(",")) return v.split(",").map((x) => x.trim()).filter(Boolean);
    return [v.trim()].filter(Boolean);
  }
  return [];
}

async function ensureSubCategories(input) {
  const ids = normalizeArrayInput(input).filter((x) => mongoose.isValidObjectId(x));
  if (!ids.length) return [];

  const rows = await WaveledSubCategory.find({ _id: { $in: ids } })
    .select("_id")
    .lean();

  if (rows.length !== ids.length) {
    throw new Error("Uma ou mais subcategorias não existem");
  }
  return rows.map((r) => r._id);
}
 
  

app.put("/api/products/:id",
  requireAuth(["admin", "editor"]),
  upload.array("images", 12),
  param("id").isMongoId(), 
  body("subcategories").optional(),
  body("link")
    .optional({ checkFalsy: true })
    .custom((v) => {
      if (typeof v !== "string") return false;
      const s = v.trim();
      return /^https?:\/\//i.test(s) || s.startsWith("/");
    })
    .withMessage('O "link" deve ser uma URL (http/https) ou um caminho relativo a começar por "/".')
    .isLength({ max: 2048 }),
  validate,
  audit("products.update"),
  asyncH(async (req, res) => {
    const p = await WaveledProduct.findById(req.params.id);
    if (!p) return errJson(res, "Produto não encontrado", 404);

    if (req.body.name) p.wl_name = req.body.name;

 
    if (req.body.category) {
      const cat = await ensureCategory(req.body.category);
      if (cat) {
        p.wl_category = cat._id;
        p.wl_categories = Array.from(new Set([...(p.wl_categories || []), cat._id]));
      }
    }
 
    if (req.body.categories !== undefined) {
      const resolved = await ensureCategories(req.body.categories);
      p.wl_categories = resolved.map((c) => c._id);
      if (!req.body.category) {
        p.wl_category = p.wl_categories[0] || undefined;
      }
    }

 
    if (req.body.subcategories !== undefined) {
      try {
        const subs = await ensureSubCategories(req.body.subcategories);
        p.wl_subcategories = subs;
      } catch (e) {
        return errJson(res, e.message || "Subcategorias inválidas", 422);
      }
    }

    if (req.body.description_html !== undefined) p.wl_description_html = req.body.description_html;
    if (req.body.specs_text !== undefined) p.wl_specs_text = req.body.specs_text;
    if (req.body.datasheet_url !== undefined) p.wl_datasheet_url = req.body.datasheet_url;
    if (req.body.manual_url !== undefined) p.wl_manual_url = req.body.manual_url;
    if (req.body.sku !== undefined) p.wl_sku = req.body.sku || undefined;

    if (req.body.link !== undefined) p.wl_link = (req.body.link || "").trim();

    if (req.files?.length) {
      const newUrls = await uploadFilesToCloudinary(req.files || []);
      p.wl_images = (p.wl_images || []).concat(newUrls);
    }

    p.wl_updated_at = new Date();
    await p.save();
    ok(res, { updated: true });
  })
);


 
app.post("/api/products/:id/clone",
  requireAuth(["admin", "editor"]),
  asyncH(async (req, res) => {
    const { id } = req.params;
    const { sku, name, includeExamples } = req.body || {};

    if (!sku || !sku.trim()) {
      return res.status(400).json({ error: "SKU é obrigatório para o clone." });
    }

    const clash = await WaveledProduct.findOne({ wl_sku: sku.trim() }).lean();
    if (clash) {
      return res.status(409).json({ error: "Já existe um produto com esse SKU." });
    }

    const src = await WaveledProduct.findById(id).lean();
    if (!src) {
      return res.status(404).json({ error: "Produto de origem não encontrado." });
    }

 
    const now = new Date();
    const clonedDoc = {
      wl_name: name?.trim() || src.wl_name || "",
      wl_sku: sku.trim(),
      wl_specs_text: src.wl_specs_text || "",
      wl_description_html: src.wl_description_html || "",
      wl_datasheet_url: src.wl_datasheet_url || "",
      wl_manual_url: src.wl_manual_url || "",
      wl_images: Array.isArray(src.wl_images) ? [...src.wl_images] : [],
      wl_likes: 0, 
      wl_categories: Array.isArray(src.wl_categories) ? [...src.wl_categories] : [],
      wl_category: src.wl_category || null,
      wl_created_at: now,
      wl_updated_at: now, 
    };

    const created = await WaveledProduct.create(clonedDoc);

 
    if (includeExamples) {
      const examples = await ExampleShowcase.find({ productId: src._id }).lean();
      if (examples?.length) {
        const copies = examples.map((ex) => ({
          productId: created._id,
          categoryId: ex.categoryId || undefined,  
          title: ex.title,
          description: ex.description || "",
          image: ex.image,
          createdAt: undefined,  
          updatedAt: undefined,
        }));
        if (copies.length) {
          await ExampleShowcase.insertMany(copies);
        }
      }
    }

 
    const withPopulates = await WaveledProduct.findById(created._id)
      .populate("wl_categories")
      .populate("wl_category")
      .lean();

    return res.json({ ok: true, data: withPopulates });
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

 

 
function productBelongsToCategory(prod, catId) {
  if (!prod) return false;
  const idStr = String(catId);
  if (prod.wl_category && String(prod.wl_category) === idStr) return true;
  if (Array.isArray(prod.wl_categories)) {
    return prod.wl_categories.some((c) => String(c) === idStr);
  }
  return false;
}
 
function decorateWithCategoryContext(doc, cat) {
  if (!doc) return doc;
  return {
    ...doc,
    wl_matched_category: {
      _id: String(cat._id),
      wl_name: cat.wl_name,
      wl_slug: cat.wl_slug,
    },
  };
}

  
app.get(
  "/api/category/:categoryId/bundle",
  param("categoryId").isString(),
  validate,
  audit("category.bundle.get"),
  asyncH(async (req, res) => { 
    const cat = await ensureCategory(req.params.categoryId);
    if (!cat) return errJson(res, "Categoria não encontrada", 404);

    const catId = cat._id;

 
    const latest3 = await WaveledProduct.find({
      $or: [
        { wl_categories: { $elemMatch: { $eq: catId } } },
        { wl_category: catId },
      ],
    })
      .sort({ wl_created_at: -1, _id: -1 })
      .limit(3)
      .lean();

 
    const topDoc = await WaveledTopList.findOne({
      wl_scope: "category",
      wl_category: catId,
    }).lean();

    let topProduct = null;

    const pickFirstValidFrom = async (ids = []) => {
      for (const id of ids || []) {
        if (!id) continue;
        const p = await WaveledProduct.findOne({
          _id: id,
          $or: [
            { wl_categories: { $elemMatch: { $eq: catId } } },
            { wl_category: catId },
          ],
        }).lean();
        if (p) return p;
      }
      return null;
    };

    if (topDoc) {
      if (topDoc.wl_best) {
        topProduct = await WaveledProduct.findOne({
          _id: topDoc.wl_best,
          $or: [
            { wl_categories: { $elemMatch: { $eq: catId } } },
            { wl_category: catId },
          ],
        }).lean();
      }
      if (!topProduct && Array.isArray(topDoc?.wl_top3)) {
        topProduct = await pickFirstValidFrom(topDoc.wl_top3);
      }
      if (!topProduct && Array.isArray(topDoc?.wl_top10)) {
        topProduct = await pickFirstValidFrom(topDoc.wl_top10);
      }
    }

 
    const excludeIds = new Set(latest3.map((p) => String(p._id)));
    if (topProduct) excludeIds.add(String(topProduct._id));

    const others = await WaveledProduct.find({
      $or: [
        { wl_categories: { $elemMatch: { $eq: catId } } },
        { wl_category: catId },
      ],
      _id: { $nin: Array.from(excludeIds) },
    })
      .sort({ wl_created_at: -1, _id: -1 })
      .lean();

 
    const latest3Decorated = latest3.map((p) => decorateWithCategoryContext(p, cat));
    const topProductDecorated = topProduct ? decorateWithCategoryContext(topProduct, cat) : null;
    const othersDecorated = others.map((p) => decorateWithCategoryContext(p, cat));

    return ok(res, {
      category: { _id: cat._id, wl_name: cat.wl_name, wl_slug: cat.wl_slug },
      latest3: latest3Decorated,
      topProduct: topProductDecorated, 
      others: othersDecorated,
      counts: {
        latest3: latest3.length,
        others: others.length,
        excluded: excludeIds.size,
      },
    });
  })
);
 

 
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
    const images =  await uploadFilesToCloudinary(req.files || []);
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

 

 
app.put(
  "/api/success-cases/:id",
  limiterAuth,
  requireAuth(["admin", "editor"]),
  upload.array("images", 12), 
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
      const imgs =  await uploadFilesToCloudinary(req.files || []);
      c.wl_images = c.wl_images.concat(imgs);
    }

    await c.save();
    ok(res, { updated: true, id: c._id, images: c.wl_images });
  })
);
 

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

 
app.put(
  "/api/success-cases/:id/images/reorder",
  limiterAuth,
  requireAuth(["admin", "editor"]),
  param("id").isMongoId(),
  body("order").isArray({ min: 1 }),  
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




 
const makeSlug = (name) =>
  String(name || "")
    .toLowerCase()
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "") 
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");



 
app.delete(
  "/api/products/:id/images",
  limiterAuth,
  requireAuth(["admin", "editor"]),
  param("id").isMongoId(), 
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
    try {
      if (removed && removed.startsWith("/uploads/")) {
        const fileOnDisk = path.join(UPLOAD_DIR, path.basename(removed));
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


 

  
const SubCategorySchema = new Schema(
  {
    wl_name: { type: String, required: true },
    wl_slug: { type: String, required: true },
    wl_categories: [
      { type: Schema.Types.ObjectId, ref: "WaveledCategory", index: true },
    ],
    wl_created_at: { type: Date, default: Date.now },
  },
  { collection: "waveled_subcategories" }
);
 
SubCategorySchema.index({ wl_slug: 1, wl_categories: 1 }, { unique: true });

const WaveledSubCategory = mongoose.model("WaveledSubCategory", SubCategorySchema);

 
app.get(
  "/api/categories-with-subcategories",
  asyncH(async (req, res) => {
    const categories = await WaveledCategory.find({})
      .sort({ wl_order: 1 })
      .lean();

    const subs = await WaveledSubCategory.find({})
      .lean();

    const out = categories.map((c) => ({
      ...c,
      subcategories: subs.filter((s) =>
        Array.isArray(s.wl_categories) &&
        s.wl_categories.some((catId) => String(catId) === String(c._id))
      ),
    }));

    ok(res, out);
  })
);

 
app.post(
  "/api/subcategories",
  requireAuth(["admin", "editor"]),
  body("name").isString().isLength({ min: 2 }),
  body("categories").isArray({ min: 1 }),
  validate,
  asyncH(async (req, res) => {
    const { name, categories } = req.body;

 
    const ids = (categories || []).filter((x) => mongoose.isValidObjectId(x));
    if (!ids.length) return errJson(res, "Categorias inválidas", 422);
 
    const existsCats = await WaveledCategory.find({ _id: { $in: ids } }).select("_id");
    if (existsCats.length !== ids.length) return errJson(res, "Uma ou mais categorias não existem", 422);

    const slug = makeSlug(name);
 
    const already = await WaveledSubCategory.findOne({
      wl_slug: slug,
      wl_categories: { $all: ids },
    });

    if (already) return errJson(res, "Subcategoria já existe", 409);

    const sc = await WaveledSubCategory.create({
      wl_name: String(name).trim().replace(/\s+/g, " "),
      wl_slug: slug,
      wl_categories: ids,
    });

    ok(res, sc, 201);
  })
);
 
app.get(
  "/api/subcategories",
  requireAuth(["admin", "editor"]),
  asyncH(async (req, res) => {
    const rows = await WaveledSubCategory.find({})
      .sort({ wl_created_at: -1 })
      .lean();
    ok(res, rows);
  })
);
 
app.put(
  "/api/subcategories/:id",
  requireAuth(["admin", "editor"]),
  param("id").isMongoId(),
  body("name").optional().isString().isLength({ min: 2 }),
  body("slug").optional().isString().isLength({ min: 2 }),
  body("categories").optional().isArray({ min: 1 }),
  validate,
  asyncH(async (req, res) => {
    const { id } = req.params;
    const sc = await WaveledSubCategory.findById(id);
    if (!sc) return errJson(res, "Subcategoria não encontrada", 404);

    const payload = {};

    if (req.body.name) {
      payload.wl_name = String(req.body.name).trim().replace(/\s+/g, " "); 
      if (!req.body.slug) payload.wl_slug = makeSlug(payload.wl_name);
    }

    if (req.body.slug) payload.wl_slug = makeSlug(req.body.slug);

    if (req.body.categories) {
      const ids = req.body.categories.filter((x) => mongoose.isValidObjectId(x));
      if (!ids.length) return errJson(res, "Categorias inválidas", 422);

      const existsCats = await WaveledCategory.find({ _id: { $in: ids } }).select("_id");
      if (existsCats.length !== ids.length) return errJson(res, "Uma ou mais categorias não existem", 422);

      payload.wl_categories = ids;
    }

    const updated = await WaveledSubCategory.findByIdAndUpdate(id, payload, { new: true });
    ok(res, updated);
  })
);

 
app.delete(
  "/api/subcategories/:id/from-category/:categoryId",
  requireAuth(["admin", "editor"]),
  param("id").isMongoId(),
  param("categoryId").isMongoId(),
  validate,
  asyncH(async (req, res) => {
    const { id, categoryId } = req.params;

    const sc = await WaveledSubCategory.findById(id);
    if (!sc) return errJson(res, "Subcategoria não encontrada", 404);
 
    const before = sc.wl_categories.length;

    sc.wl_categories = sc.wl_categories.filter(
      (cId) => String(cId) !== String(categoryId)
    );
 
    if (sc.wl_categories.length === before) {
      return errJson(res, "Subcategoria não estava associada a esta categoria", 400);
    }
 
    if (sc.wl_categories.length > 0) {
      await sc.save();
      return ok(res, {
        updated: true,
        removedFromCategory: categoryId,
      });
    }
 
    await WaveledSubCategory.deleteOne({ _id: id });

    ok(res, {
      deleted: true,
      reason: "Subcategoria sem categorias associadas",
    });
  })
);





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

 
async function nextOrder(WaveledCategory) {
  const last = await WaveledCategory.findOne({}).sort({ wl_order: -1 });
  return typeof last?.wl_order === "number" ? last.wl_order + 1 : 0;
}
 
async function reorderFull(WaveledCategory, orderedIdsRaw) {
  const orderedIds = (orderedIdsRaw || [])
    .map((x) => (typeof x === "string" ? x : x?._id))
    .filter(Boolean)
    .map(String);
 
  const uniq = [...new Set(orderedIds)];
  if (uniq.length !== orderedIds.length) {
    const err = new Error("IDs duplicados na ordenação");
    err.status = 400;
    throw err;
  }
 
  const all = await WaveledCategory.find({}).sort({ wl_order: 1, wl_name: 1 });
  const allIds = all.map((d) => String(d._id)); 
  const notFound = uniq.filter((id) => !allIds.includes(id));
  if (notFound.length) {
    const err = new Error(`Alguns IDs não existem: ${notFound.join(", ")}`);
    err.status = 400;
    throw err;
  }
 
  const remaining = allIds.filter((id) => !uniq.includes(id));
  const finalOrder = [...uniq, ...remaining];
 
  const bulkOps = finalOrder.map((id, idx) => ({
    updateOne: {
      filter: { _id: id },
      update: { $set: { wl_order: idx } },
    },
  }));
  if (bulkOps.length) await WaveledCategory.bulkWrite(bulkOps);
}

 
 
 
 
 
  app.get(
    "/api/categories",
    limiterAuth, 
    audit("categories.list"),
    asyncH(async (req, res) => {
      if (String(req.query.normalize || "0") === "1") {
        await normalizeCategoryOrder(WaveledCategory);
      }
      const items = await WaveledCategory.find({}).sort({ wl_order: 1, wl_name: 1 });
      ok(res, items);
    })
  );





 
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

 
  app.post(
    "/api/categories",
    limiterAuth,
    requireAuth(["admin", "editor"]),
    body("name").isString().isLength({ min: 2 }).trim(),
    body("slug").optional().isString().trim(),
    validate,
    audit("categories.create"),
    requireAuth(["admin", "editor"]),
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

 
  app.put(
    "/api/categories/:id",
    limiterAuth,
    requireAuth(["admin", "editor"]),
    param("id").isMongoId(),
    body("name").optional().isString().isLength({ min: 2 }).trim(),
    body("slug").optional().isString().trim(),
    validate,
    audit("categories.update"),
    requireAuth(["admin", "editor"]),
    asyncH(async (req, res) => {
      const cat = await WaveledCategory.findById(req.params.id);
      if (!cat) return errJson(res, "Categoria não encontrada", 404);

      if (req.body.name) cat.wl_name = req.body.name.trim();

      if (req.body.slug) {
        cat.wl_slug = req.body.slug.trim().toLowerCase();
      } else if (req.body.name) {
        cat.wl_slug = makeSlug(req.body.name);
      }

    
      const conflict = await WaveledCategory.findOne({
        _id: { $ne: cat._id },
        $or: [{ wl_name: cat.wl_name }, { wl_slug: cat.wl_slug }],
      });
      if (conflict) return errJson(res, "Nome/slug já em uso por outra categoria", 409);

      await cat.save();
      ok(res, { updated: true });
    })
  );

 
  app.delete(
    "/api/categories/:id",
    limiterAuth,
    requireAuth(["admin"]),
    param("id").isMongoId(),
    validate,
    audit("categories.delete"),
    requireAuth(["admin", "editor"]),
    asyncH(async (req, res) => {
      const cat = await WaveledCategory.findById(req.params.id);
      if (!cat) return errJson(res, "Categoria não encontrada", 404);
 
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

 
  app.post(
    "/api/categories/reorder",
    limiterAuth,
    requireAuth(["admin", "editor"]),
    body("orderedIds").isArray({ min: 1 }),
    validate,
    audit("categories.reorder"),
    requireAuth(["admin", "editor"]),
    asyncH(async (req, res) => {
      await reorderFull(WaveledCategory, req.body.orderedIds);
      ok(res, { reordered: true });
    })
  ); 


  app.patch(
    "/api/categories/:id/reorder-step",
    limiterAuth,
    requireAuth(["admin", "editor"]),
    param("id").isMongoId(),
    body("direction").isIn(["up", "down"]),
    validate,
    audit("categories.reorder-step"),
    requireAuth(["admin", "editor"]),
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
 
      await WaveledCategory.bulkWrite([
        { updateOne: { filter: { _id: a._id }, update: { $set: { wl_order: b.wl_order } } } },
        { updateOne: { filter: { _id: b._id }, update: { $set: { wl_order: a.wl_order } } } },
      ]);

      ok(res, { reordered: true });
    })
  );
 

 
const ExampleShowcaseSchema = new mongoose.Schema(
  {
    categoryId: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', index: true },
    productId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Product', index: true },
    title:      { type: String, required: true },
    description:{ type: String, default: '' },
    image:      { type: String, required: true },  
  },
  { timestamps: true }
);
ExampleShowcaseSchema.index({ categoryId: 1, productId: 1, createdAt: -1 });
const ExampleShowcase = mongoose.model('ExampleShowcase', ExampleShowcaseSchema);

const CategoryVideoSchema = new mongoose.Schema(
  {
    categoryId: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', unique: true, index: true },
    videoUrl:   { type: String, default: '' },
    videoText:  { type: String, default: '' }, 
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

 
const uploadDir = path.join(process.cwd(), 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

 
 
app.post(
  "/api/upload",
  requireAuth(["admin", "editor"]),
  upload.single("file"),
  asyncH(async (req, res) => {
    if (!req.file) return errJson(res, "Ficheiro ausente", 400);

    if (req.file.size > 4 * 1024 * 1024) {
      return errJson(res, "Imagem excede 4MB", 413);
    }
 
    const uploadOne = (file, folder = "waveled/uploads") =>
      new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          {
            folder,
            resource_type: "image", 
            transformation: [{ quality: "auto", fetch_format: "auto" }], 
          },
          (err, result) => (err ? reject(err) : resolve(result))
        );
        stream.end(file.buffer);
      });

    try {
      const r = await uploadOne(req.file); 
      console.log(r.secure_url)
      return ok(res, {
        url: r.secure_url,
        path: r.secure_url, 
        public_id: r.public_id,
        width: r.width,
        height: r.height,
        format: r.format,
        bytes: r.bytes,
      });
    } catch (e) {
      console.error("Cloudinary upload error:", e);
      return errJson(res, "Falha no upload para Cloudinary", 502);
    }
  })
);
 
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


 


app.post('/api/examples', 
   requireAuth(["admin", "editor", "viewer"]),
  async (req, res) => {
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

app.delete('/api/examples/:id',   requireAuth(["admin", "editor"]), async (req, res) => {
  try {
    await ExampleShowcase.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

 

 
function isObjectId(id) {
  return mongoose.Types.ObjectId.isValid(id);
}

 
app.patch('/api/examples/:id',   requireAuth(["admin", "editor"]), async (req, res) => {
  try {
    const { id } = req.params;
    if (!isObjectId(id)) {
      return res.status(400).json({ error: 'id inválido' });
    } 
    const allowed = ['title', 'description', 'image', 'categoryId', 'productId'];
    const payload = {};
    for (const k of allowed) {
      if (k in req.body) payload[k] = req.body[k];
    }
 
    if (Object.keys(payload).length === 0) {
      return res.status(400).json({ error: 'nenhum campo válido para atualização' });
    }
 
    if ('categoryId' in payload || 'productId' in payload) {
      const nextCategory = ('categoryId' in payload) ? payload.categoryId : undefined;
      const nextProduct  = ('productId'  in payload) ? payload.productId  : undefined; 
      const current = await ExampleShowcase.findById(id).lean();
      if (!current) return res.status(404).json({ error: 'registo não encontrado' });

      const finalCategoryId = nextCategory !== undefined ? nextCategory : current.categoryId;
      const finalProductId  = nextProduct  !== undefined ? nextProduct  : current.productId;

      if (!finalCategoryId && !finalProductId) {
        return res.status(400).json({ error: 'categoryId ou productId é obrigatório' });
      }
    }

    const updated = await ExampleShowcase.findByIdAndUpdate(
      id,
      { $set: payload },
      { new: true, runValidators: true }
    ).lean();

    if (!updated) {
      return res.status(404).json({ error: 'registo não encontrado' });
    }

    res.json({ ok: true, data: updated });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

 
async function resolveCategoryId(idOrName) {
  const key = String(idOrName || "").trim();
  if (!key) return null; 
  if (Types.ObjectId.isValid(key)) {
    return key;
  }
 
  const slug = key.toLowerCase();
  let cat = await WaveledCategory.findOne({ wl_slug: slug }, { _id: 1 }).lean();
  if (cat?._id) return String(cat._id);
 
  const norm = normalizeName(key);
  cat = await WaveledCategory.findOne({ wl_name_norm: norm }, { _id: 1 }).lean();
  if (cat?._id) return String(cat._id);
 
  cat = await WaveledCategory.findOne(
    { wl_name: { $regex: `^${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, $options: "i" } },
    { _id: 1 }
  ).lean();
  if (cat?._id) return String(cat._id);

  return null; 
}

  
app.get('/api/categories/:id/style', async (req, res) => {
  try {
    const cid = await resolveCategoryId(req.params.id);
    if (!cid) { 
      return res.json({ data: {} });
    }
    const doc = await CategoryStyle.findOne({ categoryId: cid }).lean();
    res.json({ data: doc || {} });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

 
app.put('/api/categories/:id/style',   requireAuth(["admin", "editor", "viewer"]), async (req, res) => {
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

 
app.get('/api/categories/:id/video',   requireAuth(["admin", "editor", "viewer"]), async (req, res) => {
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

 
app.put('/api/categories/:id/video', requireAuth(["admin", "editor", "viewer"]),  async (req, res) => {
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

 
 

 
const ensureValid = (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: errors.array().map((e) => e.msg).join('; ') });
  }
};

 
const SolutionSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, index: 'text' },
    description: { type: String, default: '' },
    image: { type: String, default: '' },

    categories: [
      {
        type: Schema.Types.ObjectId,
        ref: "WaveledCategory",
      },
    ], 
    order: {
      type: Number,
      default: 9999,  
      index: true,
    },
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


 async function normalizeSolutionOrders() {
  const sols = await Solution.find({})
    .select("_id order createdAt")
    .sort({ order: 1, createdAt: 1, _id: 1 })
    .lean();

 
  const orders = sols.map(s => Number(s.order));
  const hasInvalid = orders.some(v => !Number.isFinite(v));
  const uniq = new Set(orders.filter(Number.isFinite));
  const hasDuplicates = uniq.size !== orders.filter(Number.isFinite).length;

 
  const count9999 = orders.filter(v => v === 9999).length;
  const looksUninitialized = count9999 >= Math.max(3, Math.floor(sols.length * 0.5));

  if (!hasInvalid && !hasDuplicates && !looksUninitialized) return false;

  const ops = sols.map((s, i) => ({
    updateOne: {
      filter: { _id: s._id },
      update: { $set: { order: i + 1 } },
    },
  }));

  if (ops.length) await Solution.bulkWrite(ops);
  return true;
}


 app.post(
  "/api/solutions/:id/move",
  [
    param("id").isMongoId().withMessage("id inválido"),
    body("dir").isIn(["up", "down"]).withMessage("dir inválido"),
  ],
  requireAuth(["admin", "editor"]),
  asyncH(async (req, res) => {
    try {
      const err = ensureValid(req, res);
      if (err) return err;

      const { id } = req.params;
      const { dir } = req.body;
 
      await normalizeSolutionOrders();

      const current = await Solution.findById(id);
      if (!current) return res.status(404).json({ error: "Solução não encontrada" });

      const curOrder = Number(current.order);

  
      const neighborFilter =
        dir === "up"
          ? { _id: { $ne: current._id }, order: { $lt: curOrder } }
          : { _id: { $ne: current._id }, order: { $gt: curOrder } };

      const neighbor = await Solution.findOne(neighborFilter)
        .sort(dir === "up" ? { order: -1 } : { order: 1 });

      if (!neighbor) {
        return res.json({
          ok: true,
          data: { moved: false, reason: "no-neighbor", curOrder },
        });
      }

      const nOrder = Number(neighbor.order);

 
      current.order = nOrder;
      neighbor.order = curOrder;
      
          console.log("id do item = " +id+ " / posição = " +dir+ " /  order atual = " +curOrder + " / proxima ordem ou atualizada = " +nOrder);
      await Promise.all([current.save(), neighbor.save()]);

      return res.json({
        ok: true,
        data: { moved: true, curOrderBefore: curOrder, neighborOrderBefore: nOrder },
      });
    } catch (error) {
      console.log("error = ", error);
      return res.status(500).json({ ok: false, error: "internal-error" });
    }
  })
); 

 
  app.put('/api/solutions/:id',
    [
      param('id').isMongoId().withMessage('id inválido'),
      body('title').optional().isString(),
      body('description').optional().isString(),
      body('image').optional().isString(),
    ],
      requireAuth(["admin", "editor"]),
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

 
  app.delete(
    '/api/solutions/:id',
    [param('id').isMongoId().withMessage('id inválido')],
    requireAuth(["admin", "editor"]),
    asyncH(async (req, res) => {
      const err = ensureValid(req, res); if (err) return err;
      const { id } = req.params;
      const removed = await Solution.findByIdAndDelete(id);
      if (!removed) return res.status(404).json({ error: 'Solução não encontrada' }); 
      await Promise.all([
        SolutionRelatedProduct.deleteMany({ solutionId: id }),
        SolutionKit.deleteMany({ solutionId: id }),
        SolutionExample.deleteMany({ solutionId: id }),
      ]);
      return res.json({ ok: true });
    })
  );

 
 
 app.get(
  '/api/solutions/:id/products',
  [param('id').isMongoId().withMessage('id inválido')],
  asyncH(async (req, res) =>{
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
  requireAuth(["admin", "editor"]),
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
    requireAuth(["admin", "editor"]),
    asyncH(async (req, res) => {
      const err = ensureValid(req, res); if (err) return err;
      const { id, productId } = req.params;
      await SolutionRelatedProduct.deleteOne({ solutionId: id, productId });
      return res.json({ ok: true });
    })
  );


 
app.get(
  '/api/solutions/',
  [query('q').optional().isString().withMessage('q inválido')],
  asyncH(async (req, res) => {

 
    const rest = await Solution.updateMany(
      { order: { $exists: false } },
      { $set: { order: 9999 } }
    );

    console.log("Atualizadas:", rest.modifiedCount);


    const err = ensureValid(req, res);
    if (err) return err;

    const { q } = req.query;

    let filter = {};
    if (q && q.trim()) {
      filter = {
        $or: [
          { title: { $regex: q.trim(), $options: 'i' } },
          { description: { $regex: q.trim(), $options: 'i' } },
        ],
      };
    }

    const items = await Solution.find(filter) 
      .sort({
        order: 1,        
        createdAt: -1,  
      })
      .lean();

    return res.json({ data: items });
  })
);



 
app.post(
  "/api/solutions/:id/categories",
  [
    param("id").isMongoId().withMessage("id inválido"),
    body("categoryId")
      .isMongoId()
      .withMessage("categoryId inválido"),
  ],
  requireAuth(["admin", "editor"]),
  asyncH(async (req, res) => {
    const err = ensureValid(req, res);
    if (err) return err;

    const { id } = req.params;
    const { categoryId } = req.body || {};

    const cat = await WaveledCategory.findById(categoryId);
    if (!cat) {
      return res.status(404).json({ error: "Categoria não encontrada" });
    }

    const sol = await Solution.findByIdAndUpdate(
      id,
      { $addToSet: { categories: categoryId } },  
      { new: true }
    ).populate("categories");

    if (!sol) {
      return res.status(404).json({ error: "Solução não encontrada" });
    }
 
    const added = (sol.categories || []).find(
      (c) => String(c._id) === String(categoryId)
    );

    return res.json({ ok: true, data: added || cat });
  })
);


 
app.delete(
  "/api/solutions/:id/categories/:catId",
  [
    param("id").isMongoId().withMessage("id inválido"),
    param("catId").isMongoId().withMessage("catId inválido"),
  ],
  requireAuth(["admin", "editor"]),
  asyncH(async (req, res) => {
    const err = ensureValid(req, res);
    if (err) return err;

    const { id, catId } = req.params;

    const sol = await Solution.findByIdAndUpdate(
      id,
      { $pull: { categories: catId } },
      { new: true }
    );

    if (!sol) {
      return res.status(404).json({ error: "Solução não encontrada" });
    }

    return res.json({ ok: true });
  })
);


 
app.get(
  "/api/solutions/:id/categories",
  [param("id").isMongoId().withMessage("id inválido")], 
  requireAuth(["admin", "editor", "viewer"]),
  asyncH(async (req, res) => {
    const err = ensureValid(req, res);
    if (err) return err;

    const { id } = req.params;

    const sol = await Solution.findById(id)
      .populate("categories")
      .lean();

    if (!sol) {
      return res.status(404).json({ error: "Solução não encontrada" });
    }

    return res.json({ data: sol.categories || [] });
  })
);




 
app.get(
  "/api/categories/:catId/solutions",
  [
    param("catId")
      .isMongoId()
      .withMessage("catId inválido"),
  ],
 
  asyncH(async (req, res) => {
    const err = ensureValid(req, res);
    if (err) return err;

    const { catId } = req.params; 
    const category = await WaveledCategory.findById(catId).lean();
    if (!category) {
      return res.status(404).json({ error: "Categoria não encontrada" });
    }

 
    const solutions = await Solution.find({
      categories: catId,
    })
      .select("_id title image createdAt")  
      .sort({ createdAt: -1 })
      .lean(); 
    return res.json({
      ok: true,
      data: {
        category: {
          _id: category._id,
          wl_name: category.wl_name,
          wl_slug: category.wl_slug,
        },
        solutions,
      },
    });
  })
); 

 
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
  requireAuth(["admin", "editor"]),
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
    requireAuth(["admin", "editor"]),
    asyncH(async (req, res) => {
      const err = ensureValid(req, res); if (err) return err;
      const { id, kitId } = req.params;
      await SolutionKit.deleteOne({ _id: kitId, solutionId: id });
      return res.json({ ok: true });
    })
  );

 

app.get(
  "/api/solutions/:id/examples",
  [param("id").isMongoId().withMessage("id inválido")],
  asyncH(async (req, res) => {
    const err = ensureValid(req, res);
    if (err) return err;

    const { id } = req.params;
    const solutionId = new mongoose.Types.ObjectId(id); 
    const sol = await Solution.findById(solutionId).lean();
    if (!sol) {
      return res.status(404).json({ error: "Solução não encontrada" });
    }
 
    const uniqById = (arr) => {
      const seen = new Set();
      return (arr || []).filter((x) => {
        const _id = String(x?._id || "");
        if (!_id || seen.has(_id)) return false;
        seen.add(_id);
        return true;
      });
    };
 
    const baseExamples = await SolutionExample.find({
      solutionId: solutionId,
    })
      .sort({ createdAt: -1 })
      .lean();
 
    let relatedSolutionIdsByCategory = [];
    if (Array.isArray(sol.categories) && sol.categories.length > 0) {
      const sameCategorySolutions = await Solution.find({
        _id: { $ne: solutionId },
        categories: { $in: sol.categories },
      })
        .select("_id title")
        .lean();

      relatedSolutionIdsByCategory = sameCategorySolutions.map((s) => s._id);
    } 
    const relProducts = await SolutionRelatedProduct.find({
      solutionId: solutionId,
    })
      .select("productId")
      .lean();
 
    const kits = await SolutionKit.find({ solutionId })
      .select("productIds")
      .lean();

    const productIdsSet = new Set();
    relProducts.forEach((r) => {
      if (r.productId) productIdsSet.add(String(r.productId));
    });
    kits.forEach((k) => {
      (k.productIds || []).forEach((pid) => {
        if (pid) productIdsSet.add(String(pid));
      });
    });

    const productIds = Array.from(productIdsSet)
      .filter(Boolean)
      .map((pid) => new mongoose.Types.ObjectId(pid));

    let relatedSolutionIdsByProducts = [];
    if (productIds.length > 0) { 
      const otherRels = await SolutionRelatedProduct.find({
        productId: { $in: productIds },
        solutionId: { $ne: solutionId },
      })
        .select("solutionId productId")
        .lean();

      const solIdSet = new Set(
        otherRels.map((r) => String(r.solutionId || ""))
      );

      relatedSolutionIdsByProducts = Array.from(solIdSet)
        .filter(Boolean)
        .map((sid) => new mongoose.Types.ObjectId(sid));
    }
 
    let relatedByCategoryExamples = [];
    if (relatedSolutionIdsByCategory.length > 0) {
      relatedByCategoryExamples = await SolutionExample.find({
        solutionId: { $in: relatedSolutionIdsByCategory },
      })
        .sort({ createdAt: -1 })
        .lean();
    }
 
    let relatedByProductsExamples = [];
    if (relatedSolutionIdsByProducts.length > 0) {
      relatedByProductsExamples = await SolutionExample.find({
        solutionId: { $in: relatedSolutionIdsByProducts },
      })
        .sort({ createdAt: -1 })
        .lean();
    }
 
    const categoryIds = (sol.categories || []).map((c) =>
      String(c)
    );
    const catIdSet = new Set(categoryIds.filter(Boolean));

    let showcaseByCategory = [];
    if (catIdSet.size > 0) {
      showcaseByCategory = await ExampleShowcase.find({
        categoryId: { $in: Array.from(catIdSet) },
      })
        .sort({ createdAt: -1 })
        .lean();
    }

    let showcaseByProducts = [];
    if (productIds.length > 0) {
      showcaseByProducts = await ExampleShowcase.find({
        productId: { $in: productIds },
      })
        .sort({ createdAt: -1 })
        .lean();
    }

    const mainExamples = uniqById(baseExamples);
    const catExamples = uniqById(relatedByCategoryExamples);
    const prodExamples = uniqById(relatedByProductsExamples); 
    const allRelated = uniqById([...catExamples, ...prodExamples]);

    const uniqShowcaseByCategory = uniqById(showcaseByCategory);
    const uniqShowcaseByProducts = uniqById(showcaseByProducts);
    const allShowcase = uniqById([
      ...uniqShowcaseByCategory,
      ...uniqShowcaseByProducts,
    ]);

    return res.json({
      ok: true,
      data: {
        solution: {
          _id: sol._id,
          alldata: sol,
          title: sol.title,
          categories: sol.categories || [],
        },
        examples: { 
          main: mainExamples,
          relatedByCategory: catExamples,
          relatedByProducts: prodExamples,
          allRelated,
 
          showcase: {
            byCategory: uniqShowcaseByCategory,
            byProducts: uniqShowcaseByProducts,
            allShowcase,
          },
        },
      },
    });
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
  requireAuth(["admin", "editor"]),
  asyncH(async (req, res) => {
    const err = ensureValid(req, res); if (err) return err;
    const { id, exampleId } = req.params;
    const { title, description, image } = req.body || {}; 
    const solutionExists = await Solution.exists({ _id: id });
    if (!solutionExists) return res.status(404).json({ error: 'Solução não encontrada' });

 
    const example = await SolutionExample.findOne({ _id: exampleId, solutionId: id });
    if (!example) return res.status(404).json({ error: 'Exemplo não encontrado' });

 
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
    requireAuth(["admin", "editor"]),
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
    requireAuth(["admin", "editor"]),
    asyncH(async (req, res) => {
      const err = ensureValid(req, res); if (err) return err;
      const { id, exampleId } = req.params;
      await SolutionExample.deleteOne({ _id: exampleId, solutionId: id });
      return res.json({ ok: true });
    })
  );

 


 
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

 

app.use((errMiddleware, req, res, next) => { 
  console.error(
    "Middleware erro:",
    errMiddleware && errMiddleware.stack ? errMiddleware.stack : errMiddleware
  );
  return errJson(res, errMiddleware?.message || "Erro interno", 500);
});

 
async function start() {
  try { 
    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 20000,  
      socketTimeoutMS: 45000,
      maxPoolSize: 10, 
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

 
mongoose.connection.on("error", (e) => {
  console.error("Mongo connection error:", e?.message || e);
});
mongoose.connection.on("disconnected", () => {
  console.warn("Mongo desconectado");
});

start(); 