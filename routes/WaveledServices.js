import express from "express";
import multer from "multer";
import mongoose from "mongoose";
import { v2 as cloudinary } from "cloudinary";
import { Schema } from "mongoose";

const WaveledServicesPageSchema = new Schema(
  {
    wl_key: { type: String, unique: true, default: "services_page" },

    hero: {
      title: { type: String, default: "", trim: true },
      description: { type: String, default: "", trim: true },
    },

    boxes: [
      {
        title: { type: String, default: "", trim: true },
        description: { type: String, default: "", trim: true },
        image: { type: String, default: "" },
        order: { type: Number, default: 0 },
      },
    ],

    content_blocks: [
      {
        type: { type: String, enum: ["service", "overlay"], required: true },
        title: { type: String, default: "", trim: true },
        subtitle: { type: String, default: "", trim: true },
        description: { type: String, default: "", trim: true },
        image: { type: String, default: "" },
        order: { type: Number, default: 0, index: true },
        wl_updated_at: { type: Date, default: Date.now },
      },
    ],

    sections_order: { type: [String], default: ["hero", "boxes", "content"] },

    wl_updated_at: { type: Date, default: Date.now },
  },
  { collection: "waveled_services_page", timestamps: true }
);

WaveledServicesPageSchema.pre("save", function (next) {
  if (!Array.isArray(this.boxes)) this.boxes = [];
  while (this.boxes.length < 3) {
    this.boxes.push({ title: "", description: "", image: "", order: this.boxes.length });
  }
  this.boxes = this.boxes
    .map((b, i) => ({
      title: String(b?.title || ""),
      description: String(b?.description || ""),
      image: String(b?.image || ""),
      order: typeof b?.order === "number" ? b.order : i,
    }))
    .sort((a, b) => (a.order ?? 0) - (b.order ?? 0))
    .slice(0, 3);

  if (!Array.isArray(this.content_blocks)) this.content_blocks = [];
  this.content_blocks = this.content_blocks
    .map((x, i) => ({
      ...x,
      type: x?.type === "overlay" ? "overlay" : "service",
      title: String(x?.title || ""),
      subtitle: String(x?.subtitle || ""),
      description: String(x?.description || ""),
      image: String(x?.image || ""),
      order: typeof x?.order === "number" ? x.order : i,
      wl_updated_at: x?.wl_updated_at ? x.wl_updated_at : new Date(),
    }))
    .sort((a, b) => (a.order ?? 0) - (b.order ?? 0))
    .map((x, idx) => ({ ...x, order: idx }));

  const base = ["hero", "boxes", "content"];
  if (!Array.isArray(this.sections_order) || !this.sections_order.length) {
    this.sections_order = base;
  } else {
    const allowed = new Set(base);
    const clean = this.sections_order.map(String).filter((k) => allowed.has(k));
    const merged = [...new Set(clean)];
    for (const k of base) if (!merged.includes(k)) merged.push(k);
    this.sections_order = merged;
  }

  next();
});

const WaveledServicesPage =
  mongoose.models.WaveledServicesPage ||
  mongoose.model("WaveledServicesPage", WaveledServicesPageSchema);

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || "",
  api_key: process.env.CLOUDINARY_API_KEY || "",
  api_secret: process.env.CLOUDINARY_API_SECRET || "",
});

const router = express.Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 4 * 1024 * 1024, files: 24 },
  fileFilter: (_req, file, cb) => {
    if (/image\/(png|jpe?g|webp|gif|svg\+xml)/.test(file.mimetype)) cb(null, true);
    else cb(new Error("Tipo de ficheiro inválido"));
  },
});

const ok = (res, data, code = 200) => res.status(code).json({ ok: true, data });
const errJson = (res, message = "Erro", code = 400, issues = null) =>
  res.status(code).json({ ok: false, error: message, issues });

export const requireAuth =
  (roles = []) =>
  (req, res, next) => {
    if (!req.session?.user) return errJson(res, "Não autenticado", 401);
    if (roles.length && !roles.includes(req.session.user.role))
      return errJson(res, "Sem permissões", 403);
    next();
  };

const asyncHandler =
  (fn) =>
  (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);

async function uploadFilesToCloudinary(files, folder = "waveled/cms") {
  if (!files?.length) return [];
  const toUrl = (file) =>
    new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { folder, resource_type: "image", transformation: [{ quality: "auto", fetch_format: "auto" }] },
        (err, result) => (err ? reject(err) : resolve(result.secure_url))
      );
      stream.end(file.buffer);
    });
  return Promise.all(files.map(toUrl));
}

function normalizeBoxes3(boxes) {
  const arr = Array.isArray(boxes) ? boxes : [];
  while (arr.length < 3) arr.push({ title: "", description: "", image: "", order: arr.length });
  return arr
    .map((b, i) => ({
      title: String(b?.title || ""),
      description: String(b?.description || ""),
      image: String(b?.image || ""),
      order: typeof b?.order === "number" ? b.order : i,
    }))
    .sort((a, b) => (a.order ?? 0) - (b.order ?? 0))
    .slice(0, 3);
}

function normalizeContentBlocks(blocks) {
  return (Array.isArray(blocks) ? blocks : [])
    .map((b, i) => ({
      _id: b?._id,
      type: b?.type === "overlay" ? "overlay" : "service",
      title: String(b?.title || ""),
      subtitle: String(b?.subtitle || ""),
      description: String(b?.description || ""),
      image: String(b?.image || ""),
      order: typeof b?.order === "number" ? b.order : i,
      wl_updated_at: b?.wl_updated_at ? new Date(b.wl_updated_at) : new Date(),
    }))
    .sort((a, b) => (a.order ?? 0) - (b.order ?? 0))
    .map((b, idx) => ({ ...b, order: idx }));
}

async function getOrCreateServicesPage() {
  let doc = await WaveledServicesPage.findOne({ wl_key: "services_page" }).lean();
  if (doc) {
    doc.boxes = normalizeBoxes3(doc.boxes);
    doc.content_blocks = normalizeContentBlocks(doc.content_blocks);
    if (!Array.isArray(doc.sections_order) || !doc.sections_order.length) doc.sections_order = ["hero", "boxes", "content"];
    return doc;
  }

  const created = await WaveledServicesPage.create({
    wl_key: "services_page",
    hero: { title: "", description: "" },
    boxes: [
      { title: "", description: "", image: "", order: 0 },
      { title: "", description: "", image: "", order: 1 },
      { title: "", description: "", image: "", order: 2 },
    ],
    content_blocks: [],
    sections_order: ["hero", "boxes", "content"],
    wl_updated_at: new Date(),
  });

  const out = created.toObject();
  out.boxes = normalizeBoxes3(out.boxes);
  out.content_blocks = normalizeContentBlocks(out.content_blocks);
  return out;
}

router.get(
  "/services",
  asyncHandler(async (_req, res) => {
    const page = await getOrCreateServicesPage();
    return ok(res, page);
  })
);

router.get(
  "/services-page",
  asyncHandler(async (_req, res) => {
    const doc = await getOrCreateServicesPage();
    return ok(res, doc);
  })
);

router.put(
  "/services-page",
  requireAuth(["admin", "editor"]),
  upload.any(),
  asyncHandler(async (req, res) => {
    let payload;
    try {
      payload = JSON.parse(req.body.json || "{}");
    } catch {
      return errJson(res, "json inválido.", 422);
    }

    const files = req.files || [];
    const uploadedMap = new Map();

    if (files.length) {
      const urls = await uploadFilesToCloudinary(files, "waveled/services-page");
      files.forEach((f, idx) => uploadedMap.set(f.fieldname, urls[idx]));
    }

    let doc = await WaveledServicesPage.findOne({ wl_key: "services_page" });
    if (!doc) doc = new WaveledServicesPage({ wl_key: "services_page" });

    if (payload.hero) {
      if (payload.hero.title !== undefined) doc.hero.title = String(payload.hero.title || "").trim();
      if (payload.hero.description !== undefined) doc.hero.description = String(payload.hero.description || "").trim();
    }

    if (payload.boxes !== undefined) {
      const nextBoxes = normalizeBoxes3(payload.boxes);
      nextBoxes.forEach((b, i) => {
        const u = uploadedMap.get(`box_image__${i}`);
        if (u) b.image = u;
      });
      doc.boxes = nextBoxes;
    } else {
      const current = normalizeBoxes3(doc.boxes);
      current.forEach((b, i) => {
        const u = uploadedMap.get(`box_image__${i}`);
        if (u) b.image = u;
      });
      doc.boxes = current;
    }

    if (payload.sections_order !== undefined) {
      const base = ["hero", "boxes", "content"];
      const allowed = new Set(base);
      const arr = Array.isArray(payload.sections_order) ? payload.sections_order : [];
      const clean = arr.map(String).filter((k) => allowed.has(k));
      const merged = [...new Set(clean)];
      for (const k of base) if (!merged.includes(k)) merged.push(k);
      doc.sections_order = merged;
    }

    if (payload.content_blocks !== undefined) {
      const nextBlocks = normalizeContentBlocks(payload.content_blocks);
      const currentBlocks = normalizeContentBlocks(doc.content_blocks);
      const byId = new Map(currentBlocks.map((b) => [String(b._id), b]));
      const merged = nextBlocks.map((b, idx) => {
        const prev = b?._id ? byId.get(String(b._id)) : null;
        const keepImage = prev?.image || "";
        const u = b?._id ? uploadedMap.get(`block_image__${String(b._id)}`) : "";
        return {
          _id: b._id,
          type: b.type,
          title: b.title,
          subtitle: b.subtitle,
          description: b.description,
          image: u || b.image || keepImage || "",
          order: idx,
          wl_updated_at: new Date(),
        };
      });
      doc.content_blocks = merged;
    } else {
      const current = normalizeContentBlocks(doc.content_blocks);
      current.forEach((b) => {
        const u = uploadedMap.get(`block_image__${String(b._id)}`);
        if (u) b.image = u;
      });
      doc.content_blocks = current;
    }

    doc.wl_updated_at = new Date();
    await doc.save();

    const out = doc.toObject();
    out.boxes = normalizeBoxes3(out.boxes);
    out.content_blocks = normalizeContentBlocks(out.content_blocks);
    return ok(res, out);
  })
);

router.post(
  "/services-blocks",
  requireAuth(["admin", "editor"]),
  upload.single("image"),
  asyncHandler(async (req, res) => {
    const { type = "service", title = "", subtitle = "", description = "" } = req.body || {};
    const t = String(type) === "overlay" ? "overlay" : "service";
    if (!String(title || "").trim()) return errJson(res, "Título obrigatório.", 422);
    if (!req.file) return errJson(res, "Imagem obrigatória.", 422);

    const [url] = await uploadFilesToCloudinary([req.file], "waveled/services-blocks");

    let doc = await WaveledServicesPage.findOne({ wl_key: "services_page" });
    if (!doc) doc = new WaveledServicesPage({ wl_key: "services_page" });

    const blocks = normalizeContentBlocks(doc.content_blocks);
    blocks.push({
      type: t,
      title: String(title || "").trim(),
      subtitle: String(subtitle || "").trim(),
      description: String(description || "").trim(),
      image: url,
      order: blocks.length,
      wl_updated_at: new Date(),
    });

    doc.content_blocks = blocks;
    doc.wl_updated_at = new Date();
    await doc.save();

    const out = doc.toObject();
    out.content_blocks = normalizeContentBlocks(out.content_blocks);
    return ok(res, out, 201);
  })
);

router.put(
  "/services-blocks/:blockId",
  requireAuth(["admin", "editor"]),
  upload.single("image"),
  asyncHandler(async (req, res) => {
    const { blockId } = req.params;
    if (!mongoose.isValidObjectId(String(blockId || ""))) return errJson(res, "blockId inválido.", 422);

    let doc = await WaveledServicesPage.findOne({ wl_key: "services_page" });
    if (!doc) return errJson(res, "Página não encontrada.", 404);

    const blocks = normalizeContentBlocks(doc.content_blocks);
    const idx = blocks.findIndex((b) => String(b._id) === String(blockId));
    if (idx < 0) return errJson(res, "Bloco não encontrado.", 404);

    const { type, title, subtitle, description } = req.body || {};

    if (type !== undefined) blocks[idx].type = String(type) === "overlay" ? "overlay" : "service";
    if (title !== undefined) blocks[idx].title = String(title || "").trim();
    if (subtitle !== undefined) blocks[idx].subtitle = String(subtitle || "").trim();
    if (description !== undefined) blocks[idx].description = String(description || "").trim();

    if (req.file) {
      const [url] = await uploadFilesToCloudinary([req.file], "waveled/services-blocks");
      blocks[idx].image = url;
    }

    blocks[idx].wl_updated_at = new Date();
    doc.content_blocks = blocks.map((b, i) => ({ ...b, order: i }));
    doc.wl_updated_at = new Date();
    await doc.save();

    const out = doc.toObject();
    out.content_blocks = normalizeContentBlocks(out.content_blocks);
    return ok(res, out);
  })
);

router.delete(
  "/services-blocks/:blockId",
  requireAuth(["admin", "editor"]),
  asyncHandler(async (req, res) => {
    const { blockId } = req.params;
    if (!mongoose.isValidObjectId(String(blockId || ""))) return errJson(res, "blockId inválido.", 422);

    let doc = await WaveledServicesPage.findOne({ wl_key: "services_page" });
    if (!doc) return errJson(res, "Página não encontrada.", 404);

    const blocks = normalizeContentBlocks(doc.content_blocks);
    const idx = blocks.findIndex((b) => String(b._id) === String(blockId));
    if (idx < 0) return errJson(res, "Bloco não encontrado.", 404);

    blocks.splice(idx, 1);
    doc.content_blocks = blocks.map((b, i) => ({ ...b, order: i }));
    doc.wl_updated_at = new Date();
    await doc.save();

    const out = doc.toObject();
    out.content_blocks = normalizeContentBlocks(out.content_blocks);
    return ok(res, out);
  })
);

router.put(
  "/services-blocks/reorder",
  requireAuth(["admin", "editor"]),
  asyncHandler(async (req, res) => {
    const { orderedIds = [] } = req.body || {};
    if (!Array.isArray(orderedIds) || !orderedIds.length) return errJson(res, "orderedIds inválido.", 422);

    let doc = await WaveledServicesPage.findOne({ wl_key: "services_page" });
    if (!doc) return errJson(res, "Página não encontrada.", 404);

    const blocks = normalizeContentBlocks(doc.content_blocks);
    const map = new Map(blocks.map((b) => [String(b._id), b]));

    const clean = orderedIds.map(String).filter((id) => map.has(id));
    if (!clean.length) return errJson(res, "orderedIds sem IDs válidos.", 422);

    const used = new Set();
    const next = [];
    for (const id of clean) {
      if (used.has(id)) continue;
      used.add(id);
      next.push(map.get(id));
    }
    for (const b of blocks) {
      const id = String(b._id);
      if (!used.has(id)) next.push(b);
    }

    doc.content_blocks = next.map((b, i) => ({ ...b, order: i, wl_updated_at: new Date() }));
    doc.wl_updated_at = new Date();
    await doc.save();

    const out = doc.toObject();
    out.content_blocks = normalizeContentBlocks(out.content_blocks);
    return ok(res, out);
  })
);

export default router;