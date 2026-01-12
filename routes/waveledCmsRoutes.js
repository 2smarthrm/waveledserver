/*
  FULLCODE: CMS ROUTES
  - mantém tudo o que tinhas
  - adiciona:
      ✅ Area Page Builder: /area-pages/:areaId (GET/PUT)
      ✅ Migração admin: /admin/migrate-category-pages-to-area-pages
  - corrige o conflito do wl_category (já tinhas corrigido também)
*/

import express from "express";
import multer from "multer";
import mongoose from "mongoose";
import { v2 as cloudinary } from "cloudinary";

import {
  WaveledVerticalSolution,
  WaveledMegaMenuBanner,
  WaveledHomeSpecial,
  WaveledCategoryPage,
  WaveledApplicationAreas,
  // ✅ NOVO (tens de criar este model no teu ficheiro de models)
  WaveledAreaPage,
} from "../models/waveledCmsModels.js";

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || "",
  api_key: process.env.CLOUDINARY_API_KEY || "",
  api_secret: process.env.CLOUDINARY_API_SECRET || "",
});

const router = express.Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 4 * 1024 * 1024, files: 12 },
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

const isObjId = (id) => mongoose.isValidObjectId(String(id || ""));

async function uploadFilesToCloudinary(files, folder = "waveled/cms") {
  if (!files?.length) return [];
  const toUrl = (file) =>
    new Promise((resolve, reject) => {
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
  return Promise.all(files.map(toUrl));
}

function normalizeOrder(list = []) {
  return (Array.isArray(list) ? list : [])
    .map((x, i) => ({ ...x, order: typeof x.order === "number" ? x.order : i }))
    .sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
}

function parseYouTubeId(input = "") {
  const s = String(input || "").trim();
  if (!s) return "";
  if (/^[a-zA-Z0-9_-]{6,}$/.test(s) && !s.includes("http")) return s;

  try {
    const u = new URL(s);
    if (u.hostname.includes("youtu.be")) return u.pathname.replace("/", "");
    if (u.searchParams.get("v")) return u.searchParams.get("v");
    const m = u.pathname.match(/\/embed\/([^/]+)/);
    if (m?.[1]) return m[1];
  } catch {}
  return s;
}

/* ============================================================
 * TAB 1 — Vertical Solutions CRUD + reorder + favorites
 * ============================================================ */

router.get(
  "/vertical-solutions",
  asyncHandler(async (req, res) => {
    const onlyFeatured = String(req.query.featured || "") === "1";
    const find = onlyFeatured ? { wl_featured_megamenu: true } : {};

    const rows = await WaveledVerticalSolution.find(find)
      .populate({
        path: "wl_product",
        select: "_id wl_name wl_link wl_images wl_category wl_categories",
      })
      .sort({ wl_featured_megamenu: -1, wl_order: 1, wl_updated_at: -1 })
      .lean();

    return res.json({ ok: true, data: rows });
  })
);

router.put(
  "/vertical-solutions/reorder",
  requireAuth(["admin", "editor"]),
  asyncHandler(async (req, res) => {
    const { orderedIds = [] } = req.body;

    if (!Array.isArray(orderedIds) || !orderedIds.length) {
      return res.status(422).json({ ok: false, error: "orderedIds inválido." });
    }

    for (const id of orderedIds) {
      if (!isObjId(id)) {
        return res.status(422).json({ ok: false, error: `ID inválido: ${id}` });
      }
    }

    const ops = orderedIds.map((id, idx) => ({
      updateOne: { filter: { _id: id }, update: { $set: { wl_order: idx } } },
    }));

    await WaveledVerticalSolution.bulkWrite(ops);

    return res.json({ ok: true, data: { saved: true } });
  })
);

router.post(
  "/vertical-solutions",
  requireAuth(["admin", "editor"]),
  upload.single("image"),
  asyncHandler(async (req, res) => {
    const { title, description = "", productId = "", featured = "false" } = req.body;

    if (!title?.trim()) return res.status(422).json({ ok: false, error: "Título obrigatório." });
    if (!req.file) return res.status(422).json({ ok: false, error: "Imagem obrigatória." });

    const [url] = await uploadFilesToCloudinary([req.file], "waveled/vertical-solutions");

    const doc = await WaveledVerticalSolution.create({
      wl_title: title.trim(),
      wl_description: String(description || ""),
      wl_image: url,
      wl_product: isObjId(productId) ? productId : null,
      wl_featured_megamenu: String(featured) === "true",
      wl_order: 0,
    });

    return res.status(201).json({ ok: true, data: doc });
  })
);

router.put(
  "/vertical-solutions/:id",
  requireAuth(["admin", "editor"]),
  upload.single("image"),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    if (!isObjId(id)) return res.status(422).json({ ok: false, error: "ID inválido." });

    const doc = await WaveledVerticalSolution.findById(id);
    if (!doc) return res.status(404).json({ ok: false, error: "Não encontrado." });

    const { title, description, productId, featured } = req.body;

    if (title !== undefined) doc.wl_title = String(title).trim();
    if (description !== undefined) doc.wl_description = String(description || "");
    if (productId !== undefined) doc.wl_product = isObjId(productId) ? productId : null;
    if (featured !== undefined) doc.wl_featured_megamenu = String(featured) === "true";

    if (req.file) {
      const [url] = await uploadFilesToCloudinary([req.file], "waveled/vertical-solutions");
      doc.wl_image = url;
    }

    await doc.save();
    return res.json({ ok: true, data: doc });
  })
);

router.delete(
  "/vertical-solutions/:id",
  requireAuth(["admin", "editor"]),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    if (!isObjId(id)) return res.status(422).json({ ok: false, error: "ID inválido." });

    await WaveledVerticalSolution.deleteOne({ _id: id });
    return res.json({ ok: true, data: { deleted: true } });
  })
);

/* ============================================================
 * TAB 2 — Megamenu Banners CRUD + reorder
 * ============================================================ */

router.get(
  "/megamenu-banners",
  asyncHandler(async (_req, res) => {
    const rows = await WaveledMegaMenuBanner.find({})
      .populate({ path: "wl_product", select: "_id wl_name wl_link wl_images" })
      .sort({ wl_order: 1, wl_updated_at: -1 })
      .lean();
    return ok(res, rows);
  })
);

router.put(
  "/megamenu-banners/reorder",
  requireAuth(["admin", "editor"]),
  asyncHandler(async (req, res) => {
    const { orderedIds = [] } = req.body;
    if (!Array.isArray(orderedIds) || !orderedIds.length) return errJson(res, "orderedIds inválido.", 422);

    for (const id of orderedIds) {
      if (!isObjId(id)) return errJson(res, `ID inválido: ${id}`, 422);
    }

    const ops = orderedIds.map((id, idx) => ({
      updateOne: { filter: { _id: id }, update: { $set: { wl_order: idx } } },
    }));
    await WaveledMegaMenuBanner.bulkWrite(ops);

    return ok(res, { saved: true });
  })
);

router.post(
  "/megamenu-banners",
  requireAuth(["admin", "editor"]),
  upload.single("image"),
  asyncHandler(async (req, res) => {
    const { title = "", description = "", productId = "" } = req.body;
    if (!req.file) return errJson(res, "Imagem obrigatória.", 422);

    const [url] = await uploadFilesToCloudinary([req.file], "waveled/megamenu-banners");

    const doc = await WaveledMegaMenuBanner.create({
      wl_title: String(title || "").trim(),
      wl_description: String(description || ""),
      wl_image: url,
      wl_product: isObjId(productId) ? productId : null,
      wl_order: 0,
    });

    return ok(res, doc, 201);
  })
);

router.put(
  "/megamenu-banners/:id",
  requireAuth(["admin", "editor"]),
  upload.single("image"),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    if (!isObjId(id)) return errJson(res, "ID inválido.", 422);

    const doc = await WaveledMegaMenuBanner.findById(id);
    if (!doc) return errJson(res, "Não encontrado.", 404);

    const { title, description, productId } = req.body;
    if (title !== undefined) doc.wl_title = String(title || "").trim();
    if (description !== undefined) doc.wl_description = String(description || "");
    if (productId !== undefined) doc.wl_product = isObjId(productId) ? productId : null;

    if (req.file) {
      const [url] = await uploadFilesToCloudinary([req.file], "waveled/megamenu-banners");
      doc.wl_image = url;
    }

    await doc.save();
    return ok(res, doc);
  })
);

router.delete(
  "/megamenu-banners/:id",
  requireAuth(["admin", "editor"]),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    if (!isObjId(id)) return errJson(res, "ID inválido.", 422);

    await WaveledMegaMenuBanner.deleteOne({ _id: id });
    return ok(res, { deleted: true });
  })
);

/* ============================================================
 * TAB 3 — Home Specials (4 slots) UPSERT por slot
 * ============================================================ */

router.get(
  "/home-specials",
  asyncHandler(async (_req, res) => {
    const rows = await WaveledHomeSpecial.find({})
      .populate({ path: "wl_product", select: "_id wl_name wl_link wl_images" })
      .sort({ wl_slot: 1 })
      .lean();
    return ok(res, rows);
  })
);

router.put(
  "/home-specials/:slot",
  requireAuth(["admin", "editor"]),
  upload.single("image"),
  asyncHandler(async (req, res) => {
    const slot = Number(req.params.slot);
    if (![1, 2, 3, 4].includes(slot)) return errJson(res, "Slot inválido (1..4).", 422);

    const { title = "", description = "", productId = "" } = req.body;

    let imageUrl = "";
    if (req.file) {
      const [url] = await uploadFilesToCloudinary([req.file], "waveled/home-specials");
      imageUrl = url;
    }

    const setDoc = {
      wl_title: String(title || "").trim(),
      wl_description: String(description || ""),
      wl_product: isObjId(productId) ? productId : null,
      wl_updated_at: new Date(),
    };

    if (imageUrl) setDoc.wl_image = imageUrl;

    const setOnInsert = { wl_slot: slot };
    if (!imageUrl) setOnInsert.wl_image = "https://via.placeholder.com/800x800?text=Upload";

    const doc = await WaveledHomeSpecial.findOneAndUpdate(
      { wl_slot: slot },
      { $set: setDoc, $setOnInsert: setOnInsert },
      { new: true, upsert: true }
    );

    return ok(res, doc);
  })
);

/* ============================================================
 * TAB 4 — Category Page Builder (mantém, legado)
 * ============================================================ */

router.get(
  "/category-pages/:categoryId",
  asyncHandler(async (req, res) => {
    const { categoryId } = req.params;
    if (!isObjId(categoryId)) return errJson(res, "categoryId inválido.", 422);

    const doc = await WaveledCategoryPage.findOne({ wl_category: categoryId })
      .populate({ path: "wl_category", select: "_id wl_name wl_slug" })
      .populate({
        path: "top_solutions.solution",
        select: "_id wl_title wl_image wl_featured_megamenu wl_order wl_product",
        populate: { path: "wl_product", select: "_id wl_name wl_link wl_images" },
      })
      .populate({
        path: "most_used_solutions.solution",
        select: "_id wl_title wl_image wl_order wl_product",
        populate: { path: "wl_product", select: "_id wl_name wl_link wl_images" },
      })
      .populate({ path: "featured_product.product", select: "_id wl_name wl_link wl_images" })
      .populate({ path: "slider_solutions.product", select: "_id wl_name wl_link wl_images" })
      .populate({ path: "two_special_products.product", select: "_id wl_name wl_link wl_images" })
      .lean();

    if (!doc) {
      return ok(res, {
        wl_category: categoryId,
        top_solutions: [],
        featured_product: { product: null, images: [], title: "", description: "" },
        slider_solutions: [],
        two_special_products: [],
        videos: [],
        most_used_solutions: [],
      });
    }

    return ok(res, doc);
  })
);

router.put(
  "/category-pages/:categoryId",
  requireAuth(["admin", "editor"]),
  upload.fields([
    { name: "featured_images", maxCount: 10 },
    { name: "slider_images", maxCount: 20 },
    { name: "two_special_images", maxCount: 2 },
  ]),
  asyncHandler(async (req, res) => {
    const { categoryId } = req.params;
    if (!isObjId(categoryId)) return errJson(res, "categoryId inválido.", 422);

    let payload;
    try {
      payload = JSON.parse(req.body.json || "{}");
    } catch {
      return errJson(res, "json inválido.", 422);
    }

    const featuredFiles = req.files?.featured_images || [];
    const sliderFiles = req.files?.slider_images || [];
    const twoSpecialFiles = req.files?.two_special_images || [];

    const featuredUrls = featuredFiles.length
      ? await uploadFilesToCloudinary(featuredFiles, "waveled/category-pages/featured")
      : [];
    const sliderUrls = sliderFiles.length
      ? await uploadFilesToCloudinary(sliderFiles, "waveled/category-pages/slider")
      : [];
    const twoSpecialUrls = twoSpecialFiles.length
      ? await uploadFilesToCloudinary(twoSpecialFiles, "waveled/category-pages/two-special")
      : [];

    // ✅ wl_category NÃO entra no $set (evita conflito)
    const clean = {
      top_solutions: normalizeOrder(payload.top_solutions || []).map((x, idx) => ({
        solution: x.solution,
        order: typeof x.order === "number" ? x.order : idx,
      })),

      featured_product: {
        product: payload?.featured_product?.product || null,
        title: String(payload?.featured_product?.title || ""),
        description: String(payload?.featured_product?.description || ""),
        images: Array.isArray(payload?.featured_product?.images)
          ? payload.featured_product.images
          : [],
      },

      slider_solutions: normalizeOrder(payload.slider_solutions || []).map((x, idx) => ({
        title: String(x.title || ""),
        image: String(x.image || ""),
        product: x.product || null,
        order: typeof x.order === "number" ? x.order : idx,
      })),

      two_special_products: normalizeOrder(payload.two_special_products || []).map((x, idx) => ({
        title: String(x.title || ""),
        image: String(x.image || ""),
        product: x.product || null,
        order: typeof x.order === "number" ? x.order : idx,
      })),

      videos: normalizeOrder(payload.videos || []).map((v, idx) => ({
        youtubeId: parseYouTubeId(v.youtubeId || ""),
        title: String(v.title || ""),
        order: typeof v.order === "number" ? v.order : idx,
      })),

      most_used_solutions: normalizeOrder(payload.most_used_solutions || []).map((x, idx) => ({
        solution: x.solution,
        order: typeof x.order === "number" ? x.order : idx,
      })),

      wl_updated_at: new Date(),
    };

    // merge uploads
    if (featuredUrls.length) {
      const prev = clean.featured_product.images || [];
      clean.featured_product.images = [...prev, ...featuredUrls].slice(0, 10);
    }

    if (sliderUrls.length) {
      const base = Array.isArray(clean.slider_solutions) ? clean.slider_solutions : [];
      const extraSlides = sliderUrls.map((u) => ({
        title: "",
        image: u,
        product: null,
        order: base.length + 999,
      }));
      clean.slider_solutions = normalizeOrder([...base, ...extraSlides]);
    }

    if (twoSpecialUrls.length) {
      const base = Array.isArray(clean.two_special_products)
        ? clean.two_special_products
        : [];
      while (base.length < 2) {
        base.push({ title: "", image: "", product: null, order: base.length });
      }
      twoSpecialUrls.forEach((u, i) => {
        if (base[i]) base[i].image = u;
      });
      clean.two_special_products = normalizeOrder(base);
    }

    const doc = await WaveledCategoryPage.findOneAndUpdate(
      { wl_category: categoryId },
      { $set: clean, $setOnInsert: { wl_category: categoryId } },
      { new: true, upsert: true }
    );

    return ok(res, doc);
  })
);

/* ============================================================
 * TAB 5 — Application Areas CRUD (já tinhas)
 * ============================================================ */

// o egt que faz todas tambem deve estar pouplado comnofme fizemso no get pot arae espeficica para pegar todos os detaljhes e dados 

router.get(
  "/application-areas",
  asyncHandler(async (_req, res) => {
    const rows = await WaveledApplicationAreas.find({})
      .populate({ path: "areas.solutions.product", select: "_id wl_name wl_link wl_images" })
      .sort({ wl_updated_at: -1 })
      .lean();
    return ok(res, rows);
  })
);




 
router.get(
  "/area-pages",
  asyncHandler(async (_req, res) => {
    const rows = await WaveledAreaPage.find({})
      .populate({ path: "wl_area", select: "_id wl_solution_title" })
      .populate({
        path: "top_solutions.solution",
        select: "_id wl_title wl_image wl_featured_megamenu wl_order wl_product",
        populate: { path: "wl_product", select: "_id wl_name wl_link wl_images" },
      })
      .populate({
        path: "most_used_solutions.solution",
        select: "_id wl_title wl_image wl_order wl_product",
        populate: { path: "wl_product", select: "_id wl_name wl_link wl_images" },
      })
      .populate({ path: "featured_product.product", select: "_id wl_name wl_link wl_images" })
      .populate({ path: "slider_solutions.product", select: "_id wl_name wl_link wl_images" })
      .populate({ path: "two_special_products.product", select: "_id wl_name wl_link wl_images" })
      .sort({ wl_updated_at: -1 })
      .lean();

    return ok(res, rows);
  })
);



/// cirar um endpoint como este mas que pegue todas a innves d epegar apenas uma 
router.get(
  "/area-pages/:areaId",
  asyncHandler(async (req, res) => {
    const { areaId } = req.params;
    if (!isObjId(areaId)) return errJson(res, "areaId inválido.", 422);

    const doc = await WaveledAreaPage.findOne({ wl_area: areaId })
      .populate({ path: "wl_area", select: "_id wl_solution_title" })
      .populate({
        path: "top_solutions.solution",
        select: "_id wl_title wl_image wl_featured_megamenu wl_order wl_product",
        populate: { path: "wl_product", select: "_id wl_name wl_link wl_images" },
      })
      .populate({
        path: "most_used_solutions.solution",
        select: "_id wl_title wl_image wl_order wl_product",
        populate: { path: "wl_product", select: "_id wl_name wl_link wl_images" },
      })
      .populate({ path: "featured_product.product", select: "_id wl_name wl_link wl_images" })
      .populate({ path: "slider_solutions.product", select: "_id wl_name wl_link wl_images" })
      .populate({ path: "two_special_products.product", select: "_id wl_name wl_link wl_images" })
      .lean();

    if (!doc) {
      return ok(res, {
        wl_area: areaId,
        top_solutions: [],
        featured_product: { product: null, images: [], title: "", description: "" },
        slider_solutions: [],
        two_special_products: [],
        videos: [],
        most_used_solutions: [],
      });
    }

    return ok(res, doc);
  })
);







router.post(
  "/application-areas",
  requireAuth(["admin", "editor"]),
  asyncHandler(async (req, res) => {
    const { solution_title } = req.body;
    if (!solution_title?.trim()) return errJson(res, "solution_title obrigatório.", 422);

    const doc = await WaveledApplicationAreas.create({
      wl_solution_title: solution_title.trim(),
      areas: [],
    });

    return ok(res, doc, 201);
  })
);

router.put(
  "/application-areas/:id",
  requireAuth(["admin", "editor"]),
  upload.any(),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    if (!isObjId(id)) return errJson(res, "ID inválido.", 422);

    const doc = await WaveledApplicationAreas.findById(id);
    if (!doc) return errJson(res, "Não encontrado.", 404);

    let payload;
    try {
      payload = JSON.parse(req.body.json || "{}");
    } catch {
      return errJson(res, "json inválido.", 422);
    }

    const files = req.files || [];
    const uploadedMap = new Map();

    if (files.length) {
      const urls = await uploadFilesToCloudinary(files, "waveled/application-areas");
      files.forEach((f, idx) => uploadedMap.set(f.fieldname, urls[idx]));
    }

    if (payload.wl_solution_title !== undefined) {
      doc.wl_solution_title = String(payload.wl_solution_title || "").trim();
    }

    const nextAreas = Array.isArray(payload.areas) ? payload.areas : [];
    doc.areas = nextAreas.map((a, aIdx) => {
      const sols = Array.isArray(a.solutions) ? a.solutions : [];
      return {
        title: String(a.title || "").trim(),
        order: typeof a.order === "number" ? a.order : aIdx,
        solutions: sols.map((s, sIdx) => {
          const key = `img__${aIdx}__${sIdx}`;
          const uploaded = uploadedMap.get(key);
          return {
            title: String(s.title || "").trim(),
            product: isObjId(s.product) ? s.product : null,
            order: typeof s.order === "number" ? s.order : sIdx,
            image: uploaded || String(s.image || ""),
          };
        }),
      };
    });

    await doc.save();
    return ok(res, doc);
  })
);

router.delete(
  "/application-areas/:id",
  requireAuth(["admin", "editor"]),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    if (!isObjId(id)) return errJson(res, "ID inválido.", 422);

    await WaveledApplicationAreas.deleteOne({ _id: id });
    return ok(res, { deleted: true });
  })
);

 
router.put(
  "/area-pages/:areaId",
  requireAuth(["admin", "editor"]),
  upload.fields([
    { name: "featured_images", maxCount: 10 },
    { name: "slider_images", maxCount: 20 },
    { name: "two_special_images", maxCount: 2 },
  ]),
  asyncHandler(async (req, res) => {
    const { areaId } = req.params;
    if (!isObjId(areaId)) return errJson(res, "areaId inválido.", 422);

    let payload;
    try {
      payload = JSON.parse(req.body.json || "{}");
    } catch {
      return errJson(res, "json inválido.", 422);
    }

    const featuredFiles = req.files?.featured_images || [];
    const sliderFiles = req.files?.slider_images || [];
    const twoSpecialFiles = req.files?.two_special_images || [];

    const featuredUrls = featuredFiles.length
      ? await uploadFilesToCloudinary(featuredFiles, "waveled/area-pages/featured")
      : [];
    const sliderUrls = sliderFiles.length
      ? await uploadFilesToCloudinary(sliderFiles, "waveled/area-pages/slider")
      : [];
    const twoSpecialUrls = twoSpecialFiles.length
      ? await uploadFilesToCloudinary(twoSpecialFiles, "waveled/area-pages/two-special")
      : [];

    const clean = {
      top_solutions: normalizeOrder(payload.top_solutions || []).map((x, idx) => ({
        solution: x.solution,
        order: typeof x.order === "number" ? x.order : idx,
      })),

      featured_product: {
        product: payload?.featured_product?.product || null,
        title: String(payload?.featured_product?.title || ""),
        description: String(payload?.featured_product?.description || ""),
        images: Array.isArray(payload?.featured_product?.images)
          ? payload.featured_product.images
          : [],
      },

      slider_solutions: normalizeOrder(payload.slider_solutions || []).map((x, idx) => ({
        title: String(x.title || ""),
        image: String(x.image || ""),
        product: x.product || null,
        order: typeof x.order === "number" ? x.order : idx,
      })),

      two_special_products: normalizeOrder(payload.two_special_products || []).map((x, idx) => ({
        title: String(x.title || ""),
        image: String(x.image || ""),
        product: x.product || null,
        order: typeof x.order === "number" ? x.order : idx,
      })),

      videos: normalizeOrder(payload.videos || []).map((v, idx) => ({
        youtubeId: parseYouTubeId(v.youtubeId || ""),
        title: String(v.title || ""),
        order: typeof v.order === "number" ? v.order : idx,
      })),

      most_used_solutions: normalizeOrder(payload.most_used_solutions || []).map((x, idx) => ({
        solution: x.solution,
        order: typeof x.order === "number" ? x.order : idx,
      })),

      wl_updated_at: new Date(),
    };

    if (featuredUrls.length) {
      const prev = clean.featured_product.images || [];
      clean.featured_product.images = [...prev, ...featuredUrls].slice(0, 10);
    }

    if (sliderUrls.length) {
      const base = Array.isArray(clean.slider_solutions) ? clean.slider_solutions : [];
      const extraSlides = sliderUrls.map((u) => ({
        title: "",
        image: u,
        product: null,
        order: base.length + 999,
      }));
      clean.slider_solutions = normalizeOrder([...base, ...extraSlides]);
    }

    if (twoSpecialUrls.length) {
      const base = Array.isArray(clean.two_special_products)
        ? clean.two_special_products
        : [];
      while (base.length < 2) {
        base.push({ title: "", image: "", product: null, order: base.length });
      }
      twoSpecialUrls.forEach((u, i) => {
        if (base[i]) base[i].image = u;
      });
      clean.two_special_products = normalizeOrder(base);
    }

    const doc = await WaveledAreaPage.findOneAndUpdate(
      { wl_area: areaId },
      { $set: clean, $setOnInsert: { wl_area: areaId } },
      { new: true, upsert: true }
    );

    return ok(res, doc);
  })
);

 
router.post(
  "/admin/migrate-category-pages-to-area-pages",
  requireAuth(["admin"]),
  asyncHandler(async (req, res) => {
    const { mappings = [], mode = "copy" } = req.body || {};

    if (!Array.isArray(mappings) || !mappings.length) {
      return errJson(res, "mappings obrigatório (array).", 422);
    }

    for (const m of mappings) {
      if (!isObjId(m?.categoryId) || !isObjId(m?.areaId)) {
        return errJson(res, "mapping inválido: categoryId/areaId têm de ser ObjectId.", 422);
      }
    }

    const report = {
      mode,
      processed: 0,
      copied: 0,
      replaced: 0,
      skipped: 0,
      errors: [],
    };

    for (const m of mappings) {
      const { categoryId, areaId } = m;

      const catDoc = await WaveledCategoryPage.findOne({ wl_category: categoryId }).lean();
      if (!catDoc) {
        report.skipped += 1;
        continue;
      }

      // remove _id para não colidir
      const { _id, wl_category, ...rest } = catDoc;

      if (mode === "replace") {
        // ⚠️ NÃO recomendado: troca id dentro da própria collection
        // isto faz com que populate de "categoria" deixe de fazer sentido
        await WaveledCategoryPage.updateOne(
          { wl_category: categoryId },
          { $set: { wl_category: areaId, wl_updated_at: new Date() } }
        );
        report.replaced += 1;
      } else {
        // ✅ copy: cria/upsert no builder por área
        await WaveledAreaPage.findOneAndUpdate(
          { wl_area: areaId },
          {
            $set: { ...rest, wl_updated_at: new Date() },
            $setOnInsert: { wl_area: areaId },
          },
          { upsert: true, new: true }
        );
        report.copied += 1;
      }

      report.processed += 1;
    }

    return ok(res, report);
  })
);

export default router;
