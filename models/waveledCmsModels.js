import mongoose from "mongoose";

const { Schema } = mongoose;

/* ----------------------------
  Vertical Solutions
---------------------------- */
const VerticalSolutionSchema = new Schema(
  {
    wl_title: { type: String, required: true, trim: true },
    wl_description: { type: String, default: "", trim: true },
    wl_image: { type: String, required: true },
    wl_product: {
      type: Schema.Types.ObjectId,
      ref: "WaveledProduct",
      default: null,
    },
    wl_featured_megamenu: { type: Boolean, default: false, index: true },
    wl_order: { type: Number, default: 0, index: true },
    wl_created_at: { type: Date, default: Date.now },
    wl_updated_at: { type: Date, default: Date.now },
  },
  { collection: "waveled_vertical_solutions" }
);

VerticalSolutionSchema.pre("save", function (next) {
  this.wl_updated_at = new Date();
  next();
});

/* ----------------------------
  MegaMenu Banners
---------------------------- */
const MegaMenuBannerSchema = new Schema(
  {
    wl_title: { type: String, default: "", trim: true },
    wl_description: { type: String, default: "", trim: true },
    wl_image: { type: String, required: true },
    wl_product: {
      type: Schema.Types.ObjectId,
      ref: "WaveledProduct",
      default: null,
    },
    wl_order: { type: Number, default: 0, index: true },
    wl_created_at: { type: Date, default: Date.now },
    wl_updated_at: { type: Date, default: Date.now },
  },
  { collection: "waveled_megamenu_banners" }
);

MegaMenuBannerSchema.pre("save", function (next) {
  this.wl_updated_at = new Date();
  next();
});

/* ----------------------------
  Home Specials
---------------------------- */
const HomeSpecialSchema = new Schema(
  {
    wl_slot: { type: Number, min: 1, max: 4, required: true, unique: true },
    wl_title: { type: String, default: "", trim: true },
    wl_description: { type: String, default: "", trim: true },
    wl_image: { type: String, required: true },
    wl_product: {
      type: Schema.Types.ObjectId,
      ref: "WaveledProduct",
      default: null,
    },
    wl_updated_at: { type: Date, default: Date.now },
  },
  { collection: "waveled_home_specials" }
);

HomeSpecialSchema.pre("save", function (next) {
  this.wl_updated_at = new Date();
  next();
});

/* ----------------------------
  Category Pages
---------------------------- */
const CategoryPageSchema = new Schema(
  {
    wl_category: {
      type: Schema.Types.ObjectId,
      ref: "WaveledCategory",
      required: true,
      unique: true,
      index: true,
    },

    top_solutions: [
      {
        solution: {
          type: Schema.Types.ObjectId,
          ref: "WaveledVerticalSolution",
          required: true,
        },
        order: { type: Number, default: 0 },
      },
    ],

    featured_product: {
      product: {
        type: Schema.Types.ObjectId,
        ref: "WaveledProduct",
        default: null,
      },
      images: { type: [String], default: [] },
      title: { type: String, default: "", trim: true },
      description: { type: String, default: "", trim: true },
    },

    slider_solutions: [
      {
        title: { type: String, default: "", trim: true },
        image: { type: String, required: true },
        product: {
          type: Schema.Types.ObjectId,
          ref: "WaveledProduct",
          default: null,
        },
        order: { type: Number, default: 0 },
      },
    ],

    two_special_products: [
      {
        title: { type: String, default: "", trim: true },
        image: { type: String, required: true },
        product: {
          type: Schema.Types.ObjectId,
          ref: "WaveledProduct",
          default: null,
        },
        order: { type: Number, default: 0 },
      },
    ],

    videos: [
      {
        youtubeId: { type: String, required: true, trim: true },
        title: { type: String, default: "", trim: true },
        order: { type: Number, default: 0 },
      },
    ],

    most_used_solutions: [
      {
        solution: {
          type: Schema.Types.ObjectId,
          ref: "WaveledVerticalSolution",
          required: true,
        },
        order: { type: Number, default: 0 },
      },
    ],

    wl_updated_at: { type: Date, default: Date.now },
  },
  { collection: "waveled_category_pages" }
);

CategoryPageSchema.pre("save", function (next) {
  this.wl_updated_at = new Date();
  next();
});

/* ----------------------------
  Application Areas
---------------------------- */
const ApplicationAreasSchema = new Schema(
  {
    wl_solution_title: { type: String, required: true, trim: true, index: true },

    areas: [
      {
        title: { type: String, required: true, trim: true },
        order: { type: Number, default: 0 },
        solutions: [
          {
            title: { type: String, required: true, trim: true },
            image: { type: String, required: true },
            product: {
              type: Schema.Types.ObjectId,
              ref: "WaveledProduct",
              default: null,
            },
            order: { type: Number, default: 0 },
          },
        ],
      },
    ],

    wl_created_at: { type: Date, default: Date.now },
    wl_updated_at: { type: Date, default: Date.now },
  },
  { collection: "waveled_application_areas" }
);

ApplicationAreasSchema.pre("save", function (next) {
  this.wl_updated_at = new Date();
  next();
});

/* ----------------------------
  Dev reset (Next.js hot reload safe)
---------------------------- */
const resetModel = (name) => {
  if (mongoose.models?.[name]) delete mongoose.models[name];
  if (mongoose.modelSchemas?.[name]) delete mongoose.modelSchemas[name];
};

if (process.env.NODE_ENV !== "production") {
  resetModel("WaveledVerticalSolution");
  resetModel("WaveledMegaMenuBanner");
  resetModel("WaveledHomeSpecial");
  resetModel("WaveledCategoryPage");
  resetModel("WaveledApplicationAreas");
  resetModel("WaveledAreaPage");
}

/* ----------------------------
  Area Pages   FIXED refs
---------------------------- */
const WaveledAreaPageSchema = new Schema(
  {
    wl_area: {
      type: Schema.Types.ObjectId,
      ref: "WaveledApplicationAreas",
      required: true,
      unique: true,
    },

    top_solutions: [
      {
        solution: { type: Schema.Types.ObjectId, ref: "WaveledVerticalSolution" },
        order: { type: Number, default: 0 },
      },
    ],

    featured_product: {
      product: { type: Schema.Types.ObjectId, ref: "WaveledProduct", default: null },
      title: { type: String, default: "", trim: true },
      description: { type: String, default: "", trim: true },
      images: { type: [String], default: [] },
    },

    slider_solutions: [
      {
        title: { type: String, default: "", trim: true },
        image: { type: String, required: true },
        product: { type: Schema.Types.ObjectId, ref: "WaveledProduct", default: null },
        order: { type: Number, default: 0 },
      },
    ],

    two_special_products: [
      {
        title: { type: String, default: "", trim: true },
        image: { type: String, required: true },
        product: { type: Schema.Types.ObjectId, ref: "WaveledProduct", default: null },
        order: { type: Number, default: 0 },
      },
    ],

    videos: [
      {
        youtubeId: { type: String, required: true, trim: true },
        title: { type: String, default: "", trim: true },
        order: { type: Number, default: 0 },
      },
    ],

    most_used_solutions: [
      {
        solution: { type: Schema.Types.ObjectId, ref: "WaveledVerticalSolution" },
        order: { type: Number, default: 0 },
      },
    ],

    wl_updated_at: { type: Date, default: Date.now },
  },
  { collection: "waveled_area_pages", timestamps: true }
);

WaveledAreaPageSchema.pre("save", function (next) {
  this.wl_updated_at = new Date();
  next();
});



 
const HomeHeroSlideSchema = new Schema(
  {
    wl_title: { type: String, default: "", trim: true },
    wl_description: { type: String, default: "", trim: true },
    wl_image: { type: String, required: true },
    wl_link: { type: String, default: "", trim: true }, // ex: /contact-us, /solution?area=12
    wl_order: { type: Number, default: 0, index: true },
    wl_enabled: { type: Boolean, default: true, index: true },
    wl_created_at: { type: Date, default: Date.now },
    wl_updated_at: { type: Date, default: Date.now },
  },
  { collection: "waveled_home_hero_slides" }
);

HomeHeroSlideSchema.pre("save", function (next) {
  this.wl_updated_at = new Date();
  next();
});

 

if (process.env.NODE_ENV !== "production") {
  resetModel("WaveledHomeHeroSlide");
}

export const WaveledHomeHeroSlide =
  mongoose.models.WaveledHomeHeroSlide ||
  mongoose.model("WaveledHomeHeroSlide", HomeHeroSlideSchema);

 
export const WaveledAreaPage =
  mongoose.models.WaveledAreaPage || mongoose.model("WaveledAreaPage", WaveledAreaPageSchema);

export const WaveledVerticalSolution =
  mongoose.models.WaveledVerticalSolution ||
  mongoose.model("WaveledVerticalSolution", VerticalSolutionSchema);

export const WaveledMegaMenuBanner =
  mongoose.models.WaveledMegaMenuBanner ||
  mongoose.model("WaveledMegaMenuBanner", MegaMenuBannerSchema);

export const WaveledHomeSpecial =
  mongoose.models.WaveledHomeSpecial ||
  mongoose.model("WaveledHomeSpecial", HomeSpecialSchema);

export const WaveledCategoryPage =
  mongoose.models.WaveledCategoryPage ||
  mongoose.model("WaveledCategoryPage", CategoryPageSchema);

export const WaveledApplicationAreas =
  mongoose.models.WaveledApplicationAreas ||
  mongoose.model("WaveledApplicationAreas", ApplicationAreasSchema);
