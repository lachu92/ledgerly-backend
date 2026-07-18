import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, lowercase: true },
  passwordHash: { type: String, required: true },
  recoveryCodeHash: { type: String, required: true },
  // The device token bound to this account. Null until the first successful
  // login, at which point it's set and every future login must present the
  // same token (sent by the frontend from its locally stored device id).
  boundDeviceToken: { type: String, default: null },
  boundDeviceLabel: { type: String, default: null }, // optional human-readable hint, e.g. browser/OS string

  // Whole-account switch. Set to false in MongoDB to suspend this user
  // entirely — they'll be logged out (or blocked at login) without
  // affecting any other account. No app code/UI needed to control this,
  // just edit the field directly in MongoDB Atlas or Compass.
  active: { type: Boolean, default: true },

  // Per-section access. Each key matches a nav item id in the app
  // (dashboard, customers, products, invoices, quotations, reports,
  // company, settings). Set any of these to false in MongoDB to hide that
  // section for this user only — everyone else is unaffected. Missing
  // keys default to true (visible) via the schema defaults below.
  permissions: {
    dashboard: { type: Boolean, default: true },
    customers: { type: Boolean, default: true },
    products: { type: Boolean, default: true },
    invoices: { type: Boolean, default: true },
    quotations: { type: Boolean, default: true },
    reports: { type: Boolean, default: true },
    company: { type: Boolean, default: true },
    settings: { type: Boolean, default: true },
  },

  createdAt: { type: Date, default: Date.now },
});

export default mongoose.model("User", userSchema);
