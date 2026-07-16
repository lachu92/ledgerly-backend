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
  createdAt: { type: Date, default: Date.now },
});

export default mongoose.model("User", userSchema);
