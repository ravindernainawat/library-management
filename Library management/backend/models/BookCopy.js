const mongoose = require("mongoose");

const bookCopySchema = new mongoose.Schema({
  bookId: { type: mongoose.Schema.Types.ObjectId, ref: "Book", required: true },
  qrCodeDataUrl: { type: String }, // Base64 image
  shelfLocation: { type: String, default: "General Shelf" },
  status: { type: String, enum: ["available", "issued"], default: "available" }
}, { timestamps: true });

module.exports = mongoose.model("BookCopy", bookCopySchema);
