const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  contact: { type: String, required: true },
  // Gamification
  points: { type: Number, default: 0 },
  streak: { type: Number, default: 0 },
  lastActiveWeek: { type: String, default: "" }, // e.g., "2026-W20"
  booksRead: { type: Number, default: 0 },
  badges: [{ type: String }]
}, { timestamps: true });

// Virtual: dynamic rank based on points
userSchema.virtual("rank").get(function () {
  if (this.points >= 500) return "Grandmaster";
  if (this.points >= 300) return "Sage";
  if (this.points >= 150) return "Scholar";
  if (this.points >= 50) return "Reader";
  return "Novice";
});

userSchema.set("toJSON", { virtuals: true });
userSchema.set("toObject", { virtuals: true });

module.exports = mongoose.model("User", userSchema);
