const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const transactionSchema = new Schema(
  {
    title: { type: String, required: true, trim: true },
    amount: { type: Number, required: true },
    date: { type: Date, default: Date.now },
    category: { type: String, trim: true },
    notes: { type: String },
    // owner references a User model. We assume sessions store the user id at
    // req.session.user._id (common convention). Adjust if your session shape
    // differs.
    owner: { type: Schema.Types.ObjectId, ref: "User", required: true },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Transaction", transactionSchema);
