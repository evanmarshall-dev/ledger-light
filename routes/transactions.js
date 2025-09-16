const express = require("express");
const router = express.Router();
const ctrl = require("../controllers/transactionsController");
const { ensureAuthenticated } = require("../middleware/auth");

// Index - list transactions
router.get("/", ensureAuthenticated, ctrl.index);

// New - form
router.get("/new", ensureAuthenticated, ctrl.new);

// Create
router.post("/", ensureAuthenticated, ctrl.create);

// Show
router.get("/:id", ensureAuthenticated, ctrl.show);

// Edit
router.get("/:id/edit", ensureAuthenticated, ctrl.edit);

// Update
router.put("/:id", ensureAuthenticated, ctrl.update);

// Destroy
router.delete("/:id", ensureAuthenticated, ctrl.destroy);

module.exports = router;
