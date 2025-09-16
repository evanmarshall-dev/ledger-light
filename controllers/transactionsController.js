const Transaction = require("../models/transaction");

// Common category suggestions for users. You can expand this list.
const COMMON_CATEGORIES = [
  "Utilities",
  "Power",
  "Water",
  "Internet",
  "Insurance",
  "Mortgage",
  "Rent",
  "Groceries",
  "Dining",
  "Transportation",
  "Fuel",
  "Entertainment",
  "Healthcare",
  "Subscriptions",
  "Savings",
  "Other",
];

// List transactions for the current user
exports.index = async (req, res, next) => {
  try {
    const ownerId = req.session.user && req.session.user._id;
    if (!ownerId) return res.redirect("/login");

    // Build query filters from query params
    const { sort, month, category } = req.query;
    const query = { owner: ownerId };

    // Filter by month if provided (format: YYYY-MM)
    if (month) {
      const [yearStr, monthStr] = month.split("-");
      const year = Number(yearStr);
      const mon = Number(monthStr) - 1; // JS Date months are 0-based
      if (!Number.isNaN(year) && !Number.isNaN(mon)) {
        const start = new Date(Date.UTC(year, mon, 1));
        const end = new Date(Date.UTC(year, mon + 1, 1));
        query.date = { $gte: start, $lt: end };
      }
    }

    // Filter by category if provided
    if (category) {
      query.category = category;
    }

    // Determine sort order
    // supported values: title_asc, title_desc, date_asc, date_desc
    let sortObj = { date: -1 };
    if (sort === "title_asc") sortObj = { title: 1 };
    else if (sort === "title_desc") sortObj = { title: -1 };
    else if (sort === "date_asc") sortObj = { date: 1 };
    else if (sort === "date_desc") sortObj = { date: -1 };

    const transactions = await Transaction.find(query).sort(sortObj);

    // For the category select options, fetch distinct categories for this user
    const userCategories = await Transaction.distinct("category", {
      owner: ownerId,
    });
    // Merge common categories with user's categories, remove falsy and duplicates
    const categories = Array.from(
      new Set([
        ...COMMON_CATEGORIES.filter(Boolean),
        ...(Array.isArray(userCategories)
          ? userCategories.filter(Boolean)
          : []),
      ])
    );

    res.render("transactions/index", {
      title: "Transactions",
      transactions,
      filters: { sort, month, category },
      categories,
    });
  } catch (err) {
    next(err);
  }
};

// Show form to create a new transaction
exports.new = (req, res) => {
  // Provide common categories for the select
  res.render("transactions/new", {
    title: "New Transaction",
    categories: COMMON_CATEGORIES,
  });
};

// Create transaction (POST)
exports.create = async (req, res, next) => {
  try {
    const ownerId = req.session.user && req.session.user._id;
    if (!ownerId) return res.redirect("/login");

    const { title, amount } = req.body;
    const errors = [];
    if (!title) errors.push("Title is required");
    if (!amount || isNaN(Number(amount)))
      errors.push("Valid amount is required");
    if (errors.length) {
      errors.forEach((e) => req.flash("error", e));
      return res.status(400).render("transactions/new", {
        title: "New Transaction",
        data: req.body,
        categories: COMMON_CATEGORIES,
      });
    }

    const data = { ...req.body, owner: ownerId };
    await Transaction.create(data);
    req.flash("success", "Transaction created");
    res.redirect("/transactions");
  } catch (err) {
    next(err);
  }
};

// Show a single transaction
exports.show = async (req, res, next) => {
  try {
    const tx = await Transaction.findById(req.params.id);
    if (!tx) return res.status(404).send("Not found");
    const ownerId = req.session && req.session.user && req.session.user._id;
    if (!ownerId) return res.redirect("/auth/login");
    // guard: tx.owner may be undefined for legacy records
    if (!tx.owner || String(tx.owner) !== String(ownerId))
      return res.status(403).send("Forbidden");
    res.render("transactions/show", { title: "Transaction", transaction: tx });
  } catch (err) {
    next(err);
  }
};

// Edit form
exports.edit = async (req, res, next) => {
  try {
    const tx = await Transaction.findById(req.params.id);
    if (!tx) return res.status(404).send("Not found");
    const ownerId = req.session && req.session.user && req.session.user._id;
    if (!ownerId) return res.redirect("/auth/login");
    if (!tx.owner || String(tx.owner) !== String(ownerId))
      return res.status(403).send("Forbidden");
    // Provide merged categories: common + user's categories
    const userCategories = ownerId
      ? await Transaction.distinct("category", { owner: ownerId })
      : [];
    const categories = Array.from(
      new Set([...COMMON_CATEGORIES, ...(userCategories || [])])
    );
    res.render("transactions/edit", {
      title: "Edit Transaction",
      transaction: tx,
      categories,
    });
  } catch (err) {
    next(err);
  }
};

// Update (PUT/PATCH)
exports.update = async (req, res, next) => {
  try {
    const tx = await Transaction.findById(req.params.id);
    if (!tx) return res.status(404).send("Not found");
    const ownerId = req.session && req.session.user && req.session.user._id;
    if (!ownerId) return res.redirect("/auth/login");
    if (!tx.owner || String(tx.owner) !== String(ownerId))
      return res.status(403).send("Forbidden");

    const { title, amount } = req.body;
    const errors = [];
    if (!title) errors.push("Title is required");
    if (!amount || isNaN(Number(amount)))
      errors.push("Valid amount is required");
    if (errors.length) {
      errors.forEach((e) => req.flash("error", e));
      // Fetch categories so select is populated when re-rendering after error
      const userCategories = ownerId
        ? await Transaction.distinct("category", { owner: ownerId })
        : [];
      const categories = Array.from(
        new Set([...COMMON_CATEGORIES, ...(userCategories || [])])
      );
      return res.status(400).render("transactions/edit", {
        title: "Edit Transaction",
        transaction: Object.assign(tx, req.body),
        categories,
      });
    }

    Object.assign(tx, req.body);
    await tx.save();
    req.flash("success", "Transaction updated");
    res.redirect(`/transactions/${tx._id}`);
  } catch (err) {
    next(err);
  }
};

// Destroy
exports.destroy = async (req, res, next) => {
  try {
    const tx = await Transaction.findById(req.params.id);
    if (!tx) return res.status(404).send("Not found");
    const ownerId = req.session && req.session.user && req.session.user._id;
    if (!ownerId) return res.redirect("/auth/login");
    if (!tx.owner || String(tx.owner) !== String(ownerId))
      return res.status(403).send("Forbidden");
    await tx.deleteOne();
    req.flash("success", "Transaction deleted");
    res.redirect("/transactions");
  } catch (err) {
    next(err);
  }
};
