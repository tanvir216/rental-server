require("dotenv").config();
require("express-async-errors");
const express = require("express"),
  cors = require("cors"),
  jwt = require("jsonwebtoken"),
  helmet = require("helmet"),
  rateLimit = require("express-rate-limit");
const cron = require("node-cron"),
  Stripe = require("stripe");
const { MongoClient, ObjectId } = require("mongodb");
const nodemailer = require("nodemailer");
const app = express(),
  stripe = Stripe(process.env.STRIPE_SECRET_KEY);


const TZ = process.env.APP_TIMEZONE || "Asia/Dhaka";
const BOOKING = {
  CONFIRMED: "confirmed",
  COMPLETED: "completed",
  CANCELLED: "cancelled",
};
const PAY = {
  PAID: "paid",
  NEEDS_REFUND: "needs_refund",
  REFUNDED: "refunded",
};
const EQUIP_FIELDS = [
  "name",
  "category",
  "image",
  "location",
  "rentalType",
  "description",
  "condition",
  "brand",
  "model",
  "terms",
];
const clientUrls = (process.env.CLIENT_URL || "")
  .split(",")
  .map((u) => u.trim().replace(/\/$/, ""))
  .filter(Boolean);


app.set("trust proxy", 1); 
app.use(helmet());
app.use(
  cors({ origin: clientUrls.length ? clientUrls : false, credentials: true }),
);
let ready;
app.use(async (req, res, next) => {
  try {
    await ready;
    next();
  } catch (e) {
    next(e);
  }
});


app.post(
  "/webhook/stripe",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    if (!process.env.STRIPE_WEBHOOK_SECRET)
      return res.status(501).send({ message: "Webhook not configured" });
    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        req.headers["stripe-signature"],
        process.env.STRIPE_WEBHOOK_SECRET,
      );
    } catch (e) {
      return res.status(400).send({ message: "Bad signature" });
    }
    if (
      event.type === "checkout.session.completed" &&
      event.data.object.payment_status === "paid"
    )
      await fulfill(event.data.object); 
    res.send({ received: true });
  },
);

app.use(express.json({ limit: "100kb" }));
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 600,
    standardHeaders: true,
    legacyHeaders: false,
  }),
);

const checkoutLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Too many attempts, try again later" },
});


const mailer = process.env.EMAIL_USER
  ? nodemailer.createTransport({
      service: "gmail",
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    })
  : null;
const sendMail = (to, subject, text) =>
  mailer
    ?.sendMail({ from: process.env.EMAIL_USER, to, subject, text })
    .catch(console.error);
const client = new MongoClient(process.env.MONGODB_URI);
let db, Users, Equip, Bookings, Payments, Favs;
const oid = (id) => new ObjectId(id);
const validId = (id) =>
  ObjectId.isValid(id) && String(new ObjectId(id)) === String(id);
const escapeRx = (t) => String(t).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const mainClient = () => clientUrls[0] || "";
const todayStr = () => new Date().toLocaleDateString("en-CA", { timeZone: TZ }); // YYYY-MM-DD
const releaseStock = (b) =>
  Equip.updateOne(
    { _id: oid(b.equipmentId) },
    { $inc: { availableQuantity: b.quantity } },
  );
const notify = (b) => {
  const t = `Your rental of "${b.equipmentName}" (${b.startDate} to ${b.endDate}) is now completed. Thank you for using RentGear!`;
  sendMail(b.customer.email, "Rental completed", t);
  sendMail(b.owner.email, "Rental completed", t);
};
const num = (v) => (v === "" || v === null || v === undefined ? NaN : +v);


const cleanEquip = (body, { partial }) => {
  const out = {};
  for (const k of EQUIP_FIELDS) {
    if (body[k] === undefined) continue;
    if (typeof body[k] !== "string") return { error: `${k} must be text` };
    out[k] = body[k].trim();
  }
  if (body.price !== undefined) {
    const n = num(body.price);
    if (!Number.isFinite(n) || n <= 0)
      return { error: "Price must be a number greater than 0" };
    out.price = n;
  }
  if (body.availableQuantity !== undefined) {
    const n = num(body.availableQuantity);
    if (!Number.isInteger(n) || n < 0)
      return { error: "Quantity must be a whole number (0 or more)" };
    out.availableQuantity = n;
  }
  if (!partial)
    for (const k of ["name", "category", "price", "availableQuantity"])
      if (out[k] === undefined || out[k] === "")
        return { error: `${k} is required` };
  if (out.name === "") return { error: "name cannot be empty" };
  return { data: out };
};

app.param("id", (req, res, next, id) =>
  validId(id) ? next() : res.status(400).send({ message: "Invalid id" }),
);


const bearer = (req) => req.headers.authorization?.split(" ")[1];
const verifyToken = (req, res, next) => {
  const t = bearer(req);
  if (!t) return res.status(401).send({ message: "Unauthorized" });
  jwt.verify(t, process.env.JWT_SECRET, (e, d) => {
    if (e) return res.status(401).send({ message: "Invalid token" });
    req.user = d;
    next();
  });
};

const optionalAuth = (req, res, next) => {
  const t = bearer(req);
  if (!t) return next();
  jwt.verify(t, process.env.JWT_SECRET, (e, d) => {
    if (!e) req.user = d;
    next();
  });
};
const role = (r) => (req, res, next) =>
  req.user.role === r ? next() : res.status(403).send({ message: "Forbidden" });
const internal = (req, res, next) =>
  process.env.INTERNAL_KEY &&
  req.headers["x-internal-key"] === process.env.INTERNAL_KEY
    ? next()
    : res.status(403).send({ message: "Forbidden" });
const verifyRenter = role("customer"),
  verifyOwner = role("owner"),
  verifyAdmin = role("admin");


app.post("/users", internal, async (req, res) => {
  const { name, email, photo } = req.body;
  if (typeof email !== "string" || !email.includes("@"))
    return res.status(400).send({ message: "Valid email required" });
  await Users.updateOne(
    { email },
    {
      $setOnInsert: {
        name,
        email,
        photo,
        role: "customer",
        phone: "",
        address: "",
        createdAt: new Date(),
      },
    },
    { upsert: true },
  );
  res.send({ ok: true });
});
app.post("/jwt", internal, async (req, res) => {
  if (typeof req.body.email !== "string")
    return res.status(400).send({ message: "Email required" });
  const u = await Users.findOne({ email: req.body.email });
  if (!u) return res.status(404).send({ message: "User not found" });
  const token = jwt.sign(
    { email: u.email, role: u.role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" },
  );
  res.send({ token, role: u.role });
});
app.get("/users/me", verifyToken, async (req, res) =>
  res.send(await Users.findOne({ email: req.user.email })),
);
app.patch("/users/me", verifyToken, async (req, res) => {
  const set = {};
  for (const k of ["name", "photo", "phone", "address"])
    if (typeof req.body[k] === "string") set[k] = req.body[k].trim();
  if (!Object.keys(set).length)
    return res.status(400).send({ message: "Nothing to update" });
  await Users.updateOne({ email: req.user.email }, { $set: set });
  res.send({ ok: true });
});
app.get("/users", verifyToken, verifyAdmin, async (req, res) =>
  res.send(await Users.find().sort({ createdAt: -1 }).toArray()),
);
app.patch("/users/:id/role", verifyToken, verifyAdmin, async (req, res) => {
  if (!["customer", "owner", "admin"].includes(req.body.role))
    return res.status(400).send({ message: "Bad role" });
  const target = await Users.findOne({ _id: oid(req.params.id) });
  if (!target) return res.status(404).send({ message: "User not found" });
  if (target.email === req.user.email)
    return res.status(400).send({ message: "You cannot change your own role" });
  res.send(
    await Users.updateOne(
      { _id: oid(req.params.id) },
      { $set: { role: req.body.role } },
    ),
  );
});
app.delete("/users/:id", verifyToken, verifyAdmin, async (req, res) => {
  const target = await Users.findOne({ _id: oid(req.params.id) });
  if (!target) return res.status(404).send({ message: "User not found" });
  if (target.email === req.user.email)
    return res.status(400).send({ message: "You cannot delete yourself" });

  const ba = await db.collection("user").findOne({ email: target.email });
  if (ba) {
    const ids = [String(ba._id), ba._id];
    await db.collection("session").deleteMany({ userId: { $in: ids } });
    await db.collection("account").deleteMany({ userId: { $in: ids } });
    await db.collection("user").deleteOne({ _id: ba._id });
  }
  await Favs.deleteMany({ email: target.email });
  res.send(await Users.deleteOne({ _id: target._id }));
});

app.get("/equipment", async (req, res) => {
  const {
    search,
    category,
    rentalType,
    minPrice,
    maxPrice,
    available,
    sort,
    page = 1,
    limit = 9,
  } = req.query;
  const q = { status: "approved" };
  if (search) {
    const rx = escapeRx(String(search).trim().slice(0, 60));
    q.$or = [
      { name: { $regex: rx, $options: "i" } },
      { location: { $regex: rx, $options: "i" } },
      { category: { $regex: rx, $options: "i" } },
    ];
  }
  if (category) q.category = String(category);
  if (rentalType) q.rentalType = String(rentalType);
  if (minPrice || maxPrice)
    q.price = {
      ...(minPrice && { $gte: +minPrice }),
      ...(maxPrice && { $lte: +maxPrice }),
    };
  if (available === "true") q.availableQuantity = { $gt: 0 };
  if (available === "false") q.availableQuantity = 0;
  const s = { low: { price: 1 }, high: { price: -1 } }[sort] || {
    createdAt: -1,
  };
  const pg = Math.max(1, parseInt(page) || 1);
  const lim = Math.min(50, Math.max(1, parseInt(limit) || 9));
  const total = await Equip.countDocuments(q);
  const items = await Equip.find(q)
    .sort(s)
    .skip((pg - 1) * lim)
    .limit(lim)
    .toArray();
  res.send({ items, total, pages: Math.ceil(total / lim) });
});
app.get("/equipment/featured", async (req, res) =>
  res.send(
    await Equip.find({ status: "approved" })
      .sort({ createdAt: -1 })
      .limit(6)
      .toArray(),
  ),
);

app.get("/equipment/:id", optionalAuth, async (req, res) => {
  const e = await Equip.findOne({ _id: oid(req.params.id) });
  const u = req.user;
  const canSee =
    e &&
    (e.status === "approved" ||
      u?.role === "admin" ||
      (u && e.owner?.email === u.email));
  if (!canSee) return res.status(404).send({ message: "Equipment not found" });
  res.send(e);
});
app.post("/equipment", verifyToken, verifyOwner, async (req, res) => {
  const { data, error } = cleanEquip(req.body, { partial: false });
  if (error) return res.status(400).send({ message: error });
  const u = await Users.findOne({ email: req.user.email });
  if (!u) return res.status(404).send({ message: "User not found" });
  res.send(
    await Equip.insertOne({
      ...data,
      status: "pending",
      owner: { name: u.name, email: u.email, photo: u.photo },
      createdAt: new Date(),
    }),
  );
});
app.get("/my-equipment", verifyToken, verifyOwner, async (req, res) =>
  res.send(await Equip.find({ "owner.email": req.user.email }).toArray()),
);
app.put("/equipment/:id", verifyToken, async (req, res) => {
  if (!["owner", "admin"].includes(req.user.role))
    return res.status(403).send({ message: "Forbidden" });
  const f = {
    _id: oid(req.params.id),
    ...(req.user.role === "owner" && { "owner.email": req.user.email }),
  };
  const { data, error } = cleanEquip(req.body, { partial: true });
  if (error) return res.status(400).send({ message: error });
  if (!Object.keys(data).length)
    return res.status(400).send({ message: "Nothing to update" });
  res.send(await Equip.updateOne(f, { $set: data }));
});
app.delete("/equipment/:id", verifyToken, async (req, res) => {
  if (!["owner", "admin"].includes(req.user.role))
    return res.status(403).send({ message: "Forbidden" });
  const f = {
    _id: oid(req.params.id),
    ...(req.user.role === "owner" && { "owner.email": req.user.email }),
  };
  res.send(await Equip.deleteOne(f));
});
app.get("/admin/equipment", verifyToken, verifyAdmin, async (req, res) =>
  res.send(await Equip.find().sort({ createdAt: -1 }).toArray()),
);
app.patch(
  "/equipment/:id/status",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    if (!["pending", "approved", "rejected"].includes(req.body.status))
      return res.status(400).send({ message: "Bad status" });
    res.send(
      await Equip.updateOne(
        { _id: oid(req.params.id) },
        { $set: { status: req.body.status } },
      ),
    );
  },
);


app.post("/favorites", verifyToken, verifyRenter, async (req, res) => {
  const { equipmentId } = req.body;
  if (!validId(equipmentId))
    return res.status(400).send({ message: "Invalid equipment" });
  await Favs.updateOne(
    { email: req.user.email, equipmentId },
    {
      $setOnInsert: {
        email: req.user.email,
        equipmentId,
        createdAt: new Date(),
      },
    },
    { upsert: true },
  );
  res.send({ ok: true });
});
app.get("/favorites", verifyToken, verifyRenter, async (req, res) => {
  const f = await Favs.find({ email: req.user.email }).toArray();
  res.send(
    await Equip.find({
      _id: {
        $in: f
          .map((x) => x.equipmentId)
          .filter(validId)
          .map(oid),
      },
    }).toArray(),
  );
});
app.delete(
  "/favorites/:equipmentId",
  verifyToken,
  verifyRenter,
  async (req, res) =>
    res.send(
      await Favs.deleteOne({
        email: req.user.email,
        equipmentId: String(req.params.equipmentId),
      }),
    ),
);


const calcTotal = (eq, start, end, qty) => {
  const days = Math.max(
    1,
    Math.round((new Date(end) - new Date(start)) / 864e5) + 1,
  );
  const units =
    eq.rentalType === "Weekly"
      ? Math.ceil(days / 7)
      : eq.rentalType === "Monthly"
        ? Math.ceil(days / 30)
        : days;
  return eq.price * units * qty;
};
app.post(
  "/create-checkout-session",
  checkoutLimiter,
  verifyToken,
  verifyRenter,
  async (req, res) => {
    const b = req.body;
    if (!validId(b.equipmentId))
      return res.status(400).send({ message: "Invalid equipment" });
    const eq = await Equip.findOne({
      _id: oid(b.equipmentId),
      status: "approved",
    });
    if (!eq) return res.status(404).send({ message: "Equipment not found" });
    const qty = +b.quantity;
    if (!(new Date(b.startDate) <= new Date(b.endDate)))
      return res.status(400).send({ message: "Invalid dates" });
    if (!Number.isInteger(qty) || qty < 1 || qty > eq.availableQuantity)
      return res.status(400).send({ message: "Not enough quantity available" });
    const total = calcTotal(eq, b.startDate, b.endDate, qty);
    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      customer_email: req.user.email,
      line_items: [
        {
          quantity: 1,
          price_data: {
            currency: "usd",
            unit_amount: Math.round(total * 100),
            product_data: { name: eq.name },
          },
        },
      ],
      metadata: {
        equipmentId: b.equipmentId,
        startDate: b.startDate,
        endDate: b.endDate,
        quantity: String(qty),
        phone: b.phone || "",
        address: b.address || "",
        notes: (b.notes || "").slice(0, 400),
        email: req.user.email,
        total: String(total),
      },
      success_url: `${mainClient()}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${mainClient()}/equipment/${b.equipmentId}`,
    });
    res.send({ url: session.url });
  },
);

class Unfulfillable extends Error {}


const refundSession = async (s) => {
  try {
    await stripe.refunds.create(
      { payment_intent: s.payment_intent },
      { idempotencyKey: `refund_${s.id}` },
    );
    await Payments.updateOne(
      { sessionId: s.id },
      { $set: { status: PAY.REFUNDED, refundedAt: new Date() } },
    );
    return true;
  } catch (e) {
    console.error("Refund failed for session", s.id, e.message);
    return false; 
  }
};


const fulfill = async (s) => {
  const m = s.metadata || {};
  const existing = await Payments.findOne({ sessionId: s.id });
  if (existing) {
    if (existing.bookingId) return { bookingId: existing.bookingId };
    if (existing.status === PAY.NEEDS_REFUND) await refundSession(s);
    return { soldOut: true };
  }
  const qty = +m.quantity;
  const [eq, u] = await Promise.all([
    validId(m.equipmentId) ? Equip.findOne({ _id: oid(m.equipmentId) }) : null,
    Users.findOne({ email: m.email }),
  ]);
  const bookingId = new ObjectId();
  const base = {
    sessionId: s.id,
    transactionId: s.payment_intent,
    email: m.email,
    ownerEmail: eq?.owner?.email,
    amount: +m.total,
    createdAt: new Date(),
  };
  const dbSession = client.startSession();
  try {

    await dbSession.withTransaction(async () => {
      if (!eq || !u) throw new Unfulfillable();
      await Payments.insertOne(
        { ...base, status: PAY.PAID, bookingId },
        { session: dbSession },
      );
      const took = await Equip.updateOne(
        { _id: eq._id, availableQuantity: { $gte: qty } },
        { $inc: { availableQuantity: -qty } },
        { session: dbSession },
      );
      if (!took.modifiedCount) throw new Unfulfillable();
      await Bookings.insertOne(
        {
          _id: bookingId,
          sessionId: s.id,
          equipmentId: m.equipmentId,
          equipmentName: eq.name,
          equipmentImage: eq.image,
          owner: eq.owner,
          customer: { name: u.name, email: u.email, phone: m.phone },
          startDate: m.startDate,
          endDate: m.endDate,
          quantity: qty,
          address: m.address,
          notes: m.notes,
          totalAmount: +m.total,
          paymentStatus: PAY.PAID,
          bookingStatus: BOOKING.CONFIRMED,
          createdAt: new Date(),
        },
        { session: dbSession },
      );
    });
    return { bookingId };
  } catch (e) {
    if (e.code === 11000) {

      const old = await Payments.findOne({ sessionId: s.id });
      return old?.bookingId ? { bookingId: old.bookingId } : { soldOut: true };
    }
    if (!(e instanceof Unfulfillable)) throw e;
  } finally {
    await dbSession.endSession();
  }

  try {
    await Payments.insertOne({ ...base, status: PAY.NEEDS_REFUND });
  } catch (e) {
    if (e.code !== 11000) throw e;
  }
  await refundSession(s);
  return { soldOut: true };
};

app.post("/payments/confirm", verifyToken, verifyRenter, async (req, res) => {
  if (typeof req.body.sessionId !== "string")
    return res.status(400).send({ message: "sessionId required" });
  const s = await stripe.checkout.sessions.retrieve(req.body.sessionId);
  if (s.payment_status !== "paid" || s.metadata?.email !== req.user.email)
    return res.status(400).send({ message: "Payment not completed" });
  const r = await fulfill(s);
  if (r.soldOut)
    return res.status(409).send({
      message:
        "Equipment just ran out of stock. Your payment is being refunded.",
    });
  res.send({ bookingId: r.bookingId });
});
app.get("/my-bookings", verifyToken, verifyRenter, async (req, res) => {
  const pg = Math.max(1, parseInt(req.query.page) || 1);
  const lim = Math.min(50, Math.max(1, parseInt(req.query.limit) || 10));
  const q = { "customer.email": req.user.email };
  res.send({
    items: await Bookings.find(q)
      .sort({ createdAt: -1 })
      .skip((pg - 1) * lim)
      .limit(lim)
      .toArray(),
    total: await Bookings.countDocuments(q),
  });
});
app.get("/owner-bookings", verifyToken, verifyOwner, async (req, res) =>
  res.send(
    await Bookings.find({ "owner.email": req.user.email })
      .sort({ createdAt: -1 })
      .toArray(),
  ),
);
app.get("/admin/bookings", verifyToken, verifyAdmin, async (req, res) =>
  res.send(await Bookings.find().sort({ createdAt: -1 }).toArray()),
);

// refund a booking's payment (used when owner/admin cancels). Returns "refunded" | "failed" | "none"
const refundBooking = async (b) => {
  const p = await Payments.findOne({ bookingId: b._id });
  if (!p || p.status !== PAY.PAID) return "none";
  try {
    await stripe.refunds.create(
      { payment_intent: p.transactionId },
      { idempotencyKey: `refund_${p.sessionId}` },
    );
    await Payments.updateOne(
      { _id: p._id },
      { $set: { status: PAY.REFUNDED, refundedAt: new Date() } },
    );
    await Bookings.updateOne(
      { _id: b._id },
      { $set: { paymentStatus: PAY.REFUNDED } },
    );
    return "refunded";
  } catch (e) {
    console.error("Booking refund failed", String(b._id), e.message);
    await Bookings.updateOne(
      { _id: b._id },
      { $set: { paymentStatus: "refund_failed" } },
    );
    return "failed";
  }
};
app.patch("/bookings/:id/status", verifyToken, async (req, res) => {
  if (!["owner", "admin"].includes(req.user.role))
    return res.status(403).send({ message: "Forbidden" });
  const f = {
    _id: oid(req.params.id),
    ...(req.user.role === "owner" && { "owner.email": req.user.email }),
  };
  const st = req.body.status;
  if (!Object.values(BOOKING).includes(st))
    return res.status(400).send({ message: "Bad status" });
  const b = await Bookings.findOne(f);
  if (!b) return res.status(404).send({ message: "Not found" });
  if (st === b.bookingStatus) return res.send({ ok: true });
  // only a confirmed booking can move on; completed/cancelled are final
  if (b.bookingStatus !== BOOKING.CONFIRMED)
    return res
      .status(409)
      .send({ message: `Booking is already ${b.bookingStatus}` });
  // atomic claim, so a double click can never release the stock twice
  const claimed = await Bookings.updateOne(
    { _id: b._id, bookingStatus: BOOKING.CONFIRMED },
    { $set: { bookingStatus: st } },
  );
  if (!claimed.modifiedCount)
    return res.status(409).send({ message: "Booking was just updated" });
  await releaseStock(b);
  let refund = "none";
  if (st === BOOKING.CANCELLED) refund = await refundBooking(b);
  if (st === BOOKING.COMPLETED) notify(b);
  res.send({ ok: true, refund });
});

// ---------- analytics ----------
const monthly = (field) => [
  {
    $group: {
      _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
      ...field,
    },
  },
  { $sort: { _id: 1 } },
];
app.get("/analytics/admin", verifyToken, verifyAdmin, async (req, res) => {
  const [users, equipment, bookings, pending, completed, rev, monthlyBookings] =
    await Promise.all([
      Users.countDocuments(),
      Equip.countDocuments(),
      Bookings.countDocuments(),
      Equip.countDocuments({ status: "pending" }),
      Bookings.countDocuments({ bookingStatus: BOOKING.COMPLETED }),
      Payments.aggregate([
        { $match: { status: PAY.PAID } }, // refunded money is not revenue
        { $group: { _id: null, t: { $sum: "$amount" } } },
      ]).toArray(),
      Bookings.aggregate(monthly({ count: { $sum: 1 } })).toArray(),
    ]);
  res.send({
    users,
    equipment,
    bookings,
    pending,
    completed,
    revenue: rev[0]?.t || 0,
    monthlyBookings: monthlyBookings.map((m) => ({
      month: m._id,
      bookings: m.count,
    })),
  });
});
app.get("/analytics/owner", verifyToken, verifyOwner, async (req, res) => {
  const e = req.user.email;
  const paid = { $match: { ownerEmail: e, status: PAY.PAID } };
  const [listed, completed, earn, me] = await Promise.all([
    Equip.countDocuments({ "owner.email": e }),
    Bookings.countDocuments({
      "owner.email": e,
      bookingStatus: BOOKING.COMPLETED,
    }),
    Payments.aggregate([
      paid,
      { $group: { _id: null, t: { $sum: "$amount" } } },
    ]).toArray(),
    Payments.aggregate([
      paid,
      ...monthly({ earnings: { $sum: "$amount" } }),
    ]).toArray(),
  ]);
  res.send({
    listed,
    completed,
    totalEarnings: earn[0]?.t || 0,
    monthlyEarnings: me.map((m) => ({ month: m._id, earnings: m.earnings })),
  });
});
app.get("/analytics/customer", verifyToken, verifyRenter, async (req, res) => {
  const e = req.user.email,
    m = [
      {
        $match: { "customer.email": e, paymentStatus: { $ne: PAY.REFUNDED } },
      },
    ];
  const [bookings, sp, mo] = await Promise.all([
    Bookings.countDocuments({ "customer.email": e }),
    Bookings.aggregate([
      ...m,
      { $group: { _id: null, t: { $sum: "$totalAmount" } } },
    ]).toArray(),
    Bookings.aggregate([
      ...m,
      ...monthly({ spent: { $sum: "$totalAmount" } }),
    ]).toArray(),
  ]);
  res.send({
    bookings,
    spent: sp[0]?.t || 0,
    monthlySpending: mo.map((x) => ({ month: x._id, spent: x.spent })),
  });
});

// ---------- cron ----------
const completeDue = async () => {
  const due = await Bookings.find({
    bookingStatus: BOOKING.CONFIRMED,
    endDate: { $lt: todayStr() },
  }).toArray();
  let n = 0;
  for (const b of due) {
    const claimed = await Bookings.updateOne(
      { _id: b._id, bookingStatus: BOOKING.CONFIRMED },
      { $set: { bookingStatus: BOOKING.COMPLETED } },
    );
    if (!claimed.modifiedCount) continue; // someone else just changed it
    await releaseStock(b);
    notify(b);
    n++;
  }
  return n;
};
app.get("/cron/complete", async (req, res) => {
  if (
    !process.env.CRON_SECRET ||
    req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`
  )
    return res.status(401).send({ message: "Unauthorized" });
  res.send({ completed: await completeDue() });
});
// node-cron only makes sense on a long-running server; on Vercel the /cron/complete endpoint is hit by Vercel Cron
if (!process.env.VERCEL)
  cron.schedule("0 0 * * *", () => completeDue().catch(console.error), {
    timezone: TZ,
  });

// ---------- fallbacks ----------
app.get("/", (_, res) => res.send("Equipment Rental API running"));
app.use((req, res) => res.status(404).send({ message: "Route not found" }));
app.use((err, req, res, next) => {
  console.error(err);
  // only expose messages of safe client errors (e.g. bad JSON); never internal ones
  if (err.expose && err.status >= 400 && err.status < 500)
    return res.status(err.status).send({ message: err.message });
  res.status(500).send({ message: "Server error" });
});

// ---------- startup ----------
const ensureIndex = (col, spec, opts) =>
  col
    .createIndex(spec, opts)
    .catch((e) =>
      console.error(
        "Index failed:",
        col.collectionName,
        JSON.stringify(spec),
        e.message,
      ),
    );

ready = client.connect().then(async () => {
  db = client.db("equipmentRental");
  [Users, Equip, Bookings, Payments, Favs] = [
    "users",
    "equipment",
    "bookings",
    "payments",
    "favorites",
  ].map((c) => db.collection(c));
  await Promise.all([
    ensureIndex(Payments, { sessionId: 1 }, { unique: true }),
    ensureIndex(Payments, { ownerEmail: 1, status: 1 }),
    ensureIndex(Payments, { bookingId: 1 }),
    ensureIndex(Users, { email: 1 }, { unique: true }),
    ensureIndex(Equip, { status: 1, createdAt: -1 }),
    ensureIndex(Equip, { "owner.email": 1 }),
    ensureIndex(Bookings, { "customer.email": 1, createdAt: -1 }),
    ensureIndex(Bookings, { "owner.email": 1, createdAt: -1 }),
    ensureIndex(Bookings, { bookingStatus: 1, endDate: 1 }),
    ensureIndex(
      Bookings,
      { sessionId: 1 },
      {
        unique: true,
        partialFilterExpression: { sessionId: { $type: "string" } },
      },
    ),
    ensureIndex(Favs, { email: 1, equipmentId: 1 }, { unique: true }),
  ]);
  if (!process.env.VERCEL)
    app.listen(process.env.PORT || 5000, () => console.log("Server up"));
});
module.exports = app;
