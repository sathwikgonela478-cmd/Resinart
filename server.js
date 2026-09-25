const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 3000);
const ADMIN_EMAIL = "sathwikgonela478@gmail.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "ChangeThisAdminPassword!";
const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");
const sessions = new Map();
const resetTokens = new Map();

const defaultProducts = [
  {
    id: 1,
    name: "Ocean Wave Coaster Set",
    category: "Home decor",
    price: 899,
    tag: "Bestseller",
    desc: "Four coasters with a soft blue wave and gold edge.",
    image:
      "https://images.unsplash.com/photo-1610701596007-11502861dcfa?auto=format&fit=crop&w=700&q=85",
  },
  {
    id: 2,
    name: "Sunset Trinket Tray",
    category: "Home decor",
    price: 749,
    tag: "New",
    desc: "A little tray for rings, keys and beautiful bits.",
    image:
      "https://images.unsplash.com/photo-1618220179428-22790b461013?auto=format&fit=crop&w=700&q=85",
  },
  {
    id: 3,
    name: "Petal Drop Earrings",
    category: "Jewellery",
    price: 499,
    tag: "Handmade",
    desc: "Light-catching floral drops for your everyday.",
    image:
      "https://images.unsplash.com/photo-1535632066927-ab7c9ab60908?auto=format&fit=crop&w=700&q=85",
  },
  {
    id: 4,
    name: "Moonlit Blue Bookmark",
    category: "Gifts",
    price: 299,
    tag: "Gift idea",
    desc: "A thoughtful little gift for the reader in your life.",
    image:
      "https://images.unsplash.com/photo-1544947950-fa07a98d237f?auto=format&fit=crop&w=700&q=85",
  },
];

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  return { salt, hash: crypto.scryptSync(password, salt, 64).toString("hex") };
}
function checkPassword(password, user) {
  const actual = crypto.scryptSync(password, user.salt, 64).toString("hex");
  return crypto.timingSafeEqual(
    Buffer.from(actual, "hex"),
    Buffer.from(user.hash, "hex"),
  );
}
function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}
function normalizePhone(phone) {
  return String(phone || "")
    .trim()
    .replace(/[\s()-]/g, "");
}
function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function validPhone(phone) {
  return /^\+[1-9]\d{7,14}$/.test(phone);
}
function json(res, status, body) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
  });
  res.end(JSON.stringify(body));
}
function readDb() {
  if (!fs.existsSync(DB_FILE)) return { users: [], products: defaultProducts };
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}
function writeDb(db) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    role: user.role,
  };
}
function token() {
  return crypto.randomBytes(32).toString("hex");
}
function auth(req, db) {
  const value = req.headers.authorization || "";
  const userId = sessions.get(value.replace(/^Bearer\s+/i, ""));
  return db.users.find((user) => user.id === userId) || null;
}
async function body(req) {
  let raw = "";
  for await (const chunk of req) raw += chunk;
  try {
    return raw ? JSON.parse(raw) : {};
  } catch {
    return null;
  }
}
function sendFile(req, res, pathname) {
  const file = pathname === "/" ? "index.html" : pathname.slice(1);
  const safe = path.normalize(file).replace(/^\.\.(?:[\\/]|$)/, "");
  const full = path.join(__dirname, safe);
  if (
    !full.startsWith(__dirname) ||
    !fs.existsSync(full) ||
    fs.statSync(full).isDirectory()
  )
    return json(res, 404, { error: "Not found" });
  const ext = path.extname(full);
  const types = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".svg": "image/svg+xml",
  };
  res.writeHead(200, {
    "Content-Type": types[ext] || "application/octet-stream",
  });
  fs.createReadStream(full).pipe(res);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const db = readDb();
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
    });
    return res.end();
  }
  if (!url.pathname.startsWith("/api/"))
    return sendFile(req, res, url.pathname);
  if (req.method === "GET" && url.pathname === "/api/products")
    return json(res, 200, { products: db.products });
  if (req.method === "POST" && url.pathname === "/api/auth/register") {
    const data = await body(req);
    if (!data) return json(res, 400, { error: "Invalid request." });
    const email = normalizeEmail(data.email),
      phone = normalizePhone(data.phone);
    if (!data.name || data.name.trim().length < 2)
      return json(res, 400, { error: "Enter your full name." });
    if (!validEmail(email))
      return json(res, 400, { error: "Enter a valid email address." });
    if (!validPhone(phone))
      return json(res, 400, {
        error: "Use international format, for example +919000430210.",
      });
    if (typeof data.password !== "string" || data.password.length < 8)
      return json(res, 400, {
        error: "Password must be at least 8 characters.",
      });
    if (db.users.some((user) => user.email === email || user.phone === phone))
      return json(res, 409, {
        error: "That email or mobile number is already registered.",
      });
    const credentials = hashPassword(data.password);
    const user = {
      id: crypto.randomUUID(),
      name: data.name.trim(),
      email,
      phone,
      role: email === ADMIN_EMAIL ? "admin" : "customer",
      cart: {},
      profile: {},
      orders: [],
      ...credentials,
      createdAt: new Date().toISOString(),
    };
    db.users.push(user);
    writeDb(db);
    const session = token();
    sessions.set(session, user.id);
    return json(res, 201, { token: session, user: publicUser(user) });
  }
  if (req.method === "POST" && url.pathname === "/api/auth/login") {
    const data = await body(req);
    const identifier = String(
      (data && (data.identifier || data.email || data.phone)) || "",
    )
      .trim()
      .toLowerCase();
    const user = db.users.find(
      (item) => item.email === identifier || item.phone === identifier,
    );
    if (!user || !checkPassword(String(data.password || ""), user))
      return json(res, 401, {
        error: "Email/mobile number or password is incorrect.",
      });
    const session = token();
    sessions.set(session, user.id);
    return json(res, 200, { token: session, user: publicUser(user) });
  }
  if (req.method === "POST" && url.pathname === "/api/auth/forgot") {
    const data = await body(req);
    const identifier = String((data && data.identifier) || "")
      .trim()
      .toLowerCase();
    const user = db.users.find(
      (item) => item.email === identifier || item.phone === identifier,
    );
    const response = {
      message: "If an account matches, reset instructions have been created.",
    };
    if (user) {
      const reset = token();
      resetTokens.set(reset, {
        userId: user.id,
        expires: Date.now() + 15 * 60 * 1000,
      });
      if (process.env.NODE_ENV !== "production")
        response.developmentResetToken = reset;
    }
    return json(res, 200, response);
  }
  if (req.method === "POST" && url.pathname === "/api/auth/reset") {
    const data = await body(req);
    const record = resetTokens.get(data && data.token);
    if (!record || record.expires < Date.now())
      return json(res, 400, { error: "Reset token is invalid or expired." });
    if (typeof data.password !== "string" || data.password.length < 8)
      return json(res, 400, {
        error: "Password must be at least 8 characters.",
      });
    const user = db.users.find((item) => item.id === record.userId);
    Object.assign(user, hashPassword(data.password));
    writeDb(db);
    resetTokens.delete(data.token);
    return json(res, 200, { message: "Password reset successfully." });
  }
  const user = auth(req, db);
  if (req.method === "GET" && url.pathname === "/api/auth/me")
    return user
      ? json(res, 200, { user: publicUser(user) })
      : json(res, 401, { error: "Not signed in." });
  if (!user) return json(res, 401, { error: "Sign in required." });
  if (url.pathname.startsWith("/api/admin/") && user.role !== "admin")
    return json(res, 403, { error: "Admin access required." });
  if (req.method === "POST" && url.pathname === "/api/auth/logout") {
    sessions.delete(
      (req.headers.authorization || "").replace(/^Bearer\s+/i, ""),
    );
    return json(res, 200, { message: "Signed out." });
  }
  if (req.method === "GET" && url.pathname === "/api/me/cart")
    return json(res, 200, { cart: user.cart || {} });
  if (req.method === "PATCH" && url.pathname === "/api/me/cart") {
    const data = await body(req);
    if (!data || typeof data.cart !== "object" || Array.isArray(data.cart))
      return json(res, 400, { error: "Invalid cart data." });
    user.cart = Object.fromEntries(
      Object.entries(data.cart)
        .filter(
          ([id, quantity]) =>
            /^\d+$/.test(id) && Number.isInteger(quantity) && quantity > 0,
        )
        .map(([id, quantity]) => [id, Math.min(quantity, 99)]),
    );
    writeDb(db);
    return json(res, 200, { cart: user.cart });
  }
  if (req.method === "GET" && url.pathname === "/api/me/profile")
    return json(res, 200, { profile: user.profile || {} });
  if (req.method === "PATCH" && url.pathname === "/api/me/profile") {
    const data = await body(req);
    const required = [
      "name",
      "email",
      "phone",
      "country",
      "address",
      "city",
      "state",
      "postal",
    ];
    if (
      !data ||
      required.some(
        (field) => typeof data[field] !== "string" || !data[field].trim(),
      )
    )
      return json(res, 400, { error: "All delivery details are required." });
    if (
      !validEmail(data.email.trim().toLowerCase()) ||
      !validPhone(normalizePhone(data.phone))
    )
      return json(res, 400, {
        error: "Enter a valid email and international phone number.",
      });
    user.profile = {
      name: data.name.trim(),
      email: data.email.trim().toLowerCase(),
      phone: normalizePhone(data.phone),
      country: data.country.trim(),
      address: data.address.trim(),
      city: data.city.trim(),
      state: data.state.trim(),
      postal: data.postal.trim(),
    };
    writeDb(db);
    return json(res, 200, { profile: user.profile });
  }
  if (req.method === "GET" && url.pathname === "/api/me/orders")
    return json(res, 200, { orders: user.orders || [] });
  if (req.method === "POST" && url.pathname === "/api/me/orders") {
    const data = await body(req);
    if (
      !data ||
      !Array.isArray(data.items) ||
      !data.items.length ||
      !data.profile ||
      !Number(data.total)
    )
      return json(res, 400, {
        error: "A complete order and delivery profile are required.",
      });
    const order = {
      id: `SRA-${Date.now()}`,
      items: data.items,
      total: Number(data.total),
      profile: data.profile,
      createdAt: new Date().toISOString(),
      status: "WhatsApp pending",
    };
    user.orders = [...(user.orders || []), order];
    user.profile = data.profile;
    writeDb(db);
    return json(res, 201, { order });
  }
  if (req.method === "POST" && url.pathname === "/api/admin/products") {
    const data = await body(req);
    if (!data.name || !Number(data.price))
      return json(res, 400, { error: "Product name and price are required." });
    const product = {
      id: Date.now(),
      name: data.name.trim(),
      category: data.category || "Home decor",
      price: Number(data.price),
      tag: data.tag || "New",
      desc: data.desc || "Made with care by Swapna.",
      image: data.image || defaultProducts[0].image,
    };
    db.products.push(product);
    writeDb(db);
    return json(res, 201, { product });
  }
  if (
    req.method === "PATCH" &&
    url.pathname.startsWith("/api/admin/products/")
  ) {
    const product = db.products.find(
      (item) => item.id === Number(url.pathname.split("/").pop()),
    );
    if (!product) return json(res, 404, { error: "Product not found." });
    const data = await body(req);
    Object.assign(product, {
      ...data,
      price: data.price === undefined ? product.price : Number(data.price),
    });
    writeDb(db);
    return json(res, 200, { product });
  }
  if (
    req.method === "DELETE" &&
    url.pathname.startsWith("/api/admin/products/")
  ) {
    db.products = db.products.filter(
      (item) => item.id !== Number(url.pathname.split("/").pop()),
    );
    writeDb(db);
    return json(res, 200, { message: "Product removed." });
  }
  return json(res, 404, { error: "API route not found." });
});

const db = readDb();
if (!db.users.some((user) => user.email === ADMIN_EMAIL)) {
  const credentials = hashPassword(ADMIN_PASSWORD);
  db.users.push({
    id: crypto.randomUUID(),
    name: "Swapna Admin",
    email: ADMIN_EMAIL,
    phone: "",
    role: "admin",
    cart: {},
    profile: {},
    orders: [],
    ...credentials,
    createdAt: new Date().toISOString(),
  });
  writeDb(db);
}
server.listen(PORT, () =>
  console.log(`Swapna's Resinart running at http://localhost:${PORT}`),
);
