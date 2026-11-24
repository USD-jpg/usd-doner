require("dotenv").config();
const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const morgan = require("morgan");
const webpush = require("web-push");
const {OAuth2Client} = require("google-auth-library");

const app = express();
const googleClient = process.env.GOOGLE_CLIENT_ID ? new OAuth2Client(process.env.GOOGLE_CLIENT_ID) : null;
const PORT = process.env.PORT || 3000;
if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY && process.env.VAPID_SUBJECT) {
  webpush.setVapidDetails(process.env.VAPID_SUBJECT, process.env.VAPID_PUBLIC_KEY, process.env.VAPID_PRIVATE_KEY);
}
async function sendPush(payload) {
  if (!process.env.VAPID_PUBLIC_KEY || !process.env.VAPID_PRIVATE_KEY || !process.env.VAPID_SUBJECT) return;
  const rows=db.prepare("SELECT endpoint,subscription_json FROM push_subscriptions").all();
  for (const row of rows) { try { await webpush.sendNotification(JSON.parse(row.subscription_json),JSON.stringify(payload)); } catch(e) { if (e.statusCode===404 || e.statusCode===410) db.prepare("DELETE FROM push_subscriptions WHERE endpoint=?").run(row.endpoint); } }
}
const databasePath = process.env.DB_PATH || path.join(__dirname, "usd-doner.sqlite");
fs.mkdirSync(path.dirname(databasePath), { recursive: true });
const db = new Database(databasePath);
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_code TEXT UNIQUE NOT NULL,
  customer_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  address TEXT,
  fulfillment TEXT NOT NULL,
  items_json TEXT NOT NULL,
  note TEXT,
  courier_note TEXT,
  total INTEGER NOT NULL,
  payment_method TEXT,
  payment_status TEXT DEFAULT 'pending',
  status TEXT DEFAULT 'pending',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  discount INTEGER DEFAULT 0,
  promo_code TEXT,
  customer_id INTEGER
);
CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT UNIQUE,
  email TEXT,
  google_sub TEXT UNIQUE,
  password_salt TEXT,
  password_hash TEXT,
  phone_verified INTEGER DEFAULT 0,
  bonus_credit INTEGER DEFAULT 0,
  referral_code TEXT UNIQUE,
  referred_by TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS promos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,
  discount_percent INTEGER NOT NULL,
  active INTEGER DEFAULT 1,
  usage_limit INTEGER DEFAULT 0,
  used_count INTEGER DEFAULT 0,
  expires_at TEXT
);
CREATE TABLE IF NOT EXISTS push_subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  endpoint TEXT UNIQUE NOT NULL,
  subscription_json TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);
// Safe schema upgrades for existing databases.
for (const [name, definition] of [["discount","INTEGER DEFAULT 0"],["promo_code","TEXT"],["customer_id","INTEGER"]]) {
  try { db.exec(`ALTER TABLE orders ADD COLUMN ${name} ${definition}`); } catch (e) { if (!String(e.message).includes("duplicate column")) throw e; }
}
app.use(helmet({contentSecurityPolicy:false}));
app.use(morgan("tiny"));
app.use(express.json({limit:"1mb"}));
app.use(express.static(path.join(__dirname,"public")));

const menuPath = path.join(__dirname,"data","menu.json");
let menu = JSON.parse(fs.readFileSync(menuPath,"utf8"));
const sessions = new Map();
const customerSessions = new Map();
const loginAttempts = new Map();
const customerLoginAttempts = new Map();
const ORDER_STATUSES = ["pending","paid","preparing","on_delivery","delivered"];
const STATUS_LABELS = {pending:"Төлем күтілуде",paid:"Төлем қабылданды",preparing:"Дайындалуда",on_delivery:"Жеткізу үстінде",delivered:"Жеткізілді"};

function safeEqual(a,b){
  const aa=Buffer.from(String(a)); const bb=Buffer.from(String(b));
  return aa.length===bb.length && crypto.timingSafeEqual(aa,bb);
}
function adminAuth(req,res,next){
  const token=req.cookies?.usd_admin_session || (req.headers.cookie||"").split(";").map(x=>x.trim()).find(x=>x.startsWith("usd_admin_session="))?.slice("usd_admin_session=".length);
  const session=token && sessions.get(token);
  if(!session || session.expires<Date.now()){
    if(token) sessions.delete(token);
    return res.status(401).json({error:"Әкімші аккаунтына кіріңіз"});
  }
  session.expires=Date.now()+8*60*60*1000;
  next();
}
function getCookie(req,name){return (req.headers.cookie||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(name+"="))?.slice(name.length+1);}
function currentCustomer(req){const token=getCookie(req,"usd_customer_session");const session=token&&customerSessions.get(token);if(!session||session.expires<Date.now()){if(token)customerSessions.delete(token);return null;}session.expires=Date.now()+30*24*60*60*1000;return db.prepare("SELECT id,name,phone,email,phone_verified,bonus_credit,referral_code FROM customers WHERE id=?").get(session.customerId)||null;}
function customerAuth(req,res,next){req.customer=currentCustomer(req);if(!req.customer)return res.status(401).json({error:"Аккаунтқа кіріңіз"});next();}
function setCustomerSession(res,id){const token=crypto.randomBytes(32).toString("hex");customerSessions.set(token,{customerId:id,expires:Date.now()+30*24*60*60*1000});res.setHeader("Set-Cookie",`usd_customer_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000${process.env.NODE_ENV==="production"?"; Secure":""}`);}
function parseOrder(row){
  return {...row,items:JSON.parse(row.items_json||"[]").map(it=>({...it,name:menu.find(m=>m.id===it.id)?.name||it.id})),status_label:STATUS_LABELS[row.status]||row.status};
}
app.get("/api/health", (_req,res)=>res.json({ok:true,service:"USD Doner API"}));
app.get("/api/menu", (_req,res)=>res.json(menu));
app.post("/api/orders", (req,res)=>{
  const {customerName,phone,address,fulfillment,items,note,courierNote,paymentMethod} = req.body || {};
  const signedInCustomer=currentCustomer(req);
  if(!customerName || !phone || !["delivery","pickup"].includes(fulfillment) || !["kaspi","halyk"].includes(paymentMethod||"kaspi") || !Array.isArray(items) || !items.length || items.length>100)
    return res.status(400).json({error:"Тапсырыс деректері толық емес"});
  const cleanItems=[]; let total=0;
  for(const entry of items){
    const product=menu.find(x=>x.id===entry.id); const qty=Number(entry.qty);
    if(!product || !Number.isInteger(qty) || qty<1 || qty>50) return res.status(400).json({error:"Тапсырыстағы тағам немесе саны дұрыс емес"});
    let variantName="", unitPrice=Number(product.price);
    if(Array.isArray(product.variants)&&product.variants.length){const variant=product.variants.find(v=>v.name===entry.variant);if(!variant)return res.status(400).json({error:"Тағам нұсқасын таңдаңыз"});variantName=variant.name;unitPrice=Number(variant.price);}
    total+=unitPrice*qty; cleanItems.push({id:product.id,name:product.name,variant:variantName,price:unitPrice,qty});
  }
  let discount = 0, promoCode = null;
  if (req.body?.promoCode) {
    const promo = db.prepare("SELECT * FROM promos WHERE code=? AND active=1").get(String(req.body.promoCode).trim().toUpperCase());
    if (!promo || (promo.usage_limit > 0 && promo.used_count >= promo.usage_limit) || (promo.expires_at && new Date(promo.expires_at) < new Date()))
      return res.status(400).json({error:"Промокод жарамсыз немесе мерзімі өткен"});
    discount = Math.min(total, Math.floor(total * promo.discount_percent / 100));
    total -= discount; promoCode = promo.code;
  }
  const next = db.prepare("SELECT COALESCE(MAX(id),1000)+1 AS n FROM orders").get().n;
  const code = `USD-${next}`;
  const result = db.prepare(`INSERT INTO orders
    (order_code,customer_name,phone,address,fulfillment,items_json,note,courier_note,total,payment_method,discount,promo_code,customer_id)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(code,customerName,phone,address||"",fulfillment,JSON.stringify(cleanItems),note||"",courierNote||"",total,paymentMethod||"kaspi",discount,promoCode,signedInCustomer?.id||null);
  if (promoCode) db.prepare("UPDATE promos SET used_count=used_count+1 WHERE code=?").run(promoCode);
  res.status(201).json({ok:true,orderId:result.lastInsertRowid,orderCode:code,status:"pending",total,discount,promoCode});
});
// Customer accounts. Phone verification is deliberately separate: no bonus is granted before an SMS provider verifies the number.
app.get("/api/public/config",(_req,res)=>res.json({googleClientId:process.env.GOOGLE_CLIENT_ID||null}));
app.post("/api/customer/register",(req,res)=>{const name=String(req.body?.name||"").trim();const phone=String(req.body?.phone||"").trim();const password=String(req.body?.password||"");const normalized=phone.replace(/\D/g,"");if(name.length<2||normalized.length<10||password.length<8)return res.status(400).json({error:"Аты-жөніңізді, телефонды және кемінде 8 таңбалы құпиясөзді енгізіңіз"});const salt=crypto.randomBytes(16).toString("hex");const hash=crypto.scryptSync(password,salt,64).toString("hex");const referral=crypto.randomBytes(4).toString("hex").toUpperCase();const referredBy=req.body?.referralCode?String(req.body.referralCode).trim().toUpperCase():null;if(referredBy&&!db.prepare("SELECT id FROM customers WHERE referral_code=?").get(referredBy))return res.status(400).json({error:"Реферал коды табылмады"});try{const r=db.prepare("INSERT INTO customers(name,phone,password_salt,password_hash,referral_code,referred_by) VALUES(?,?,?,?,?,?)").run(name,normalized,salt,hash,referral,referredBy);setCustomerSession(res,r.lastInsertRowid);res.status(201).json({ok:true,customer:db.prepare("SELECT id,name,phone,phone_verified,bonus_credit,referral_code FROM customers WHERE id=?").get(r.lastInsertRowid)});}catch(e){res.status(409).json({error:"Бұл телефон нөмірімен аккаунт бар"});}});
app.post("/api/customer/login",(req,res)=>{const ip=req.ip||req.socket.remoteAddress||"unknown";const attempt=customerLoginAttempts.get(ip)||{count:0,until:0};if(attempt.until>Date.now())return res.status(429).json({error:"Көп рет қате енгізілді. 10 минуттан кейін қайталаңыз."});const phone=String(req.body?.phone||"").replace(/\D/g,"");const rows=db.prepare("SELECT * FROM customers").all();const customer=rows.find(x=>String(x.phone||"").replace(/\D/g,"")===phone);const password=String(req.body?.password||"");if(!customer||!customer.password_hash||!safeEqual(crypto.scryptSync(password,customer.password_salt,64).toString("hex"),customer.password_hash)){attempt.count++;if(attempt.count>=5){attempt.count=0;attempt.until=Date.now()+10*60*1000;}customerLoginAttempts.set(ip,attempt);return res.status(401).json({error:"Телефон немесе құпиясөз қате"});}customerLoginAttempts.delete(ip);setCustomerSession(res,customer.id);res.json({ok:true,customer:{id:customer.id,name:customer.name,phone:customer.phone,phone_verified:customer.phone_verified,bonus_credit:customer.bonus_credit,referral_code:customer.referral_code}});});
app.post("/api/customer/google",async(req,res)=>{if(!googleClient)return res.status(503).json({error:"Google кіруі үшін GOOGLE_CLIENT_ID бапталмаған"});try{const ticket=await googleClient.verifyIdToken({idToken:String(req.body?.credential||""),audience:process.env.GOOGLE_CLIENT_ID});const g=ticket.getPayload();let customer=db.prepare("SELECT * FROM customers WHERE google_sub=?").get(g.sub);if(!customer){const referral=crypto.randomBytes(4).toString("hex").toUpperCase();const r=db.prepare("INSERT INTO customers(name,email,google_sub,referral_code) VALUES(?,?,?,?)").run(g.name||"Google user",g.email||null,g.sub,referral);customer=db.prepare("SELECT * FROM customers WHERE id=?").get(r.lastInsertRowid);}setCustomerSession(res,customer.id);res.json({ok:true,customer:{id:customer.id,name:customer.name,phone:customer.phone,phone_verified:customer.phone_verified,bonus_credit:customer.bonus_credit,referral_code:customer.referral_code}});}catch(e){res.status(401).json({error:"Google арқылы кіру сәтсіз аяқталды"});}});
app.get("/api/customer/me",customerAuth,(req,res)=>res.json({customer:req.customer}));
app.get("/api/customer/orders",customerAuth,(req,res)=>res.json(db.prepare("SELECT order_code,total,status,payment_status,created_at FROM orders WHERE customer_id=? ORDER BY id DESC LIMIT 50").all(req.customer.id)));
app.post("/api/customer/logout",(req,res)=>{const token=getCookie(req,"usd_customer_session");if(token)customerSessions.delete(token);res.setHeader("Set-Cookie","usd_customer_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");res.json({ok:true});});
// Public order lookup and promo validation.
app.post("/api/promos/validate",(req,res)=>{
  const code=String(req.body?.code||"").trim().toUpperCase();
  const subtotal=Number(req.body?.subtotal);
  if(!code || !Number.isInteger(subtotal) || subtotal<0) return res.status(400).json({error:"Промокод пен сома дұрыс емес"});
  const promo=db.prepare("SELECT * FROM promos WHERE code=? AND active=1").get(code);
  if(!promo || (promo.usage_limit>0 && promo.used_count>=promo.usage_limit) || (promo.expires_at && new Date(promo.expires_at)<new Date())) return res.status(404).json({error:"Промокод жарамсыз немесе мерзімі өткен"});
  res.json({ok:true,code,discountPercent:promo.discount_percent,discount:Math.floor(subtotal*promo.discount_percent/100)});
});
app.get("/api/orders/:code", (req,res)=>{ const order=db.prepare("SELECT * FROM orders WHERE order_code=?").get(req.params.code); if(!order) return res.status(404).json({error:"Тапсырыс табылмады"}); const normalize=x=>String(x||"").replace(/\D/g,""); if(!req.query.phone || normalize(req.query.phone)!==normalize(order.phone)) return res.status(403).json({error:"Телефон нөмірі сәйкес келмейді"}); order.items=JSON.parse(order.items_json); delete order.items_json; order.status_label=STATUS_LABELS[order.status]||order.status; res.json(order); });
app.get("/api/public/vapid-key",(_req,res)=>res.json({key:process.env.VAPID_PUBLIC_KEY||null}));
app.post("/api/push/subscribe",(req,res)=>{ const sub=req.body; if(!sub?.endpoint || !sub?.keys?.p256dh || !sub?.keys?.auth) return res.status(400).json({error:"Жазылым деректері қате"}); db.prepare("INSERT OR REPLACE INTO push_subscriptions(endpoint,subscription_json) VALUES(?,?)").run(sub.endpoint,JSON.stringify(sub)); res.json({ok:true}); });

// Admin login uses a scrypt hash; plaintext passwords are never stored.
app.post("/api/admin/login",(req,res)=>{
  const ip=req.ip || req.socket.remoteAddress || "unknown";
  const attempt=loginAttempts.get(ip) || {count:0,until:0};
  if(attempt.until>Date.now()) return res.status(429).json({error:"Көп әрекет жасалды. Біраздан соң қайталаңыз."});
  const password=String(req.body?.password||"");
  const stored=process.env.ADMIN_PASSWORD_HASH||""; // format: salt:hexHash
  const [salt,expected]=stored.split(":");
  if(!salt || !expected || !process.env.ADMIN_SESSION_SECRET){
    return res.status(503).json({error:"Әкімші құпиясөзі серверде бапталмаған. README нұсқаулығын қараңыз."});
  }
  const actual=crypto.scryptSync(password,salt,64).toString("hex");
  if(!safeEqual(actual,expected)){
    attempt.count++;
    if(attempt.count>=5){attempt.count=0;attempt.until=Date.now()+10*60*1000;}
    loginAttempts.set(ip,attempt);
    return res.status(401).json({error:"Құпиясөз қате"});
  }
  loginAttempts.delete(ip);
  const token=crypto.randomBytes(32).toString("hex");
  sessions.set(token,{expires:Date.now()+8*60*60*1000});
  res.setHeader("Set-Cookie",`usd_admin_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${process.env.NODE_ENV==="production"?"; Secure":""}`);
  res.json({ok:true});
});
app.post("/api/admin/logout",adminAuth,(req,res)=>{
  const token=(req.headers.cookie||"").split(";").map(x=>x.trim()).find(x=>x.startsWith("usd_admin_session="))?.slice("usd_admin_session=".length);
  if(token) sessions.delete(token);
  res.setHeader("Set-Cookie","usd_admin_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
  res.json({ok:true});
});
app.get("/api/admin/me",adminAuth,(_req,res)=>res.json({ok:true}));
app.get("/api/admin/orders",adminAuth,(req,res)=>{
  const limit=Math.min(Math.max(Number(req.query.limit)||100,1),500);
  const rows=db.prepare("SELECT * FROM orders ORDER BY id DESC LIMIT ?").all(limit).map(parseOrder);
  const stats=db.prepare(`SELECT COUNT(*) AS total, COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),0) AS waiting,
    COALESCE(SUM(CASE WHEN status='delivered' THEN 1 ELSE 0 END),0) AS delivered,
    COALESCE(SUM(CASE WHEN payment_status='paid' OR status IN ('paid','preparing','on_delivery','delivered') THEN total ELSE 0 END),0) AS revenue FROM orders`).get();
  res.json({orders:rows,stats});
});
app.patch("/api/admin/orders/:id/status",adminAuth,(req,res)=>{
  const {status,paymentStatus}=req.body||{};
  if(status!==undefined && !ORDER_STATUSES.includes(status)) return res.status(400).json({error:"Мәртебе дұрыс емес"});
  if(paymentStatus!==undefined && !["pending","paid","rejected"].includes(paymentStatus)) return res.status(400).json({error:"Төлем мәртебесі дұрыс емес"});
  const row=db.prepare("SELECT id FROM orders WHERE id=?").get(Number(req.params.id));
  if(!row) return res.status(404).json({error:"Тапсырыс табылмады"});
  if(status!==undefined) { db.prepare("UPDATE orders SET status=? WHERE id=?").run(status,row.id); const order=db.prepare("SELECT order_code FROM orders WHERE id=?").get(row.id); sendPush({title:"USD Doner · Тапсырыс",body:`${order.order_code}: ${STATUS_LABELS[status]}`,url:"/"}).catch(()=>{}); }
  if(paymentStatus!==undefined) { db.prepare("UPDATE orders SET payment_status=? WHERE id=?").run(paymentStatus,row.id); const order=db.prepare("SELECT order_code FROM orders WHERE id=?").get(row.id); sendPush({title:"USD Doner · Төлем",body:`${order.order_code}: ${paymentStatus==="paid"?"Төлем қабылданды":paymentStatus==="rejected"?"Төлем қабылданбады":"Төлем күтілуде"}`,url:"/"}).catch(()=>{}); }
  res.json({ok:true});
});
app.get("/api/admin/menu",adminAuth,(_req,res)=>res.json(menu));
app.patch("/api/admin/menu/:id",adminAuth,(req,res)=>{
  const item=menu.find(x=>x.id===req.params.id);
  if(!item) return res.status(404).json({error:"Тағам табылмады"});
  const price=Number(req.body?.price);
  if(!Number.isInteger(price)||price<0||price>1000000) return res.status(400).json({error:"Бағаны дұрыс енгізіңіз"});
  item.price=price;
  if(Array.isArray(item.variants) && Array.isArray(req.body?.variants)){
    for(const v of req.body.variants){
      const target=item.variants.find(x=>x.name===v.name);
      const p=Number(v.price);
      if(target && Number.isInteger(p)&&p>=0&&p<=1000000) target.price=p;
    }
  }
  fs.writeFileSync(menuPath,JSON.stringify(menu,null,2)+"\n");
  res.json({ok:true,item});
});
app.get("/api/admin/promos",adminAuth,(_req,res)=>res.json(db.prepare("SELECT * FROM promos ORDER BY id DESC").all()));
app.post("/api/admin/notifications",adminAuth,async(req,res)=>{ const title=String(req.body?.title||"USD Doner").slice(0,80); const body=String(req.body?.body||"").slice(0,180); if(!body) return res.status(400).json({error:"Хабарлама мәтінін енгізіңіз"}); if(!process.env.VAPID_PUBLIC_KEY) return res.status(503).json({error:"Push-хабарлама кілттері бапталмаған. README нұсқаулығын қараңыз."}); await sendPush({title,body,url:"/"}); res.json({ok:true}); });
app.post("/api/admin/promos",adminAuth,(req,res)=>{ const code=String(req.body?.code||"").trim().toUpperCase().replace(/[^A-Z0-9_-]/g,""); const pct=Number(req.body?.discountPercent); const limit=Number(req.body?.usageLimit||0); const expires=req.body?.expiresAt||null; if(code.length<3 || !Number.isInteger(pct)||pct<1||pct>100||!Number.isInteger(limit)||limit<0) return res.status(400).json({error:"Промокод деректері дұрыс емес"}); try { const r=db.prepare("INSERT INTO promos(code,discount_percent,usage_limit,expires_at) VALUES(?,?,?,?)").run(code,pct,limit,expires); res.status(201).json({ok:true,id:r.lastInsertRowid}); } catch(e) { res.status(409).json({error:"Бұл промокод бұрыннан бар"}); } });
app.patch("/api/admin/promos/:id",adminAuth,(req,res)=>{ const active=req.body?.active?1:0; const r=db.prepare("UPDATE promos SET active=? WHERE id=?").run(active,Number(req.params.id)); if(!r.changes) return res.status(404).json({error:"Промокод табылмады"}); res.json({ok:true}); });
app.delete("/api/admin/promos/:id",adminAuth,(req,res)=>{ const r=db.prepare("DELETE FROM promos WHERE id=?").run(Number(req.params.id)); if(!r.changes) return res.status(404).json({error:"Промокод табылмады"}); res.json({ok:true}); });
app.get("*", (_req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`USD Doner running on http://localhost:${PORT}`));
