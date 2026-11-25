const CACHE="usd-doner-v3";
const CORE=["/","/manifest.webmanifest","/icon.svg","/menu-source/menu-1.jpg","/menu-source/menu-2.jpg","/menu-source/menu-3.jpg"];
self.addEventListener("install",e=>e.waitUntil(caches.open(CACHE).then(c=>c.addAll(CORE))));
self.addEventListener("activate",e=>e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k))))));
self.addEventListener("fetch",e=>{
  const req=e.request;if(req.method!=="GET")return;
  const url=new URL(req.url);if(url.origin!==self.location.origin||url.pathname.startsWith("/api/")||url.pathname==="/admin.html")return;
  if(req.mode==="navigate"){e.respondWith(fetch(req).then(r=>{const copy=r.clone();caches.open(CACHE).then(c=>c.put("/",copy));return r;}).catch(()=>caches.match("/")));return;}
  e.respondWith(caches.match(req).then(cached=>cached||fetch(req).then(r=>{if(r.ok){const copy=r.clone();caches.open(CACHE).then(c=>c.put(req,copy));}return r;})));
});
self.addEventListener("push",event=>{let data={title:"USD Doner",body:"Сізге жаңа хабарлама келді",url:"/"};try{data={...data,...event.data.json()}}catch{}event.waitUntil(self.registration.showNotification(data.title,{body:data.body,icon:"/icon.svg",data:{url:data.url||"/"}}));});
self.addEventListener("notificationclick",event=>{event.notification.close();event.waitUntil(clients.openWindow(event.notification.data?.url||"/"));});
