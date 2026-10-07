require('dotenv').config();
const express=require('express'),fs=require('fs'),path=require('path'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),
speakeasy=require('speakeasy'),QR=require('qrcode'),passport=require('passport');
const PORT=process.env.PORT||3000,BASE=process.env.BASE_URL||`http://localhost:${PORT}`,SECRET=process.env.JWT_SECRET||'cambia-esto';
const ROLES=['Administrador','Gerente','Ventas','Auditor'],PW=/^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;
const DBF=path.join(__dirname,'db.json');
let db=fs.existsSync(DBF)?JSON.parse(fs.readFileSync(DBF)):{seq:5,users:[],productos:[
{id:1,nombre:'Laptop Pro 14',precio:3200,stock:10,tienda:'Lima-01'},{id:2,nombre:'Mouse Gamer',precio:90,stock:40,tienda:'Lima-01'},
{id:3,nombre:'Monitor 27"',precio:850,stock:15,tienda:'Cusco-02'},{id:4,nombre:'Teclado Mecánico',precio:210,stock:25,tienda:'Cusco-02'}]};
const save=()=>fs.writeFileSync(DBF,JSON.stringify(db,null,2));
const app=express();app.use(express.json());app.use(express.static(path.join(__dirname,'public')));app.use(passport.initialize());
const pub=u=>({email:u.email,nombre:u.nombre,tienda:u.tienda,rol:u.rol});
const full=u=>jwt.sign(pub(u),SECRET,{expiresIn:'1h'});
const bearer=r=>(r.headers.authorization||'').replace('Bearer ','');
const find=e=>db.users.find(u=>u.email===String(e).toLowerCase());

// ---------- Registro ----------
app.post('/api/register',async(req,res)=>{
 const{email,password,nombre,tienda,rol}=req.body;
 if(!email||!nombre||!tienda||!password)return res.status(400).json({error:'Todos los campos son obligatorios'});
 if(!/^\S+@\S+\.\S+$/.test(email))return res.status(400).json({error:'Email inválido'});
 if(!PW.test(password))return res.status(400).json({error:'La contraseña necesita 8+ caracteres, mayúscula, número y carácter especial'});
 if(find(email))return res.status(409).json({error:'Ese email ya está registrado'});
 db.users.push({email:email.toLowerCase(),hash:await bcrypt.hash(password,10),nombre,tienda,rol:ROLES.includes(rol)?rol:'Ventas',
  fails:0,lockedUntil:0,mfaSecret:null,mfaOn:false,mfaFails:0});save();res.status(201).json({ok:true});
});

// ---------- Login (paso 1) ----------
app.post('/api/login',async(req,res)=>{
 const u=find(req.body.email||'');
 if(!u||!u.hash)return res.status(401).json({error:'Credenciales inválidas'});
 if(u.lockedUntil>Date.now())return res.status(423).json({error:`Cuenta bloqueada. Intenta en ${Math.ceil((u.lockedUntil-Date.now())/60000)} min`});
 if(!await bcrypt.compare(req.body.password||'',u.hash)){
  u.fails++;let msg=`Credenciales inválidas. Intento ${u.fails}/5`;
  if(u.fails>=5){u.lockedUntil=Date.now()+15*60000;u.fails=0;msg='Cuenta bloqueada 15 minutos por 5 intentos fallidos'}
  save();return res.status(u.lockedUntil>Date.now()?423:401).json({error:msg});
 }
 u.fails=0;u.mfaFails=0;save();
 res.json({mfa_required:u.mfaOn,mfa_setup:!u.mfaOn,tempToken:jwt.sign({email:u.email,mfa:true},SECRET,{expiresIn:'5m'})});
});

// ---------- MFA TOTP (paso 2) ----------
function mfaUser(req,res){try{const p=jwt.verify(bearer(req),SECRET);if(!p.mfa)throw 0;const u=find(p.email);
 if(u.mfaFails>=3){res.status(429).json({error:'Máximo de 3 intentos. Inicia sesión de nuevo'});return null}return u}
 catch{res.status(401).json({error:'Sesión MFA inválida o expirada'});return null}}
app.get('/api/mfa/setup',async(req,res)=>{const u=mfaUser(req,res);if(!u)return;
 if(u.mfaOn)return res.status(400).json({error:'MFA ya configurado'});
 const s=speakeasy.generateSecret({name:`TechStore (${u.email})`});u.mfaSecret=s.base32;save();
 res.json({qr:await QR.toDataURL(s.otpauth_url),secret:s.base32})});
app.post('/api/mfa/verify',(req,res)=>{const u=mfaUser(req,res);if(!u)return;
 const ok=speakeasy.totp.verify({secret:u.mfaSecret,encoding:'base32',token:String(req.body.code||''),window:1});
 if(!ok){u.mfaFails++;save();return res.status(401).json({error:`Código incorrecto. Intento ${u.mfaFails}/3`})}
 u.mfaOn=true;u.mfaFails=0;save();res.json({token:full(u),user:pub(u)})});

// ---------- Login social ----------
const social=(name,Strat,cfg)=>{
 if(!cfg.clientID)return console.log(`(${name} no configurado: falta CLIENT_ID en .env)`);
 passport.use(new Strat({...cfg,callbackURL:`${BASE}/auth/${name}/callback`},(a,r,p,done)=>{
  const email=(p.emails&&p.emails[0]&&p.emails[0].value)||`${p.username||p.id}@${name}.local`;
  let u=find(email);if(!u){u={email:email.toLowerCase(),hash:null,nombre:p.displayName||p.username||email,tienda:'Sin asignar',rol:'Ventas',fails:0,lockedUntil:0,mfaOn:true};db.users.push(u);save()}
  done(null,u)}));
 app.get(`/auth/${name}`,passport.authenticate(name,{session:false,scope:name==='google'?['profile','email']:['user:email']}));
 app.get(`/auth/${name}/callback`,passport.authenticate(name,{session:false,failureRedirect:'/?error=social'}),(req,res)=>res.redirect('/?token='+full(req.user)));
};
social('google',require('passport-google-oauth20').Strategy,{clientID:process.env.GOOGLE_CLIENT_ID,clientSecret:process.env.GOOGLE_CLIENT_SECRET});
social('github',require('passport-github2').Strategy,{clientID:process.env.GITHUB_CLIENT_ID,clientSecret:process.env.GITHUB_CLIENT_SECRET});

// ---------- Autorización por rol ----------
const auth=(...roles)=>(req,res,next)=>{try{const p=jwt.verify(bearer(req),SECRET);if(p.mfa)throw 0;
 if(roles.length&&!roles.includes(p.rol))return res.status(403).json({error:`El rol ${p.rol} no tiene permiso para esta acción`});req.user=p;next()}
 catch{res.status(401).json({error:'Token inválido o expirado'})}};
const own=(req,p)=>req.user.rol==='Administrador'||p.tienda===req.user.tienda;
const prod=(req,res)=>{const p=db.productos.find(x=>x.id==req.params.id);if(!p)res.status(404).json({error:'No existe'});
 else if(!own(req,p))res.status(403).json({error:'Solo puedes gestionar productos de tu tienda'});else return p};

app.get('/api/me',auth(),(req,res)=>res.json(req.user));
app.get('/api/productos',auth(),(req,res)=>res.json(db.productos));
app.post('/api/productos',auth('Administrador','Gerente'),(req,res)=>{const{nombre,precio,stock}=req.body;
 const p={id:db.seq++,nombre,precio:+precio,stock:+stock,tienda:req.user.rol==='Administrador'?(req.body.tienda||req.user.tienda):req.user.tienda};db.productos.push(p);save();res.status(201).json(p)});
app.put('/api/productos/:id',auth('Administrador','Gerente'),(req,res)=>{const p=prod(req,res);if(!p)return;
 Object.assign(p,{nombre:req.body.nombre??p.nombre,precio:req.body.precio!=null?+req.body.precio:p.precio});save();res.json(p)});
app.patch('/api/productos/:id/stock',auth('Administrador','Gerente','Ventas'),(req,res)=>{const p=db.productos.find(x=>x.id==req.params.id);
 if(!p)return res.status(404).json({error:'No existe'});p.stock=+req.body.stock;save();res.json(p)});
app.delete('/api/productos/:id',auth('Administrador','Gerente'),(req,res)=>{const p=prod(req,res);if(!p)return;
 db.productos=db.productos.filter(x=>x!==p);save();res.json({ok:true})});
app.get('/api/reportes',auth('Administrador','Gerente','Auditor'),(req,res)=>{
 const l=req.user.rol==='Gerente'?db.productos.filter(p=>p.tienda===req.user.tienda):db.productos;
 res.json({productos:l.length,unidades:l.reduce((a,p)=>a+p.stock,0),valorInventario:l.reduce((a,p)=>a+p.stock*p.precio,0),alcance:req.user.rol==='Gerente'?req.user.tienda:'Todas las tiendas'})});
app.get('/api/usuarios',auth('Administrador'),(req,res)=>res.json(db.users.map(pub)));
app.put('/api/usuarios/:email/rol',auth('Administrador'),(req,res)=>{const u=find(req.params.email);
 if(!u||!ROLES.includes(req.body.rol))return res.status(400).json({error:'Datos inválidos'});u.rol=req.body.rol;save();res.json(pub(u))});

app.listen(PORT,()=>console.log('TechStore en '+BASE));
