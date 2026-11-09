const {createHmac,randomBytes,timingSafeEqual,createHash}=require('node:crypto');
const COOKIE='__Host-aquaria-dev';
const digest=s=>createHash('sha256').update(s).digest();
const equal=(a,b)=>timingSafeEqual(digest(a),digest(b));
module.exports=async(req,res)=>{
 res.setHeader('Cache-Control','no-store');
 const password=process.env.AQUARIA_DEV_PASSWORD,secret=process.env.AQUARIA_DEV_SESSION_SECRET;
 const issues=[];
 if(!password)issues.push('AQUARIA_DEV_PASSWORD가 배포에 없어');
 else if(password.length<16)issues.push('개발자 비밀번호가 16자보다 짧아');
 if(!secret)issues.push('AQUARIA_DEV_SESSION_SECRET이 배포에 없어');
 else if(secret.length<32)issues.push('인증 비밀키가 32자보다 짧아');
 if(issues.length)return res.status(503).json({error:issues.join(' · ')+'. Production 설정을 저장한 뒤 최신 버전을 재배포해.'});
 const sign=s=>createHmac('sha256',secret).update(s).digest('base64url');
 const token=(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith(COOKIE+'='))?.slice(COOKIE.length+1)||'';
 const parts=token.split('.');
 const valid=parts.length===3&&/^\d+$/.test(parts[0])&&Number(parts[0])>Date.now()&&Number(parts[0])<=Date.now()+3600000&&equal(sign(parts[0]+'.'+parts[1]),parts[2]);
 if(req.method==='GET')return res.status(valid?200:401).json({authenticated:valid});
 if(!['POST','DELETE'].includes(req.method)){res.setHeader('Allow','GET, POST, DELETE');return res.status(405).end();}
 if(req.headers['sec-fetch-site']==='cross-site'||!req.headers.origin||req.headers.origin!=='https://'+req.headers.host)return res.status(403).json({error:'요청 출처를 확인할 수 없어.'});
 if(req.method==='DELETE'){res.setHeader('Set-Cookie',COOKIE+'=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0');return res.status(200).json({authenticated:false});}
 let body=req.body;
 try{if(typeof body==='string')body=JSON.parse(body);}catch{return res.status(400).json({error:'잘못된 요청이야.'});}
 if(typeof body?.password!=='string'||body.password.length>256||!equal(body.password,password))return res.status(401).json({error:'비밀번호가 맞지 않아.'});
 const payload=(Date.now()+3600000)+'.'+randomBytes(24).toString('base64url');
 res.setHeader('Set-Cookie',COOKIE+'='+payload+'.'+sign(payload)+'; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600');
 return res.status(200).json({authenticated:true});
};