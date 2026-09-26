const fs = require('fs');
const path = require('path');
const {query} = require('./_lib/db');
const {normalizePhone,e164,sign,setCookie,clearCookie,getSessionUser,requireUser,requireAdmin,requireMaster,hashOtp,generateOtp,verifyPassword} = require('./_lib/auth');

async function body(req){
  if(req.body && typeof req.body==='object') return req.body;
  return new Promise((resolve,reject)=>{
    let raw=''; req.on('data',c=>{raw+=c;if(raw.length>5e6){reject(new Error('Request too large'));req.destroy();}});
    req.on('end',()=>{try{resolve(raw?JSON.parse(raw):{})}catch(e){reject(e)}}); req.on('error',reject);
  });
}
function json(res,status,data){res.statusCode=status;res.setHeader('Content-Type','application/json; charset=utf-8');res.end(JSON.stringify(data));}
function ok(res,data){json(res,200,{ok:true,...data});}
function bad(res,status,message){json(res,status,{ok:false,error:message});}
async function log(actor,action,details){try{await query('INSERT INTO admin_logs(actor_id,action,details) VALUES($1,$2,$3)',[actor?.id||null,action,details||null]);}catch{}}
function route(req){return new URL(req.url,'http://local').searchParams.get('action')||'';}

async function sendTwilioOtp(phone){
  const sid=process.env.TWILIO_ACCOUNT_SID, token=process.env.TWILIO_AUTH_TOKEN, svc=process.env.TWILIO_VERIFY_SERVICE_SID;
  if(!sid||!token||!svc) throw new Error('Twilio SMS is not configured');
  const auth=Buffer.from(`${sid}:${token}`).toString('base64');
  const form=new URLSearchParams({To:e164(phone),Channel:'sms'});
  const r=await fetch(`https://verify.twilio.com/v2/Services/${encodeURIComponent(svc)}/Verifications`,{method:'POST',headers:{Authorization:`Basic ${auth}`,'Content-Type':'application/x-www-form-urlencoded'},body:form});
  if(!r.ok){const t=await r.text();throw new Error(`Twilio: ${t.slice(0,300)}`);}
}
async function verifyTwilioOtp(phone,code){
  const sid=process.env.TWILIO_ACCOUNT_SID, token=process.env.TWILIO_AUTH_TOKEN, svc=process.env.TWILIO_VERIFY_SERVICE_SID;
  const auth=Buffer.from(`${sid}:${token}`).toString('base64');
  const form=new URLSearchParams({To:e164(phone),Code:String(code)});
  const r=await fetch(`https://verify.twilio.com/v2/Services/${encodeURIComponent(svc)}/VerificationCheck`,{method:'POST',headers:{Authorization:`Basic ${auth}`,'Content-Type':'application/x-www-form-urlencoded'},body:form});
  const j=await r.json();
  return r.ok && j.status==='approved';
}

async function setup(req,res){
  if(process.env.SETUP_ENABLED!=='true' || !process.env.SETUP_TOKEN) return bad(res,404,'Setup disabled');
  const token=req.headers['x-setup-token'] || new URL(req.url,'http://local').searchParams.get('token');
  if(token!==process.env.SETUP_TOKEN)return bad(res,403,'Invalid setup token');
  const sql=fs.readFileSync(path.join(process.cwd(),'schema.sql'),'utf8');
  await query(sql);
  ok(res,{message:'Database schema is ready'});
}

async function authStart(req,res){
  const b=await body(req),phone=normalizePhone(b.phone),purpose=b.purpose==='login'?'login':'register',name=String(b.name||'').trim();
  if(!/^998\d{9}$/.test(phone))return bad(res,400,'Введите корректный номер телефона');
  if(purpose==='register' && name.length<2)return bad(res,400,'Введите имя');
  if(purpose==='register' && phone===normalizePhone(process.env.MASTER_ADMIN_PHONE||'998933763262') && !verifyPassword(b.adminPassword||'')) return bad(res,403,'Для главного администратора нужен правильный пароль');
  const existing=await query('SELECT id,name,role FROM users WHERE phone=$1',[phone]);
  if(purpose==='login' && !existing.rows[0]) return bad(res,404,'Пользователь с таким номером не найден');
  await query('DELETE FROM otp_codes WHERE phone=$1 OR expires_at<now()',[phone]);
  const mode=process.env.SMS_MODE||'demo';
  let demoOtp=null;
  if(mode==='twilio') await sendTwilioOtp(phone);
  else {demoOtp=generateOtp();await query('INSERT INTO otp_codes(phone,purpose,code_hash,expires_at) VALUES($1,$2,$3,now()+interval \'5 minutes\')',[phone,purpose,hashOtp(demoOtp)]);}
  ok(res,{phone,purpose, ...(demoOtp?{demoOtp}: {})});
}

async function authVerify(req,res){
  const b=await body(req),phone=normalizePhone(b.phone),purpose=b.purpose==='login'?'login':'register',code=String(b.code||'').trim(),mode=process.env.SMS_MODE||'demo';
  if(!/^998\d{9}$/.test(phone)||!/^\d{6}$/.test(code))return bad(res,400,'Неверный номер или код');
  let valid=false;
  if(mode==='twilio') valid=await verifyTwilioOtp(phone,code);
  else {
    const r=await query('SELECT id,code_hash,attempts FROM otp_codes WHERE phone=$1 AND purpose=$2 AND expires_at>now() ORDER BY created_at DESC LIMIT 1',[phone,purpose]);
    const row=r.rows[0];
    if(row){
      if(row.attempts>=5)return bad(res,429,'Слишком много попыток. Запросите новый код.');
      valid=hashOtp(code)===row.code_hash;
      await query('UPDATE otp_codes SET attempts=attempts+1 WHERE id=$1',[row.id]);
    }
  }
  if(!valid)return bad(res,400,'Неверный SMS-код');
  let user;
  const existing=await query('SELECT id,phone,name,role,phone_verified,created_at,updated_at FROM users WHERE phone=$1',[phone]);
  const master=phone===normalizePhone(process.env.MASTER_ADMIN_PHONE||'998933763262');
  if(existing.rows[0]){
    const u=existing.rows[0];
    const updated=await query('UPDATE users SET phone_verified=true, updated_at=now(), name=CASE WHEN $2<>\'\' AND $2 IS NOT NULL THEN $2 ELSE name END, role=CASE WHEN $3 THEN \'master_admin\' ELSE role END WHERE id=$1 RETURNING id,phone,name,role,phone_verified,created_at,updated_at',[u.id,String(b.name||''),master]);
    user=updated.rows[0];
  } else {
    const ins=await query('INSERT INTO users(phone,name,role,phone_verified) VALUES($1,$2,$3,true) RETURNING id,phone,name,role,phone_verified,created_at,updated_at',[phone,String(b.name||'Пользователь'),master?'master_admin':'user']);
    user=ins.rows[0];
  }
  await query('DELETE FROM otp_codes WHERE phone=$1 AND purpose=$2',[phone,purpose]);
  const token=sign({uid:user.id,exp:Date.now()+7*24*60*60*1000});
  setCookie(res,'doktoruz_session',token);
  ok(res,{user});
}

async function bootstrap(req,res){
  const user=await getSessionUser(req);
  const dr=await query("SELECT id,name,phone,specialty,experience,rating,price,status,clinic_name,description,created_at FROM doctors WHERE status='active' ORDER BY created_at DESC");
  const ads=await query('SELECT id,title,body,media_type,media_url,show_home,created_at FROM ads WHERE show_home=true ORDER BY created_at DESC');
  ok(res,{user,doctors:dr.rows,ads:ads.rows});
}

function doctorIdFallback(name){return null;}
async function findOrCreateDoctor({doctorId,name,specialty,phone,clinicName}){
  if(doctorId){const r=await query('SELECT * FROM doctors WHERE id=$1',[doctorId]);if(r.rows[0])return r.rows[0];}
  const r=await query("SELECT * FROM doctors WHERE name=$1 AND COALESCE(phone,'')=COALESCE($2,'') AND status<>'deleted' LIMIT 1",[name,phone||null]);
  if(r.rows[0])return r.rows[0];
  const ins=await query('INSERT INTO doctors(name,phone,specialty,clinic_name,status) VALUES($1,$2,$3,$4,\'active\') RETURNING *',[name,phone||null,specialty||'Врач',clinicName||'—']);
  return ins.rows[0];
}

async function availability(req,res){
  const url=new URL(req.url,'http://local'),name=url.searchParams.get('doctor_name')||'',date=url.searchParams.get('date');
  if(!name||!date)return bad(res,400,'Не хватает параметров');
  const r=await query("SELECT a.appointment_time::text AS time FROM appointments a WHERE a.doctor_name=$1 AND a.appointment_date=$2 AND a.status<>'cancelled'",[name,date]);
  ok(res,{taken:r.rows.map(x=>String(x.time).slice(0,5))});
}

async function createAppointment(req,res){
  const user=await requireUser(req,res),b=await body(req);
  const d=await findOrCreateDoctor({doctorId:b.doctorId,name:b.doctorName,specialty:b.doctorSpecialty,phone:b.doctorPhone,clinicName:b.clinicName});
  if(d.status!=='active')return bad(res,409,'Этот врач недоступен для записи');
  try{
    const ins=await query(`INSERT INTO appointments(patient_id,patient_name,patient_phone,doctor_id,doctor_name,doctor_specialty,clinic_name,appointment_date,appointment_time,payment,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'confirmed') RETURNING *`,[user.id,user.name,user.phone,d.id,d.name,d.specialty,d.clinic_name||'—',b.date,b.time,b.payment||'Наличные']);
    ok(res,{appointment:ins.rows[0]});
  }catch(e){ if(e.code==='23505') return bad(res,409,'Это время уже занято. Выберите другое.'); throw e; }
}

async function userAppointments(req,res){
  const user=await requireUser(req,res);
  const r=await query('SELECT * FROM appointments WHERE patient_id=$1 OR patient_phone=$2 ORDER BY appointment_date DESC,appointment_time DESC',[user.id,user.phone]);
  ok(res,{appointments:r.rows});
}
async function cancelMy(req,res){
  const user=await requireUser(req,res),b=await body(req);
  const r=await query("UPDATE appointments SET status='cancelled',cancelled_at=now(),cancelled_by=$3 WHERE id=$1 AND (patient_id=$2 OR patient_phone=$4) AND status='confirmed' RETURNING *",[b.id,user.id,user.id,user.phone]);
  if(!r.rows[0])return bad(res,404,'Запись не найдена'); ok(res,{appointment:r.rows[0]});
}

async function submitApplication(req,res){
  const user=await requireUser(req,res),b=await body(req);
  const spec=String(b.specialty||'').trim(),exp=String(b.experience||'').trim(),desc=String(b.description||'').trim(),phone=normalizePhone(b.phone||user.phone);
  if(spec.length<3||!/^\d{1,2}$/.test(exp)||desc.length<10)return bad(res,400,'Проверьте данные заявки');
  const dup=await query("SELECT id FROM doctor_applications WHERE phone=$1 AND status='pending' LIMIT 1",[phone]);
  if(dup.rows[0])return bad(res,409,'Заявка с этим номером уже находится на модерации');
  const r=await query('INSERT INTO doctor_applications(user_id,name,phone,specialty,experience,description,verification) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',[user.id,user.name,phone,spec,exp+' лет',desc,JSON.stringify(b.verification||{})]);
  ok(res,{application:r.rows[0]});
}

async function adminUsers(req,res){await requireAdmin(req,res);const q=new URL(req.url,'http://local').searchParams.get('q')||'';const r=await query("SELECT id,name,phone,role,phone_verified,created_at,updated_at FROM users WHERE name ILIKE $1 OR phone ILIKE $1 ORDER BY created_at DESC",['%'+q+'%']);ok(res,{users:r.rows});}
async function adminDeleteUser(req,res){const admin=await requireAdmin(req,res),b=await body(req),r=await query('SELECT id,phone,role FROM users WHERE id=$1',[b.id]);const u=r.rows[0];if(!u)return bad(res,404,'Пользователь не найден');if(u.role==='master_admin')return bad(res,400,'Главного администратора удалить нельзя');if(u.role==='admin'&&admin.role!=='master_admin')return bad(res,403,'Только главный администратор может удалить другого администратора');await query('DELETE FROM users WHERE id=$1',[u.id]);await log(admin,'Удалён пользователь',u.phone);ok(res,{});}
async function adminAppointments(req,res){await requireAdmin(req,res);const q=new URL(req.url,'http://local').searchParams.get('q')||'';const r=await query(`SELECT * FROM appointments WHERE patient_name ILIKE $1 OR patient_phone ILIKE $1 OR doctor_name ILIKE $1 ORDER BY appointment_date DESC,appointment_time DESC`,['%'+q+'%']);ok(res,{appointments:r.rows});}
async function adminAppointmentAction(req,res){const admin=await requireAdmin(req,res),b=await body(req);let status=b.status;if(!['cancelled','completed'].includes(status))return bad(res,400,'Недопустимый статус');const r=await query(`UPDATE appointments SET status=$2,cancelled_at=CASE WHEN $2='cancelled' THEN now() ELSE cancelled_at END,cancelled_by=CASE WHEN $2='cancelled' THEN $3 ELSE cancelled_by END,completed_at=CASE WHEN $2='completed' THEN now() ELSE completed_at END WHERE id=$1 RETURNING *`,[b.id,status,admin.id]);if(!r.rows[0])return bad(res,404,'Запись не найдена');await log(admin,status==='cancelled'?'Отменена запись':'Завершена запись',`${r.rows[0].patient_name} → ${r.rows[0].doctor_name}`);ok(res,{appointment:r.rows[0]});}
async function adminDeleteAppointment(req,res){const admin=await requireAdmin(req,res),b=await body(req);const r=await query('DELETE FROM appointments WHERE id=$1 RETURNING *',[b.id]);if(!r.rows[0])return bad(res,404,'Запись не найдена');await log(admin,'Удалена запись из истории',r.rows[0].id);ok(res,{});}

async function adminDoctors(req,res){await requireAdmin(req,res);const q=new URL(req.url,'http://local').searchParams.get('q')||'';const r=await query("SELECT * FROM doctors WHERE status<>'deleted' AND (name ILIKE $1 OR COALESCE(phone,'') ILIKE $1) ORDER BY created_at DESC",['%'+q+'%']);ok(res,{doctors:r.rows});}
async function adminDoctorAction(req,res){const admin=await requireAdmin(req,res),b=await body(req);if(b.action==='delete'){const r=await query("UPDATE doctors SET status='deleted',updated_at=now() WHERE id=$1 RETURNING *",[b.id]);if(!r.rows[0])return bad(res,404,'Врач не найден');await log(admin,'Удалён врач',r.rows[0].name);return ok(res,{doctor:r.rows[0]});}if(b.action==='toggle_block'){const r=await query("UPDATE doctors SET status=CASE WHEN status='blocked' THEN 'active' ELSE 'blocked' END,updated_at=now() WHERE id=$1 RETURNING *",[b.id]);if(!r.rows[0])return bad(res,404,'Врач не найден');await log(admin,r.rows[0].status==='blocked'?'Заблокирован врач':'Разблокирован врач',r.rows[0].name);return ok(res,{doctor:r.rows[0]});}return bad(res,400,'Недопустимое действие');}
async function adminApplications(req,res){await requireAdmin(req,res);const r=await query('SELECT * FROM doctor_applications WHERE status=\'pending\' ORDER BY submitted_at ASC');ok(res,{applications:r.rows});}
async function adminApplicationAction(req,res){const admin=await requireAdmin(req,res),b=await body(req);const r=await query('SELECT * FROM doctor_applications WHERE id=$1',[b.id]);const a=r.rows[0];if(!a)return bad(res,404,'Заявка не найдена');if(a.status!=='pending')return bad(res,409,'Заявка уже обработана');if(b.action==='reject'){const u=await query("UPDATE doctor_applications SET status='rejected',rejection_reason=$2,decided_at=now(),decided_by=$3 WHERE id=$1 RETURNING *",[b.id,String(b.reason||''),admin.id]);await log(admin,'Отклонена заявка врача',`${a.name} · ${b.reason||'без причины'}`);return ok(res,{application:u.rows[0]});}if(b.action==='approve'){const d=await query("INSERT INTO doctors(name,phone,specialty,experience,description,status,source_application_id) VALUES($1,$2,$3,$4,$5,'active',$6) ON CONFLICT (name, COALESCE(phone,'')) DO UPDATE SET status='active',specialty=excluded.specialty,experience=excluded.experience,description=excluded.description,source_application_id=excluded.source_application_id RETURNING *",[a.name,a.phone,a.specialty,a.experience,a.description,a.id]);const u=await query("UPDATE doctor_applications SET status='approved',decided_at=now(),decided_by=$2 WHERE id=$1 RETURNING *",[b.id,admin.id]);await log(admin,'Одобрена заявка врача',`${a.name} · ${a.specialty}`);return ok(res,{application:u.rows[0],doctor:d.rows[0]});}return bad(res,400,'Недопустимое действие');}

async function adminAds(req,res){await requireAdmin(req,res);const r=await query('SELECT * FROM ads ORDER BY created_at DESC');ok(res,{ads:r.rows});}
async function adminCreateAd(req,res){const admin=await requireAdmin(req,res),b=await body(req);if(!b.title||!b.mediaUrl||!['image','video'].includes(b.mediaType))return bad(res,400,'Заполните заголовок и медиа');const r=await query('INSERT INTO ads(title,body,media_type,media_url,show_home,created_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',[String(b.title).trim(),String(b.body||'').trim(),b.mediaType,b.mediaUrl,b.showHome!==false,admin.id]);await log(admin,'Опубликована реклама',b.title);ok(res,{ad:r.rows[0]});}
async function adminAdAction(req,res){const admin=await requireAdmin(req,res),b=await body(req);if(b.action==='delete'){const r=await query('DELETE FROM ads WHERE id=$1 RETURNING *',[b.id]);if(!r.rows[0])return bad(res,404,'Реклама не найдена');await log(admin,'Удалена реклама',r.rows[0].title);return ok(res,{});}if(b.action==='toggle'){const r=await query('UPDATE ads SET show_home=NOT show_home WHERE id=$1 RETURNING *',[b.id]);if(!r.rows[0])return bad(res,404,'Реклама не найдена');await log(admin,r.rows[0].show_home?'Показана реклама на главной':'Скрыта реклама с главной',r.rows[0].title);return ok(res,{ad:r.rows[0]});}return bad(res,400,'Недопустимое действие');}
async function adminAccess(req,res){const admin=await requireMaster(req,res),b=await body(req),phone=normalizePhone(b.phone);if(!/^998\d{9}$/.test(phone))return bad(res,400,'Неверный номер');if(phone===normalizePhone(process.env.MASTER_ADMIN_PHONE||'998933763262'))return bad(res,400,'Это главный администратор');const u=await query("UPDATE users SET role='admin',updated_at=now() WHERE phone=$1 RETURNING id,name,phone,role",[phone]);if(!u.rows[0])return bad(res,404,'Пользователь с таким номером ещё не зарегистрирован');await log(admin,'Выдан админ-доступ',phone);ok(res,{user:u.rows[0]});}
async function adminRevoke(req,res){const admin=await requireMaster(req,res),b=await body(req),u=await query('UPDATE users SET role=\'user\',updated_at=now() WHERE id=$1 AND role=\'admin\' RETURNING id,name,phone,role',[b.id]);if(!u.rows[0])return bad(res,404,'Администратор не найден');await log(admin,'Отозван админ-доступ',u.rows[0].phone);ok(res,{user:u.rows[0]});}
async function adminLogs(req,res){await requireAdmin(req,res);const r=await query('SELECT l.id,l.action,l.details,l.created_at,u.phone AS actor_phone,u.name AS actor_name FROM admin_logs l LEFT JOIN users u ON u.id=l.actor_id ORDER BY l.created_at DESC LIMIT 300');ok(res,{logs:r.rows});}

async function syncDoctors(req,res){const admin=await requireMaster(req,res),b=await body(req),list=Array.isArray(b.doctors)?b.doctors:[];for(const d of list){if(!d?.n)continue;await query("INSERT INTO doctors(name,phone,specialty,experience,rating,price,clinic_name,status) VALUES($1,$2,$3,$4,$5,$6,$7,'active') ON CONFLICT (name, COALESCE(phone,'')) DO UPDATE SET specialty=excluded.specialty,experience=excluded.experience,rating=excluded.rating,price=excluded.price,clinic_name=excluded.clinic_name,status=CASE WHEN doctors.status='blocked' THEN 'blocked' ELSE 'active' END",[d.n,d.phone||null,d.s||'Врач',d.e||'',d.r||'Новый',d.p||'Уточнить',d.clinicName||'—']);}await log(admin,'Синхронизирован каталог врачей','demo/static → database');ok(res,{count:list.length});}

async function main(req,res){
  const a=route(req);
  if(a==='setup')return setup(req,res);
  if(a==='auth/start')return authStart(req,res);
  if(a==='auth/verify')return authVerify(req,res);
  if(a==='auth/me'){const user=await getSessionUser(req);return ok(res,{user});}
  if(a==='auth/logout'){clearCookie(res,'doktoruz_session');clearCookie(res,'doktoruz_admin');return ok(res,{});}
  if(a==='bootstrap')return bootstrap(req,res);
  if(a==='appointments/availability')return availability(req,res);
  if(a==='appointments/create')return createAppointment(req,res);
  if(a==='appointments/mine')return userAppointments(req,res);
  if(a==='appointments/cancel')return cancelMy(req,res);
  if(a==='doctor-applications/create')return submitApplication(req,res);
  if(a==='admin/verify'){const u=await requireUser(req,res),b=await body(req);if(!['admin','master_admin'].includes(u.role))return bad(res,403,'Недостаточно прав');if(!verifyPassword(b.password||''))return bad(res,401,'Неверный код администратора');setCookie(res,'doktoruz_admin',sign({uid:u.id,admin:true,exp:Date.now()+60*60*1000}),3600);return ok(res,{role:u.role});}
  if(a==='admin/users')return adminUsers(req,res);
  if(a==='admin/users/delete')return adminDeleteUser(req,res);
  if(a==='admin/appointments')return adminAppointments(req,res);
  if(a==='admin/appointments/action')return adminAppointmentAction(req,res);
  if(a==='admin/appointments/delete')return adminDeleteAppointment(req,res);
  if(a==='admin/doctors')return adminDoctors(req,res);
  if(a==='admin/doctors/action')return adminDoctorAction(req,res);
  if(a==='admin/applications')return adminApplications(req,res);
  if(a==='admin/applications/action')return adminApplicationAction(req,res);
  if(a==='admin/ads')return adminAds(req,res);
  if(a==='admin/ads/create')return adminCreateAd(req,res);
  if(a==='admin/ads/action')return adminAdAction(req,res);
  if(a==='admin/access/grant')return adminAccess(req,res);
  if(a==='admin/access/revoke')return adminRevoke(req,res);
  if(a==='admin/logs')return adminLogs(req,res);
  if(a==='admin/doctors/sync')return syncDoctors(req,res);
  return bad(res,404,'Unknown action');
}

module.exports=async(req,res)=>{try{await main(req,res);}catch(e){console.error(e);if(!res.headersSent)bad(res,res.statusCode>=400?res.statusCode:500,e.message||'Server error');}};
