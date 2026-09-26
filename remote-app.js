/* Server-backed DoktorUZ adapter. Loaded after the prototype so the core flows use the API. */
(function(){
  const API='/api/router';
  const MASTER_PHONE='998933763262';
  const pendingKey='doktoruz_remote_pending';
  let pending=null;
  let adminTab='users';
  let otpResendUntil=0, otpTimer=null;

  function norm(v){return String(v||'').replace(/\D/g,'');}
  function esc(v){return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}
  function curUser(){try{return JSON.parse(localStorage.getItem('hc_user')||'null')}catch{return null}}
  function setLocalUser(u){if(u){localStorage.setItem('hc_user',JSON.stringify(u));localStorage.setItem('hc_registered','1')}else{localStorage.removeItem('hc_user');localStorage.removeItem('hc_registered')}}
  async function api(action,opts={}){
    const res=await fetch(API+'?action='+encodeURIComponent(action),{credentials:'include',headers:{'Content-Type':'application/json',...(opts.headers||{})},method:opts.method||'GET',body:opts.body?JSON.stringify(opts.body):undefined});
    const data=await res.json().catch(()=>({ok:false,error:'Некорректный ответ сервера'}));
    if(!res.ok||data.ok===false)throw new Error(data.error||('HTTP '+res.status));
    return data;
  }
  function savePending(){sessionStorage.setItem(pendingKey,JSON.stringify(pending));}
  function loadPending(){try{return JSON.parse(sessionStorage.getItem(pendingKey)||'null')}catch{return null}}
  function clearPending(){sessionStorage.removeItem(pendingKey);pending=null}
  function showOtp(data){
    pending=data;savePending();otpResendUntil=Date.now()+30000;
    document.getElementById('otpPhone').textContent=data.phone||'—';
    document.getElementById('otpCode').value='';
    document.getElementById('otpError').textContent='';
    const demo=document.getElementById('otpDemo');
    if(demo){demo.innerHTML=data.demoOtp?`Демо-режим: код для тестирования — <b style="font-size:16px;letter-spacing:.18em">${esc(data.demoOtp)}</b>`:'Код отправлен на телефон. Введите его в поле выше.';}
    if(data.purpose==='login')document.querySelector('#verifySms h1').textContent='Вход по SMS';
    else document.querySelector('#verifySms h1').textContent='Подтвердите номер';
    go('verifySms');
    startOtpTimer();
    setTimeout(()=>document.getElementById('otpCode')?.focus(),80);
  }
  function startOtpTimer(){if(otpTimer)clearInterval(otpTimer);otpTimer=setInterval(()=>{const left=Math.max(0,otpResendUntil-Date.now());const t=document.getElementById('otpTimer'),b=document.getElementById('otpResendBtn');if(t)t.textContent=left?`Повторно отправить можно через ${Math.ceil(left/1000)} сек.`:'Можно отправить код повторно.';if(b)b.disabled=left>0;if(left===0)clearInterval(otpTimer)},300);}

  window.startLogin=async function(){
    const phone=prompt('Введите номер телефона:','+998 ');if(!phone)return;
    try{const d=await api('auth/start',{method:'POST',body:{phone,purpose:'login'}});showOtp(d);}catch(e){alert(e.message)}
  };
  window.registerUser=async function(){
    const name=(document.getElementById('regName')?.value||'').trim(),phone=(document.getElementById('regPhone')?.value||'').trim(),err=document.getElementById('regError');
    if(name.length<2){err.textContent='Введите имя';return;}
    if(norm(phone).length!==12||!norm(phone).startsWith('998')){err.textContent='Введите корректный номер телефона';return;}
    const adminPass=document.getElementById('regAdminPassword')?.value||'';
    try{const d=await api('auth/start',{method:'POST',body:{name,phone,purpose:'register',adminPassword:norm(phone)===MASTER_PHONE?adminPass:''}});showOtp(d);}catch(e){err.textContent=e.message}
  };
  window.verifyRegistrationOtp=async function(){
    pending=loadPending();if(!pending){document.getElementById('otpError').textContent='Сессия подтверждения истекла.';return;}
    const code=(document.getElementById('otpCode')?.value||'').trim();
    if(!/^\d{6}$/.test(code)){document.getElementById('otpError').textContent='Введите 6-значный код.';return;}
    try{const d=await api('auth/verify',{method:'POST',body:{phone:pending.phone,purpose:pending.purpose,code,name:pending.name||''}});setLocalUser(d.user);clearPending();await remoteBootstrap();go('home');alert('Номер подтверждён.');}catch(e){document.getElementById('otpError').textContent=e.message}
  };
  window.resendRegistrationOtp=async function(){
    pending=loadPending();if(!pending||Date.now()<otpResendUntil)return;
    try{const d=await api('auth/start',{method:'POST',body:{phone:pending.phone,purpose:pending.purpose,name:pending.name||'',adminPassword:pending.adminPassword||''}});showOtp(d);document.getElementById('otpError').textContent='Новый код отправлен.';}catch(e){document.getElementById('otpError').textContent=e.message}
  };
  window.cancelRegistrationOtp=function(){clearPending();if(otpTimer)clearInterval(otpTimer);document.querySelector('nav.bottom').style.display='none';go('register');};

  window.verifyAdminPassword=async function(){
    const p=document.getElementById('adminPassword')?.value||'',err=document.getElementById('adminCodeError');
    try{await api('admin/verify',{method:'POST',body:{password:p}});sessionStorage.setItem('hc_admin_auth','1');sessionStorage.setItem('hc_admin_phone',norm(curUser()?.phone||''));closeAdminAuth();go('admin');await window.renderAdmin();}catch(e){err.textContent=e.message}
  };
  window.openAdmin=function(){
    const u=curUser();if(!u||!['admin','master_admin'].includes(u.role)){alert('Админ-доступ для этого номера не выдан.');return;}
    if(sessionStorage.getItem('hc_admin_auth')==='1'){go('admin');window.renderAdmin();return;}
    const ov=document.getElementById('adminAuthOverlay');if(ov)ov.classList.add('open');
  };
  window.adminLogout=async function(){sessionStorage.removeItem('hc_admin_auth');sessionStorage.removeItem('hc_admin_phone');try{await api('auth/logout',{method:'POST',body:{}})}catch{}go('profile');};
  window.logoutUser=async function(){sessionStorage.removeItem('hc_admin_auth');sessionStorage.removeItem('hc_admin_phone');clearPending();try{await api('auth/logout',{method:'POST',body:{}})}catch{}setLocalUser(null);go('register');};

  async function remoteBootstrap(){
    try{
      const d=await api('bootstrap');
      if(d.user)setLocalUser(d.user);
      if(Array.isArray(d.doctors)&&d.doctors.length){
        const grouped={};
        d.doctors.forEach(x=>{const spec=x.specialty||'Врач';(grouped[spec]||(grouped[spec]=[])).push({id:x.id,n:x.name,s:x.specialty,r:x.rating,e:x.experience,p:x.price,phone:x.phone,status:x.status,clinicName:x.clinic_name,description:x.description})});
        window.doctors=grouped;
      }
      if(Array.isArray(d.ads)){localStorage.setItem('hc_remote_ads',JSON.stringify(d.ads));}
      updateAdminEntry();
      return d;
    }catch(e){console.warn('Remote bootstrap:',e.message);return null}
  }
  window.remoteBootstrap=remoteBootstrap;

  window.selectDate=async function(chip,d){
    document.querySelectorAll('.date-chip').forEach(c=>c.classList.remove('active'));chip.classList.add('active');bookState.date=d;bookState.time=null;
    const iso=d.toISOString().slice(0,10),grid=document.getElementById('timeGrid');if(!grid)return;grid.innerHTML='<div style="font-size:12px;color:var(--sub);padding:8px 0;grid-column:1/-1">Проверяем свободное время…</div>';
    let taken=[];try{const r=await fetch(API+'?action=appointments/availability&doctor_name='+encodeURIComponent(bookState.doctorName)+'&date='+encodeURIComponent(iso),{credentials:'include'});const j=await r.json();taken=j.taken||[]}catch{}
    grid.innerHTML='';const slots=['09:00','09:30','10:00','10:30','11:00','11:30','14:00','14:30','15:00','15:30','16:00','16:30'];
    slots.forEach(t=>{const busy=taken.includes(t),el=document.createElement('div');el.className='time-slot'+(busy?' taken':'');el.textContent=busy?t+' · занято':t;if(!busy)el.onclick=()=>{document.querySelectorAll('.time-slot').forEach(s=>s.classList.remove('active'));el.classList.add('active');bookState.time=t;checkBookReady()};grid.appendChild(el)});checkBookReady();
  };
  window.openBooking=function(){
    bookState={date:null,time:null,pay:null,doctorName:null,doctorSpec:null,doctorId:null};const u=curUser();if(!u){alert('Сначала войдите.');go('register');return;}
    const d=(window.currentDoctorFavorite&&window.currentDoctorFavorite.name)?window.currentDoctorFavorite:findDoctorByName(document.getElementById('docName')?.textContent.replace(/✅/g,'').replace('Проверенный врач','').trim());
    const name=d?.name||d?.n||document.getElementById('docName')?.textContent||'Врач',spec=d?.spec||d?.s||document.getElementById('docSpec')?.textContent||'Врач';
    bookState.doctorName=name;bookState.doctorSpec=spec;bookState.doctorId=d?.doctorId||d?.id||null;
    document.getElementById('bookDocName').textContent=name;const dateRow=document.getElementById('dateRow');dateRow.innerHTML='';const today=new Date();
    for(let i=1;i<=14;i++){const dd=new Date(today);dd.setDate(today.getDate()+i);const chip=document.createElement('div');chip.className='date-chip';chip.dataset.iso=dd.toISOString().slice(0,10);chip.innerHTML=`<span>${weekdays[dd.getDay()]}</span><b>${dd.getDate()}</b><span>${months[dd.getMonth()]}</span>`;chip.onclick=()=>window.selectDate(chip,dd);dateRow.appendChild(chip);if(i===1)window.selectDate(chip,dd)}
    document.getElementById('payCash')?.classList.remove('active');document.getElementById('payClick')?.classList.remove('active');document.getElementById('bookConfirm').disabled=true;go('booking');
  };
  window.confirmBooking=async function(){
    const u=curUser();if(!u){alert('Сначала войдите.');go('register');return}if(!bookState.date||!bookState.time||!bookState.pay){alert('Выберите дату, время и способ оплаты.');return}
    try{const d=await api('appointments/create',{method:'POST',body:{doctorId:bookState.doctorId,doctorName:bookState.doctorName,doctorSpecialty:bookState.doctorSpec,date:bookState.date.toISOString().slice(0,10),time:bookState.time,payment:bookState.pay==='cash'?'Наличные':'Click'}});const a=d.appointment;document.getElementById('bookSummary').textContent=`${a.doctor_name} · ${formatAppointmentDate(a.appointment_date,a.appointment_time)}. Оплата: ${a.payment}.`;go('bookOk');}catch(e){alert(e.message);if(e.message.includes('занято'))window.selectDate(document.querySelector('.date-chip.active'),bookState.date)}
  };

  window.renderMyAppointments=async function(){
    const root=document.getElementById('myAppointmentsList');if(!root)return;root.innerHTML='<div class="admin-empty">Загрузка записей…</div>';
    try{const d=await api('appointments/mine');root.innerHTML=(d.appointments||[]).map(a=>{const cancelled=a.status==='cancelled',completed=a.status==='completed';return `<div class="admin-card"><div class="section-head" style="margin:0 0 6px;"><h3>${esc(a.doctor_name)}</h3><span class="admin-pill ${cancelled?'bad':completed?'ok':'wait'}">${cancelled?'Отменена':completed?'Завершена':'Подтверждена'}</span></div><div style="font-size:12px;color:var(--sub);line-height:1.6;">${esc(a.doctor_specialty||'')}<br>📅 ${esc(formatAppointmentDate(a.appointment_date,a.appointment_time))}<br>💳 ${esc(a.payment||'—')}<br><span class="admin-mini">Создана: ${formatAdminDate(a.created_at)}</span></div>${cancelled||completed?'':`<button class="big-btn" style="background:var(--card);color:#D92D20;border:1px solid #F2B8B5;box-shadow:none;" onclick="cancelMyAppointment('${esc(a.id)}')">Отменить запись</button>`}</div>`}).join('')||'<div class="favorite-empty"><b>Записей пока нет</b></div>'}catch(e){root.innerHTML='<div class="admin-empty">'+esc(e.message)+'</div>'}
  };
  window.cancelMyAppointment=async function(id){if(!confirm('Отменить запись?'))return;try{await api('appointments/cancel',{method:'POST',body:{id}});await renderMyAppointments()}catch(e){alert(e.message)}};

  window.submitDoctorApplication=async function(){
    const u=curUser();if(!u){alert('Сначала войдите.');go('register');return}const spec=(document.getElementById('vacSpecialty')?.value||'').trim(),exp=(document.getElementById('vacExperience')?.value||'').trim(),desc=(document.getElementById('vacDescription')?.value||'').trim(),phone=(document.getElementById('vacPhone')?.value||u.phone||'').trim();
    try{await api('doctor-applications/create',{method:'POST',body:{specialty:spec,experience:exp,description:desc,phone,verification:window.doctorVerification||{}}});['vacSpecialty','vacExperience','vacDescription'].forEach(id=>{const el=document.getElementById(id);if(el)el.value=''});go('v7')}catch(e){alert(e.message)}
  };

  function adminRequired(){if(sessionStorage.getItem('hc_admin_auth')!=='1'){alert('Откройте админ-панель и подтвердите код.');return false}return true}
  window.setAdminTab=async function(tab){adminTab=tab;await window.renderAdmin()};
  window.renderAdmin=async function(){
    if(!adminRequired())return;const root=document.getElementById('adminContent');if(!root)return;root.innerHTML='<div class="admin-empty">Загрузка…</div>';
    const tabs=['users','appointments','doctors','pending','ads','access','logs'];const user=curUser();
    let html=`<div class="admin-card"><b style="font-size:15px;">ДокторUZ — серверная админка</b><p class="admin-login-note">${esc(user?.phone||'')} · роль: ${esc(user?.role||'admin')}</p><div class="admin-tabs">${tabs.map(t=>`<button class="admin-tab ${t===adminTab?'active':''}" onclick="setAdminTab('${t}')">${({users:'👥 Пользователи',appointments:'📅 Записи',doctors:'🩺 Врачи',pending:'⏳ Модерация',ads:'📣 Реклама',access:'🔐 Доступы',logs:'🧾 Журнал'})[t]}</button>`).join('')}</div></div>`;
    root.innerHTML=html;
    const box=document.createElement('div');root.appendChild(box);
    try{
      if(adminTab==='users')await renderAdminUsers(box);
      else if(adminTab==='appointments')await renderAdminAppointments(box);
      else if(adminTab==='doctors')await renderAdminDoctors(box);
      else if(adminTab==='pending')await renderAdminPending(box);
      else if(adminTab==='ads')await renderAdminAds(box);
      else if(adminTab==='access')await renderAdminAccess(box);
      else await renderAdminLogs(box);
    }catch(e){box.innerHTML='<div class="admin-card"><div class="admin-empty">'+esc(e.message)+'</div></div>'}
  };
  async function renderAdminUsers(root){const d=await api('admin/users');root.innerHTML=`<div class="admin-card"><input id="raUserQ" class="admin-input" placeholder="Поиск по имени или номеру"><button class="big-btn" style="margin-bottom:8px" onclick="searchAdminUsers()">Найти</button><div class="admin-wide-list">${(d.users||[]).map(u=>`<div class="admin-item stacked"><div class="meta"><b>${esc(u.name)} <span class="admin-pill ${u.role==='user'?'wait':'ok'}">${esc(u.role)}</span></b><span>${esc(u.phone)} · ${u.phone_verified?'номер подтверждён':'не подтверждён'}</span><span class="admin-mini">Регистрация: ${formatAdminDate(u.created_at)}</span></div><div class="admin-actions">${u.role==='master_admin'?'':`<button class="danger" onclick="adminDeleteUserRemote('${u.id}')">Удалить</button>`}</div></div>`).join('')||'<div class="admin-empty">Пользователей нет.</div>'}</div></div>`}
  window.searchAdminUsers=async function(){const q=document.getElementById('raUserQ')?.value||'';const d=await api('admin/users&noop=1');const filtered=(d.users||[]).filter(u=>(u.name+' '+u.phone).toLowerCase().includes(q.toLowerCase()));const box=document.querySelector('#adminContent .admin-wide-list');if(box)box.innerHTML=filtered.map(u=>`<div class="admin-item stacked"><div class="meta"><b>${esc(u.name)} <span class="admin-pill ${u.role==='user'?'wait':'ok'}">${esc(u.role)}</span></b><span>${esc(u.phone)}</span><span class="admin-mini">Регистрация: ${formatAdminDate(u.created_at)}</span></div><div class="admin-actions">${u.role==='master_admin'?'':`<button class="danger" onclick="adminDeleteUserRemote('${u.id}')">Удалить</button>`}</div></div>`).join('')||'<div class="admin-empty">Не найдено.</div>'};
  window.adminDeleteUserRemote=async function(id){if(!confirm('Удалить пользователя?'))return;try{await api('admin/users/delete',{method:'POST',body:{id}});await renderAdmin()}catch(e){alert(e.message)}};
  async function renderAdminAppointments(root){const d=await api('admin/appointments');root.innerHTML=`<div class="admin-card"><input id="raApptQ" class="admin-input" placeholder="Поиск: пациент, номер, врач"><div class="admin-wide-list">${(d.appointments||[]).map(a=>`<div class="admin-item stacked"><div class="meta"><b>${esc(a.patient_name)} → ${esc(a.doctor_name)} <span class="admin-pill ${a.status==='cancelled'?'bad':a.status==='completed'?'ok':'wait'}">${esc(a.status)}</span></b><span>📱 ${esc(a.patient_phone)}</span><span>📅 ${esc(formatAppointmentDate(a.appointment_date,a.appointment_time))} · 💳 ${esc(a.payment||'—')}</span><span class="admin-mini">Создана: ${formatAdminDate(a.created_at)}</span></div><div class="admin-actions">${a.status==='confirmed'?`<button class="primary" onclick="adminCompleteRemote('${a.id}')">Завершить</button><button class="danger" onclick="adminCancelRemote('${a.id}')">Отменить</button>`:''}<button onclick="adminDeleteAppointmentRemote('${a.id}')">Удалить</button></div></div>`).join('')||'<div class="admin-empty">Записей нет.</div>'}</div></div>`}
  window.adminCompleteRemote=async function(id){try{await api('admin/appointments/action',{method:'POST',body:{id,status:'completed'}});await renderAdmin()}catch(e){alert(e.message)}};window.adminCancelRemote=async function(id){if(!confirm('Отменить запись?'))return;try{await api('admin/appointments/action',{method:'POST',body:{id,status:'cancelled'}});await renderAdmin()}catch(e){alert(e.message)}};window.adminDeleteAppointmentRemote=async function(id){if(!confirm('Удалить запись из истории?'))return;try{await api('admin/appointments/delete',{method:'POST',body:{id}});await renderAdmin()}catch(e){alert(e.message)}};
  async function renderAdminDoctors(root){const d=await api('admin/doctors');root.innerHTML=`<div class="admin-card"><input id="raDocQ" class="admin-input" placeholder="Поиск по имени или телефону"><button class="big-btn" style="margin-bottom:8px" onclick="searchAdminDoctors()">Найти</button><div class="admin-wide-list">${(d.doctors||[]).map(x=>`<div class="admin-item stacked"><div class="meta"><b>${esc(x.name)} <span class="admin-pill ${x.status==='blocked'?'bad':'ok'}">${esc(x.status)}</span></b><span>${esc(x.phone||'—')} · ${esc(x.specialty||'')}</span><span class="admin-mini">ID: ${esc(x.id)}</span></div><div class="admin-actions"><button class="warn" onclick="adminToggleDoctorRemote('${x.id}')">${x.status==='blocked'?'Разблокировать':'Заблокировать'}</button><button class="danger" onclick="adminRemoveDoctorRemote('${x.id}')">Удалить</button></div></div>`).join('')||'<div class="admin-empty">Врачи не найдены.</div>'}</div></div>`}
  window.searchAdminDoctors=async function(){const q=document.getElementById('raDocQ')?.value||'';const d=await fetch(API+'?action=admin/doctors&q='+encodeURIComponent(q),{credentials:'include'}).then(r=>r.json());const box=document.querySelector('#adminContent .admin-wide-list');if(box)box.innerHTML=(d.doctors||[]).map(x=>`<div class="admin-item stacked"><div class="meta"><b>${esc(x.name)} <span class="admin-pill ${x.status==='blocked'?'bad':'ok'}">${esc(x.status)}</span></b><span>${esc(x.phone||'—')} · ${esc(x.specialty||'')}</span></div><div class="admin-actions"><button class="warn" onclick="adminToggleDoctorRemote('${x.id}')">${x.status==='blocked'?'Разблокировать':'Заблокировать'}</button><button class="danger" onclick="adminRemoveDoctorRemote('${x.id}')">Удалить</button></div></div>`).join('')||'<div class="admin-empty">Не найдено.</div>'};
  window.adminToggleDoctorRemote=async function(id){try{await api('admin/doctors/action',{method:'POST',body:{id,action:'toggle_block'}});await remoteBootstrap();await renderAdmin()}catch(e){alert(e.message)}};window.adminRemoveDoctorRemote=async function(id){if(!confirm('Удалить врача?'))return;try{await api('admin/doctors/action',{method:'POST',body:{id,action:'delete'}});await remoteBootstrap();await renderAdmin()}catch(e){alert(e.message)}};
  async function renderAdminPending(root){const d=await api('admin/applications');root.innerHTML=`<div class="admin-card"><div class="admin-wide-list">${(d.applications||[]).map(a=>`<div class="admin-item stacked"><div class="meta"><b>${esc(a.name)}</b><span>${esc(a.phone)} · ${esc(a.specialty)} · ${esc(a.experience||'')}</span><span>${esc(a.description||'')}</span><span class="admin-mini">Отправлена: ${formatAdminDate(a.submitted_at)}</span></div><div class="admin-actions"><button class="success" onclick="adminApproveRemote('${a.id}')">Одобрить</button><button class="danger" onclick="adminRejectRemote('${a.id}')">Отклонить</button></div></div>`).join('')||'<div class="admin-empty">Новых заявок нет.</div>'}</div></div>`}
  window.adminApproveRemote=async function(id){try{await api('admin/applications/action',{method:'POST',body:{id,action:'approve'}});await remoteBootstrap();await renderAdmin();alert('Врач одобрен и добавлен в каталог.')}catch(e){alert(e.message)}};window.adminRejectRemote=async function(id){const reason=prompt('Причина отклонения:','Необходимо уточнить данные');if(reason===null)return;try{await api('admin/applications/action',{method:'POST',body:{id,action:'reject',reason}});await renderAdmin()}catch(e){alert(e.message)}};
  async function uploadFile(file){
    const cfg=window.DOKTORUZ_CONFIG?.cloudinary||{};
    if(cfg.cloudName&&cfg.uploadPreset){const resource=file.type.startsWith('video/')?'video':'image';const fd=new FormData();fd.append('file',file);fd.append('upload_preset',cfg.uploadPreset);const r=await fetch(`https://api.cloudinary.com/v1_1/${encodeURIComponent(cfg.cloudName)}/${resource}/upload`,{method:'POST',body:fd});if(!r.ok)throw new Error('Не удалось загрузить файл в Cloudinary');const j=await r.json();return j.secure_url;}
    if(file.size>3.5*1024*1024)throw new Error('Для теста без облачного хранилища файл должен быть до 3.5 МБ. Для больших видео подключите Cloudinary в конфигурации.');
    return new Promise((resolve,reject)=>{const r=new FileReader();r.onload=()=>resolve(String(r.result||''));r.onerror=()=>reject(new Error('Не удалось прочитать файл'));r.readAsDataURL(file)});
  }
  async function renderAdminAds(root){root.innerHTML=`<div class="admin-card"><h3>Новая реклама</h3><input id="adTitle" class="admin-input" placeholder="Заголовок"><textarea id="adText" class="admin-input admin-textarea" placeholder="Текст"></textarea><select id="adType" class="admin-select"><option value="image">Фото</option><option value="video">Видео</option></select><input id="adFile" class="admin-input" type="file" accept="image/*,video/*"><label class="admin-check"><input id="adShowHome" type="checkbox" checked> Показывать на главной</label><button id="publishAdBtn" class="big-btn" onclick="publishAdminAd()">Опубликовать</button><p class="admin-login-note">Фото/видео: лучше использовать облачное хранилище. Без него тестовый файл — до 3.5 МБ.</p></div><div class="admin-card" id="remoteAdsList"></div>`;const d=await api('admin/ads');const list=document.getElementById('remoteAdsList');list.innerHTML='<h3>Опубликованные</h3>'+(d.ads||[]).map(a=>`<div class="admin-ad-item"><b>${esc(a.title)}</b><div class="admin-mini">${a.media_type==='video'?'Видео':'Фото'} · ${formatAdminDate(a.created_at)} ${a.show_home?'':'· скрыта'}</div>${a.media_url?(a.media_type==='video'?`<video class="admin-media-preview" controls playsinline src="${esc(a.media_url)}"></video>`:`<img class="admin-media-preview" src="${esc(a.media_url)}" alt="Реклама">`):''}<div style="font-size:12px;margin-bottom:8px">${esc(a.body||'')}</div><div class="admin-actions"><button class="warn" onclick="adminToggleAdRemote('${a.id}')">${a.show_home?'Скрыть с главной':'Показать на главной'}</button><button class="danger" onclick="adminRemoveAdRemote('${a.id}')">Удалить</button></div></div>`).join('')||'<div class="admin-empty">Рекламы пока нет.</div>'}
  window.publishAdminAd=async function(){const title=(document.getElementById('adTitle')?.value||'').trim(),body=(document.getElementById('adText')?.value||'').trim(),type=document.getElementById('adType')?.value||'image',file=document.getElementById('adFile')?.files?.[0],showHome=document.getElementById('adShowHome')?.checked!==false;if(!title||!file){alert('Введите заголовок и выберите файл.');return}if(type==='video'&&!file.type.startsWith('video/')){alert('Выберите видео.');return}if(type==='image'&&!file.type.startsWith('image/')){alert('Выберите фото.');return}const b=document.getElementById('publishAdBtn');if(b){b.disabled=true;b.textContent='Загрузка…'}try{const mediaUrl=await uploadFile(file);await api('admin/ads/create',{method:'POST',body:{title,body,mediaType:type,mediaUrl,showHome}});document.getElementById('adFile').value='';document.getElementById('adTitle').value='';document.getElementById('adText').value='';await remoteRenderHomePromos();await renderAdmin();go('home');alert('Реклама опубликована и сразу доступна на главной.')}catch(e){alert(e.message)}finally{if(b){b.disabled=false;b.textContent='Опубликовать'}}};
  window.adminToggleAdRemote=async function(id){try{await api('admin/ads/action',{method:'POST',body:{id,action:'toggle'}});await renderAdmin()}catch(e){alert(e.message)}};window.adminRemoveAdRemote=async function(id){if(!confirm('Удалить рекламу?'))return;try{await api('admin/ads/action',{method:'POST',body:{id,action:'delete'}});await renderAdmin()}catch(e){alert(e.message)}};
  async function renderAdminAccess(root){const u=curUser();const d=await api('admin/users');root.innerHTML=`<div class="admin-card"><h3>Выдача админки по номеру</h3>${u?.role==='master_admin'?`<div class="admin-access-row"><input id="grantPhone" class="admin-input" placeholder="+998 90 123 45 67"><button class="primary" onclick="grantAdminRemote()">Выдать</button></div>`:'<p class="admin-login-note">Выдавать и отзывать доступ может только главный администратор.</p>'}<div class="admin-wide-list">${(d.users||[]).filter(x=>['admin','master_admin'].includes(x.role)).map(x=>`<div class="admin-item"><div class="meta"><b>${esc(x.name)}</b><span>${esc(x.phone)} · ${esc(x.role)}</span></div>${x.role==='admin'&&u?.role==='master_admin'?`<button class="danger" onclick="revokeAdminRemote('${x.id}')">Отозвать</button>`:''}</div>`).join('')||'<div class="admin-empty">Дополнительных администраторов нет.</div>'}</div></div>`}
  window.grantAdminRemote=async function(){const phone=document.getElementById('grantPhone')?.value||'';try{await api('admin/access/grant',{method:'POST',body:{phone}});await renderAdmin()}catch(e){alert(e.message)}};window.revokeAdminRemote=async function(id){if(!confirm('Отозвать админ-доступ?'))return;try{await api('admin/access/revoke',{method:'POST',body:{id}});await renderAdmin()}catch(e){alert(e.message)}};
  async function renderAdminLogs(root){const d=await api('admin/logs');root.innerHTML=`<div class="admin-card"><div class="admin-wide-list">${(d.logs||[]).map(x=>`<div class="admin-item stacked"><div class="meta"><b>${esc(x.action)}</b><span>${esc(x.details||'')}</span><span class="admin-mini">${formatAdminDate(x.created_at)} · ${esc(x.actor_phone||'system')}</span></div></div>`).join('')||'<div class="admin-empty">Журнал пуст.</div>'}</div></div>`}

  async function remoteRenderHomePromos(){
    const root=document.getElementById('homePromos');if(!root)return;try{const d=await api('bootstrap');const ads=(d.ads||[]).filter(a=>a.show_home!==false);if(!ads.length){root.innerHTML='';return}root.innerHTML=`<div class="section-head"><h3>Промо</h3></div><div class="hcards">${ads.map(a=>`<div class="hcard" style="min-width:220px;cursor:default"><div class="img" style="height:130px;background:none;display:block;overflow:hidden">${a.media_url?(a.media_type==='video'?`<video src="${esc(a.media_url)}" muted loop autoplay playsinline controls style="width:100%;height:100%;object-fit:cover"></video>`:`<img src="${esc(a.media_url)}" alt="" style="width:100%;height:100%;object-fit:cover">`):''}</div><div class="body"><h4>${esc(a.title)}</h4>${a.body?`<p>${esc(a.body)}</p>`:''}</div></div>`).join('')}</div>`}catch(e){console.warn(e)}}
  window.renderHomePromos=remoteRenderHomePromos;

  function injectLoginAndLogout(){
    const card=document.querySelector('#register .register-card');if(card&&!document.getElementById('remoteLoginBtn')){const b=document.createElement('button');b.id='remoteLoginBtn';b.className='otp-link';b.style.cssText='display:block;width:100%;margin-top:10px';b.textContent='Уже зарегистрированы? Войти по номеру';b.onclick=window.startLogin;card.appendChild(b)}
    const list=document.querySelector('#profile .profile-list');if(list&&!document.getElementById('remoteLogoutRow')){const row=document.createElement('div');row.id='remoteLogoutRow';row.className='p-item';row.innerHTML='<div class="l"><span class="ic">↪️</span>Выйти из аккаунта</div><span class="chev">›</span>';row.onclick=window.logoutUser;list.appendChild(row)}
  }
  async function syncStaticDoctors(){
    const u=curUser();if(!u||u.role!=='master_admin')return;try{const flat=[];Object.keys(window.doctors||{}).forEach(spec=>(window.doctors[spec]||[]).forEach(d=>flat.push({n:d.n,s:d.s||spec,e:d.e,r:d.r,p:d.p,phone:d.phone,clinicName:d.clinicName})));if(flat.length)await api('admin/doctors/sync',{method:'POST',body:{doctors:flat}});}catch(e){console.warn('Doctor sync',e.message)}}
  document.addEventListener('DOMContentLoaded',async()=>{
    injectLoginAndLogout();
    const d=await remoteBootstrap();
    if(d?.user){setLocalUser(d.user);document.querySelector('nav.bottom').style.display='flex';go('home');}
    else if(loadPending())showOtp(loadPending());
    else {document.querySelectorAll('.screen').forEach(x=>x.classList.remove('active'));document.getElementById('register')?.classList.add('active');document.querySelector('nav.bottom').style.display='none';}
    injectLoginAndLogout();
    await remoteRenderHomePromos();
    if(curUser()?.role==='master_admin')syncStaticDoctors();
  });
})();
