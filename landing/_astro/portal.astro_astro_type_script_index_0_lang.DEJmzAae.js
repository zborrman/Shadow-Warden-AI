(()=>{let e=`sw_communities`,t=`sw_user_id`,n={starter:{name:`Starter`,color:`#64748b`,maxComm:0},individual:{name:`Individual`,color:`#06b6d4`,maxComm:1},community_business:{name:`Community Business`,color:`#BF5AF2`,maxComm:3}};function r(){return localStorage.getItem(`sw_tier`)||`starter`}function i(){return n[r()]||n.community_business}function a(){let e=localStorage.getItem(t);if(!e){let n=crypto.getRandomValues(new Uint8Array(3));e=`USR-`+Array.from(n).map(e=>e.toString(16).padStart(2,`0`)).join(``).toUpperCase().slice(0,4),localStorage.setItem(t,e)}return e}function o(){try{return JSON.parse(localStorage.getItem(e)||`[]`)}catch{return[]}}function s(t){localStorage.setItem(e,JSON.stringify(t))}function c(e){return String(e).replace(/&/g,`&amp;`).replace(/</g,`&lt;`).replace(/>/g,`&gt;`)}function l(e){try{return JSON.parse(localStorage.getItem(`sw_tunnel_${e}`)||`[]`).length}catch{return 0}}function u(){let e=a(),t=document.getElementById(`my-uid`);t&&(t.textContent=e);let n=document.getElementById(`user-chip`);n&&(n.textContent=e.replace(`USR-`,``).slice(0,2));let r=i(),s=o(),u=document.getElementById(`tier-bar`);if(u){let e=s.length,t=r.maxComm,n=t<=0?0:Math.min(e/t*100,100);u.innerHTML=`
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
          <span style="padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;font-family:monospace;background:${r.color}18;border:1px solid ${r.color}30;color:${r.color}">${r.name.toUpperCase()}</span>
          ${t===-1?`<span style="font-size:13px;color:#64748b">${e} communities (unlimited)</span>`:t===0?`<span style="font-size:13px;color:#f87171">0 private communities on Starter — <a href="/price" style="color:#BF5AF2;text-decoration:none">upgrade</a></span>`:`<span style="font-size:13px;color:#64748b">${e} / ${t} communities</span>`}
          ${t>0?`<div style="flex:1;min-width:80px;max-width:140px;height:4px;border-radius:2px;background:#1e293b;overflow:hidden"><div style="height:100%;width:${n}%;background:${n>=100?`#f87171`:r.color};border-radius:2px"></div></div>`:``}
          <a href="/price" style="margin-left:auto;font-size:12px;color:#475569;text-decoration:none" onmouseover="this.style.color='#BF5AF2'" onmouseout="this.style.color='#475569'">Change plan →</a>
        </div>`}let d=r.maxComm!==-1&&s.length>=r.maxComm,f=document.getElementById(`new-btn`);f&&d&&(f.href=`/price`,f.textContent=r.maxComm===0?`Upgrade to create`:`↑ Upgrade for more`,f.style.background=`rgba(255,255,255,0.06)`,f.style.color=`#94a3b8`);let p=(document.getElementById(`comm-search`)?.value||``).toLowerCase(),m=p?s.filter(e=>e.name.toLowerCase().includes(p)||e.id.toLowerCase().includes(p)):s,h=document.getElementById(`comm-grid`);h.innerHTML=s.length===0?`
        <div class="empty-state">
          <div class="empty-icon">◈</div>
          <p class="empty-title">No communities yet</p>
          <p class="empty-sub">Create your first secure collaboration space.<br>
            Each community gets a unique <code style="color:#BF5AF2;font-family:monospace">COMM-XXXX</code> identifier.</p>
          <a href="/community/new" class="btn-primary-violet" style="display:inline-flex;text-decoration:none">+ Create First Community</a>
        </div>`:m.length===0?`<p style="color:#475569;padding:24px 0">No communities match "${c(p)}".</p>`:`<div class="comm-grid">${m.map(t=>{let n=(t.members||[]).length,r=l(t.id),i=(t.join_requests||[]).some(t=>t.userId===e),a=(t.members||[]).find(t=>t.id===e)?.role===`owner`;return`
        <div class="comm-card" onclick="location.href='/community/view?id=${encodeURIComponent(t.id)}'">
          <div class="card-top">
            <div style="min-width:0">
              <div class="card-id-row">
                <span class="card-id">${c(t.id)}</span>
                ${t.isJoined||a?`<span class="badge-joined">✓ JOINED</span>`:``}
                ${i?`<span class="badge-pending">PENDING</span>`:``}
              </div>
              <div class="card-name">${c(t.name)}</div>
            </div>
            <span class="card-member-chip">${n} member${n===1?``:`s`}</span>
          </div>
          ${t.description?`<p class="card-desc">${c(t.description)}</p>`:``}
          <div class="card-stats">
            ${r>0?`<span>💬 ${r} message${r===1?``:`s`}</span>`:``}
            <span class="e2ee-pill">Demo</span>
          </div>
          <div class="card-actions" onclick="event.stopPropagation()">
            <a href="/community/view?id=${encodeURIComponent(t.id)}" class="card-btn-main">Open Portal →</a>
            <a href="/community/view?id=${encodeURIComponent(t.id)}&tab=tunnel" class="card-btn-ghost">🔒 Tunnel${r>0?` (${r})`:``}</a>
            <a href="/community/view?id=${encodeURIComponent(t.id)}&tab=members" class="card-btn-ghost">Members</a>
          </div>
          <div class="card-date">Created ${new Date(t.created||Date.now()).toLocaleDateString()}</div>
        </div>`}).join(``)}</div>`}document.getElementById(`comm-search`)?.addEventListener(`input`,u);let d=document.getElementById(`join-modal`),f=document.getElementById(`join-input`),p=document.getElementById(`join-err`),m=document.getElementById(`join-ok`);function h(){f.value=``,p.style.display=`none`,m.style.display=`none`,d.style.display=`flex`,setTimeout(()=>f.focus(),50)}function g(){d.style.display=`none`}document.getElementById(`join-btn`)?.addEventListener(`click`,h),document.getElementById(`join-cancel`)?.addEventListener(`click`,g),document.getElementById(`join-close`)?.addEventListener(`click`,g),d.addEventListener(`click`,e=>{e.target===d&&g()}),document.getElementById(`join-confirm`)?.addEventListener(`click`,()=>{let e=f.value.trim().toUpperCase();if(p.style.display=`none`,m.style.display=`none`,!e.match(/^COMM-[0-9A-F]{4}$/)){p.textContent=`Format must be COMM-XXXX (e.g. COMM-1A2B)`,p.style.display=`block`;return}let t=a(),n=o(),r=n.find(t=>t.id===e);if(r){if((r.members||[]).some(e=>(typeof e==`string`?e:e.id)===t)){m.textContent=`✓ You're already a member of "${r.name}".`,m.style.display=`block`,setTimeout(()=>{g(),u()},1400);return}if((r.join_requests||[]).some(e=>e.userId===t)){m.textContent=`📨 Join request already pending for "${r.name}".`,m.style.display=`block`;return}r.join_requests||=[],r.join_requests.push({userId:t,ts:Date.now()}),r.activityLog||=[],r.activityLog.unshift({ts:Date.now(),action:`join_request_sent`,userId:t,detail:`${t} requested to join`}),s(n),m.textContent=`📨 Join request sent to "${r.name}". An admin must approve.`,m.style.display=`block`,setTimeout(()=>g(),2200);return}let i={id:e,name:`Community ${e}`,description:`Joined via community code`,members:[{id:t,role:`member`}],join_requests:[],activityLog:[{ts:Date.now(),action:`member_joined`,userId:t,detail:`${t} joined via code`}],disappearingMessages:`off`,created:new Date().toISOString(),isJoined:!0};n.push(i),s(n),m.textContent=`✓ Joined ${e} — community added to your list.`,m.style.display=`block`,setTimeout(()=>{g(),u()},1400)}),f?.addEventListener(`keydown`,e=>{e.key===`Enter`&&document.getElementById(`join-confirm`)?.click(),e.key===`Escape`&&g()}),u()})();