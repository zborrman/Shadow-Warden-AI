(()=>{const x="sw_communities",C="sw_user_id",k="sw_tier",I={starter:{name:"Starter",color:"#64748b",maxComm:0},individual:{name:"Individual",color:"#06b6d4",maxComm:1},community_business:{name:"Community Business",color:"#BF5AF2",maxComm:3},pro:{name:"Pro",color:"#FF8C42",maxComm:10},enterprise:{name:"Enterprise",color:"#FFD60A",maxComm:-1}};function S(){return localStorage.getItem(k)||"pro"}function L(){return I[S()]||I.pro}function $(){let e=localStorage.getItem(C);if(!e){const o=crypto.getRandomValues(new Uint8Array(3));e="USR-"+Array.from(o).map(a=>a.toString(16).padStart(2,"0")).join("").toUpperCase().slice(0,4),localStorage.setItem(C,e)}return e}function E(){try{return JSON.parse(localStorage.getItem(x)||"[]")}catch{return[]}}function w(e){localStorage.setItem(x,JSON.stringify(e))}function p(e){return String(e).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")}function M(e){try{return JSON.parse(localStorage.getItem(`sw_tunnel_${e}`)||"[]").length}catch{return 0}}function u(){const e=$(),o=document.getElementById("my-uid");o&&(o.textContent=e);const a=document.getElementById("user-chip");a&&(a.textContent=e.replace("USR-","").slice(0,2));const t=L(),m=E(),l=document.getElementById("tier-bar");if(l){const n=m.length,r=t.maxComm,c=r<=0?0:Math.min(n/r*100,100);l.innerHTML=`
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
          <span style="padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;font-family:monospace;background:${t.color}18;border:1px solid ${t.color}30;color:${t.color}">${t.name.toUpperCase()}</span>
          ${r===-1?`<span style="font-size:13px;color:#64748b">${n} communities (unlimited)</span>`:r===0?'<span style="font-size:13px;color:#f87171">0 private communities on Starter — <a href="/price" style="color:#BF5AF2;text-decoration:none">upgrade</a></span>':`<span style="font-size:13px;color:#64748b">${n} / ${r} communities</span>`}
          ${r>0?`<div style="flex:1;min-width:80px;max-width:140px;height:4px;border-radius:2px;background:#1e293b;overflow:hidden"><div style="height:100%;width:${c}%;background:${c>=100?"#f87171":t.color};border-radius:2px"></div></div>`:""}
          <a href="/price" style="margin-left:auto;font-size:12px;color:#475569;text-decoration:none" onmouseover="this.style.color='#BF5AF2'" onmouseout="this.style.color='#475569'">Change plan →</a>
        </div>`}const j=t.maxComm!==-1&&m.length>=t.maxComm,i=document.getElementById("new-btn");i&&j&&(i.href="/price",i.textContent=t.maxComm===0?"Upgrade to create":"↑ Upgrade for more",i.style.background="rgba(255,255,255,0.06)",i.style.color="#94a3b8");const v=(document.getElementById("comm-search")?.value||"").toLowerCase(),B=v?m.filter(n=>n.name.toLowerCase().includes(v)||n.id.toLowerCase().includes(v)):m,b=document.getElementById("comm-grid");if(m.length===0){b.innerHTML=`
        <div class="empty-state">
          <div class="empty-icon">◈</div>
          <p class="empty-title">No communities yet</p>
          <p class="empty-sub">Create your first secure collaboration space.<br>
            Each community gets a unique <code style="color:#BF5AF2;font-family:monospace">COMM-XXXX</code> identifier.</p>
          <a href="/community/new" class="btn-primary-violet" style="display:inline-flex;text-decoration:none">+ Create First Community</a>
        </div>`;return}if(B.length===0){b.innerHTML=`<p style="color:#475569;padding:24px 0">No communities match "${p(v)}".</p>`;return}b.innerHTML=`<div class="comm-grid">${B.map(n=>{const r=(n.members||[]).length,c=M(n.id),F=(n.join_requests||[]).some(h=>h.userId===e),q=(n.members||[]).find(h=>h.id===e)?.role==="owner";return`
        <div class="comm-card" onclick="location.href='/community/view?id=${encodeURIComponent(n.id)}'">
          <div class="card-top">
            <div style="min-width:0">
              <div class="card-id-row">
                <span class="card-id">${p(n.id)}</span>
                ${n.isJoined||q?'<span class="badge-joined">✓ JOINED</span>':""}
                ${F?'<span class="badge-pending">PENDING</span>':""}
              </div>
              <div class="card-name">${p(n.name)}</div>
            </div>
            <span class="card-member-chip">${r} member${r!==1?"s":""}</span>
          </div>
          ${n.description?`<p class="card-desc">${p(n.description)}</p>`:""}
          <div class="card-stats">
            ${c>0?`<span>💬 ${c} message${c!==1?"s":""}</span>`:""}
            <span class="e2ee-pill">🔐 E2EE</span>
          </div>
          <div class="card-actions" onclick="event.stopPropagation()">
            <a href="/community/view?id=${encodeURIComponent(n.id)}" class="card-btn-main">Open Portal →</a>
            <a href="/community/view?id=${encodeURIComponent(n.id)}&tab=tunnel" class="card-btn-ghost">🔒 Tunnel${c>0?` (${c})`:""}</a>
            <a href="/community/view?id=${encodeURIComponent(n.id)}&tab=members" class="card-btn-ghost">Members</a>
          </div>
          <div class="card-date">Created ${new Date(n.created||Date.now()).toLocaleDateString()}</div>
        </div>`}).join("")}</div>`}document.getElementById("comm-search")?.addEventListener("input",u);const y=document.getElementById("join-modal"),g=document.getElementById("join-input"),f=document.getElementById("join-err"),s=document.getElementById("join-ok");function _(){g.value="",f.style.display="none",s.style.display="none",y.style.display="flex",setTimeout(()=>g.focus(),50)}function d(){y.style.display="none"}document.getElementById("join-btn")?.addEventListener("click",_),document.getElementById("join-cancel")?.addEventListener("click",d),document.getElementById("join-close")?.addEventListener("click",d),y.addEventListener("click",e=>{e.target===y&&d()}),document.getElementById("join-confirm")?.addEventListener("click",()=>{const e=g.value.trim().toUpperCase();if(f.style.display="none",s.style.display="none",!e.match(/^COMM-[0-9A-F]{4}$/)){f.textContent="Format must be COMM-XXXX (e.g. COMM-1A2B)",f.style.display="block";return}const o=$(),a=E(),t=a.find(l=>l.id===e);if(t){if((t.members||[]).some(i=>(typeof i=="string"?i:i.id)===o)){s.textContent=`✓ You're already a member of "${t.name}".`,s.style.display="block",setTimeout(()=>{d(),u()},1400);return}if((t.join_requests||[]).some(i=>i.userId===o)){s.textContent=`📨 Join request already pending for "${t.name}".`,s.style.display="block";return}t.join_requests||(t.join_requests=[]),t.join_requests.push({userId:o,ts:Date.now()}),t.activityLog||(t.activityLog=[]),t.activityLog.unshift({ts:Date.now(),action:"join_request_sent",userId:o,detail:`${o} requested to join`}),w(a),s.textContent=`📨 Join request sent to "${t.name}". An admin must approve.`,s.style.display="block",setTimeout(()=>d(),2200);return}const m={id:e,name:`Community ${e}`,description:"Joined via community code",members:[{id:o,role:"member"}],join_requests:[],activityLog:[{ts:Date.now(),action:"member_joined",userId:o,detail:`${o} joined via code`}],disappearingMessages:"off",created:new Date().toISOString(),isJoined:!0};a.push(m),w(a),s.textContent=`✓ Joined ${e} — community added to your list.`,s.style.display="block",setTimeout(()=>{d(),u()},1400)}),g?.addEventListener("keydown",e=>{e.key==="Enter"&&document.getElementById("join-confirm")?.click(),e.key==="Escape"&&d()}),u()})();
