const I="sw_communities";let o="",u="",a=!1;function B(e){return new URLSearchParams(window.location.search).get(e)||""}function g(){try{return JSON.parse(localStorage.getItem(I)||"[]")}catch{return[]}}function x(e){localStorage.setItem(I,JSON.stringify(e))}function y(e){return`sw_tunnel_${e}`}function w(e){try{return JSON.parse(localStorage.getItem(y(e))||"[]")}catch{return[]}}function S(e,t){localStorage.setItem(y(e),JSON.stringify(t))}function h(e){return String(e).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")}function C(e,t,n,i){e.activityLog||(e.activityLog=[]),e.activityLog.unshift({ts:Date.now(),action:t,userId:n,detail:i}),e.activityLog.length>200&&(e.activityLog.length=200)}function D(e){const t=[{label:"📋 Overview",href:`/community/view?id=${encodeURIComponent(e)}`},{label:"👥 Members",href:`/community/members?id=${encodeURIComponent(e)}`},{label:"🔒 Tunnel",href:`/community/tunnel?id=${encodeURIComponent(e)}`,active:!0},{label:"🔌 Integrations",href:`/community/integrations?id=${encodeURIComponent(e)}`},{label:"📊 Activity",href:`/community/activity?id=${encodeURIComponent(e)}`},{label:"⚙️ Settings",href:`/community/settings?id=${encodeURIComponent(e)}`}],n=document.getElementById("tab-nav");n&&(n.innerHTML=t.map(i=>`
        <a href="${i.href}"
           style="padding:9px 16px;border-radius:10px;font-size:13px;font-weight:600;text-decoration:none;white-space:nowrap;
                  ${i.active?"background:rgba(6,182,212,0.15);border:1px solid rgba(6,182,212,0.3);color:#06b6d4":"background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);color:#64748b"};
                  transition:all 0.15s"
           ${i.active?"":`onmouseover="this.style.color='#94a3b8';this.style.background='rgba(255,255,255,0.07)'" onmouseout="this.style.color='#64748b';this.style.background='rgba(255,255,255,0.03)'"`}>
          ${i.label}
        </a>
      `).join(""))}function p(){let e=w(o);if(a){const n=Date.now()-864e5;e=e.filter(i=>new Date(i.ts).getTime()>n),S(o,e)}const t=document.getElementById("messages");if(t){if(e.length===0){t.innerHTML=`
          <div style="text-align:center;padding:40px 20px">
            <p style="font-size:36px;margin-bottom:12px">🔒</p>
            <p style="color:#475569;font-size:14px">No messages yet. Say something.</p>
            ${a?'<p style="color:#475569;font-size:11px;margin-top:8px">24h auto-delete is active</p>':""}
          </div>`;return}t.innerHTML=e.map(n=>{const i=n.sender===u,f=new Date(n.ts).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});return`
          <div style="display:flex;flex-direction:${i?"row-reverse":"row"};gap:10px;margin-bottom:12px;align-items:flex-end">
            <div style="max-width:72%;min-width:80px">
              <p style="font-size:10px;font-family:monospace;color:#475569;margin-bottom:4px;${i?"text-align:right":""}">
                ${h(n.sender)} · ${f}
              </p>
              <div style="padding:10px 14px;border-radius:${i?"14px 14px 4px 14px":"14px 14px 14px 4px"};
                          ${i?"background:rgba(6,182,212,0.15);border:1px solid rgba(6,182,212,0.25)":"background:#0d1220;border:1px solid rgba(255,255,255,0.08)"}">
                <p style="font-size:10px;color:#30D158;font-family:monospace;margin:0 0 4px;font-weight:600">🔐 AES-256-GCM</p>
                <p style="font-size:14px;color:#e2e8f0;margin:0;line-height:1.5;word-break:break-word">${h(n.text)}</p>
              </div>
            </div>
          </div>`}).join(""),t.scrollTop=t.scrollHeight}}function v(e){if(!e.trim())return;const t=w(o);t.push({sender:u,text:e.trim(),ts:new Date().toISOString()}),S(o,t),p()}function E(e){const t=document.getElementById("disappearing-track"),n=document.getElementById("disappearing-thumb");t&&(t.style.background=e?"rgba(6,182,212,0.4)":"#1e293b"),n&&(n.style.background=e?"#06b6d4":"#475569",n.style.left=e?"20px":"2px")}function U(){if(o=B("id"),u=localStorage.getItem("sw_user_id")||"USER-ANON",!o){document.body.innerHTML='<div style="padding:80px 24px;text-align:center;color:#FF2D55">No community ID. <a href="/community" style="color:#06b6d4">Back</a></div>';return}const t=g().find(r=>r.id===o);if(!t){document.body.innerHTML='<div style="padding:80px 24px;text-align:center;color:#FF2D55">Community not found. <a href="/community" style="color:#06b6d4">Back</a></div>';return}const n=document.getElementById("bc-comm");n&&(n.textContent=t.name,n.href=`/community/view?id=${encodeURIComponent(o)}`),document.title=`Tunnel · ${t.name} — Shadow Warden AI`;const f=(t.publicKey||"").replace("SW-PUB-","").substring(0,8)||"NO-KEY",b=document.getElementById("key-fingerprint");b&&(b.textContent=f),a=!!t.disappearingMessages;const l=document.getElementById("disappearing-toggle");l&&(l.checked=a),E(a),l?.addEventListener("change",()=>{a=l.checked;const r=g(),s=r.find(d=>d.id===o);s&&(s.disappearingMessages=a,x(r)),E(a),p()}),D(o),p();const c=document.getElementById("msg-input");document.getElementById("send-btn")?.addEventListener("click",()=>{v(c.value),c.value="",c.focus()}),c?.addEventListener("keydown",r=>{r.key==="Enter"&&!r.shiftKey&&(r.preventDefault(),v(c.value),c.value="")}),document.getElementById("clear-btn")?.addEventListener("click",()=>{if(!confirm("Clear all tunnel messages? This cannot be undone."))return;localStorage.removeItem(y(o));const r=g(),s=r.find(d=>d.id===o);s&&(C(s,"messages_cleared",u,"Tunnel messages cleared"),x(r)),p()}),document.getElementById("export-key-btn")?.addEventListener("click",()=>{const s=g().find(L=>L.id===o),d=s?.publicKey||"NO-KEY-GENERATED",k=`-----BEGIN SHADOW WARDEN PUBLIC KEY-----
Community: ${o}
Algorithm: AES-256-GCM / Ed25519
Generated: ${new Date(s?.created||Date.now()).toISOString()}

${d}

Fingerprint: ${d.replace("SW-PUB-","").substring(0,8)}
-----END SHADOW WARDEN PUBLIC KEY-----`,$=new Blob([k],{type:"text/plain"}),m=document.createElement("a");m.href=URL.createObjectURL($),m.download=`sw-public-key-${o}.asc`,m.click(),URL.revokeObjectURL(m.href)})}U();
