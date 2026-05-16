const u="sw_communities";let r="",s="";function g(e){return new URLSearchParams(window.location.search).get(e)||""}function p(){try{return JSON.parse(localStorage.getItem(u)||"[]")}catch{return[]}}function c(e){return`sw_tunnel_${e}`}function m(e){try{return JSON.parse(localStorage.getItem(c(e))||"[]")}catch{return[]}}function b(e,t){localStorage.setItem(c(e),JSON.stringify(t))}function d(e){return e.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")}function f(e){const t=[{label:"📋 Overview",href:`/community/view?id=${encodeURIComponent(e)}`},{label:"👥 Members",href:`/community/members?id=${encodeURIComponent(e)}`},{label:"🔒 Tunnel",href:`/community/tunnel?id=${encodeURIComponent(e)}`,active:!0},{label:"🔌 Integrations",href:`/community/integrations?id=${encodeURIComponent(e)}`},{label:"⚙️ Settings",href:`/community/settings?id=${encodeURIComponent(e)}`}],o=document.getElementById("tab-nav");o&&(o.innerHTML=t.map(n=>`
          <a href="${n.href}"
             style="padding:9px 16px;border-radius:10px;font-size:13px;font-weight:600;text-decoration:none;white-space:nowrap;
                    ${n.active?"background:rgba(6,182,212,0.15);border:1px solid rgba(6,182,212,0.3);color:#06b6d4":"background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);color:#64748b"};
                    transition:all 0.15s"
             ${n.active?"":`onmouseover="this.style.color='#94a3b8';this.style.background='rgba(255,255,255,0.07)'" onmouseout="this.style.color='#64748b';this.style.background='rgba(255,255,255,0.03)'"`}>
            ${n.label}
          </a>
        `).join(""))}function a(){const e=m(r),t=document.getElementById("messages");if(t){if(e.length===0){t.innerHTML=`
          <div style="text-align:center;padding:40px 20px">
            <p style="font-size:36px;margin-bottom:12px">🔒</p>
            <p style="color:#475569;font-size:14px">No messages yet. Say something.</p>
          </div>`;return}t.innerHTML=e.map(o=>{const n=o.sender===s;return`
          <div style="display:flex;flex-direction:${n?"row-reverse":"row"};gap:10px;margin-bottom:12px;align-items:flex-end">
            <div style="max-width:72%;min-width:80px">
              <p style="font-size:10px;font-family:monospace;color:#475569;margin-bottom:4px;${n?"text-align:right":""}">
                ${d(o.sender)} · ${new Date(o.ts).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"})}
              </p>
              <div style="padding:10px 14px;border-radius:${n?"14px 14px 4px 14px":"14px 14px 14px 4px"};
                          ${n?"background:rgba(6,182,212,0.15);border:1px solid rgba(6,182,212,0.25)":"background:#0d1220;border:1px solid rgba(255,255,255,0.08)"}">
                <p style="font-size:14px;color:#e2e8f0;margin:0;line-height:1.5;word-break:break-word">${d(o.text)}</p>
              </div>
            </div>
          </div>`}).join(""),t.scrollTop=t.scrollHeight}}function l(e){if(!e.trim())return;const t=m(r);t.push({sender:s,text:e.trim(),ts:new Date().toISOString()}),b(r,t),a()}function y(){if(r=g("id"),s=localStorage.getItem("sw_user_id")||"USER-ANON",!r){document.body.innerHTML='<div style="padding:80px 24px;text-align:center;color:#FF2D55">No community ID. <a href="/community" style="color:#06b6d4">Back</a></div>';return}const t=p().find(i=>i.id===r);if(!t){document.body.innerHTML='<div style="padding:80px 24px;text-align:center;color:#FF2D55">Community not found. <a href="/community" style="color:#06b6d4">Back</a></div>';return}const o=document.getElementById("bc-comm");o&&(o.textContent=t.name,o.href=`/community/view?id=${encodeURIComponent(r)}`),document.title=`Tunnel · ${t.name} — Shadow Warden AI`,f(r),a();const n=document.getElementById("msg-input");document.getElementById("send-btn")?.addEventListener("click",()=>{l(n.value),n.value="",n.focus()}),n?.addEventListener("keydown",i=>{i.key==="Enter"&&!i.shiftKey&&(i.preventDefault(),l(n.value),n.value="")}),document.getElementById("clear-btn")?.addEventListener("click",()=>{confirm("Clear all tunnel messages? This cannot be undone.")&&(localStorage.removeItem(c(r)),a())})}y();
