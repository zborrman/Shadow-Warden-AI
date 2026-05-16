const b="sw_communities";function y(e){return new URLSearchParams(window.location.search).get(e)||""}function f(){try{return JSON.parse(localStorage.getItem(b)||"[]")}catch{return[]}}function x(e){return e.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")}function h(e){try{return JSON.parse(localStorage.getItem(`sw_tunnel_${e}`)||"[]").length}catch{return 0}}function I(){const e=y("id");if(!e){document.getElementById("comm-header").innerHTML='<p style="color:#FF2D55;font-size:14px">No community ID specified. <a href="/community" style="color:#06b6d4">Back to communities</a></p>';return}const t=f().find(o=>o.id===e);if(!t){document.getElementById("comm-header").innerHTML=`<p style="color:#FF2D55;font-size:14px">Community <code>${x(e)}</code> not found. <a href="/community" style="color:#06b6d4">Back to communities</a></p>`;return}const i=document.getElementById("bc-name");i&&(i.textContent=t.name),document.title=`${t.name} — Shadow Warden AI`;const a=document.getElementById("comm-id-display"),c=document.getElementById("comm-name-display"),m=document.getElementById("comm-desc-display"),s=document.getElementById("comm-created"),l=document.getElementById("comm-member-count");a&&(a.textContent=t.id),c&&(c.textContent=t.name),m&&(m.textContent=t.description||""),s&&(s.textContent=`Created ${new Date(t.created).toLocaleDateString("en-US",{year:"numeric",month:"long",day:"numeric"})}`);const n=(t.members||[]).length;l&&(l.textContent=`${n} member${n!==1?"s":""}`);const g=[{label:"📋 Overview",href:`/community/view?id=${encodeURIComponent(e)}`,active:!0},{label:"👥 Members",href:`/community/members?id=${encodeURIComponent(e)}`},{label:"🔒 Tunnel",href:`/community/tunnel?id=${encodeURIComponent(e)}`},{label:"🔌 Integrations",href:`/community/integrations?id=${encodeURIComponent(e)}`},{label:"⚙️ Settings",href:`/community/settings?id=${encodeURIComponent(e)}`}],d=document.getElementById("tab-nav");d&&(d.innerHTML=g.map(o=>`
          <a href="${o.href}"
             style="padding:9px 16px;border-radius:10px;font-size:13px;font-weight:600;text-decoration:none;white-space:nowrap;
                    ${o.active?"background:rgba(6,182,212,0.15);border:1px solid rgba(6,182,212,0.3);color:#06b6d4":"background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);color:#64748b"};
                    transition:all 0.15s"
             ${o.active?"":`onmouseover="this.style.color='#94a3b8';this.style.background='rgba(255,255,255,0.07)'" onmouseout="this.style.color='#64748b';this.style.background='rgba(255,255,255,0.03)'"`}>
            ${o.label}
          </a>
        `).join(""));const r=h(e),p=document.getElementById("stats-grid");p&&(p.innerHTML=[{label:"Members",value:n.toString(),color:"#06b6d4",icon:"👥"},{label:"Tunnel Messages",value:r.toString(),color:"#BF5AF2",icon:"🔒"},{label:"Community ID",value:t.id,color:"#30D158",icon:"🪪",mono:!0},{label:"Status",value:"Active",color:"#30D158",icon:"✅"}].map(o=>`
          <div style="background:#0d1220;border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:16px">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
              <span style="font-size:16px">${o.icon}</span>
              <span style="font-size:11px;color:#475569;text-transform:uppercase;letter-spacing:0.05em;font-weight:600">${o.label}</span>
            </div>
            <p style="font-size:${o.mono?"12px":"22px"};font-weight:700;color:${o.color};${o.mono?"font-family:monospace":""};margin:0">${o.value}</p>
          </div>
        `).join(""));const u=document.getElementById("quick-actions");u&&(u.innerHTML=`
          <a href="/community/tunnel?id=${encodeURIComponent(e)}"
             style="display:block;padding:20px;background:#0d1220;border:1px solid rgba(255,255,255,0.06);border-radius:16px;text-decoration:none;transition:border-color 0.2s"
             onmouseover="this.style.borderColor='rgba(6,182,212,0.25)'" onmouseout="this.style.borderColor='rgba(255,255,255,0.06)'">
            <p style="font-size:24px;margin-bottom:8px">🔒</p>
            <p style="font-size:15px;font-weight:700;color:#f1f5f9;margin:0 0 4px">Open Tunnel</p>
            <p style="font-size:12px;color:#64748b;margin:0">End-to-end encrypted channel${r>0?` · ${r} messages`:""}</p>
          </a>
          <a href="/community/members?id=${encodeURIComponent(e)}"
             style="display:block;padding:20px;background:#0d1220;border:1px solid rgba(255,255,255,0.06);border-radius:16px;text-decoration:none;transition:border-color 0.2s"
             onmouseover="this.style.borderColor='rgba(191,90,242,0.25)'" onmouseout="this.style.borderColor='rgba(255,255,255,0.06)'">
            <p style="font-size:24px;margin-bottom:8px">👥</p>
            <p style="font-size:15px;font-weight:700;color:#f1f5f9;margin:0 0 4px">Manage Members</p>
            <p style="font-size:12px;color:#64748b;margin:0">Invite, remove, merge communities</p>
          </a>
        `)}I();
