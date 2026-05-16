const x="sw_communities";function h(o){return new URLSearchParams(window.location.search).get(o)||""}function $(){try{return JSON.parse(localStorage.getItem(x)||"[]")}catch{return[]}}function I(o){return o.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")}function C(o){try{return JSON.parse(localStorage.getItem(`sw_tunnel_${o}`)||"[]").length}catch{return 0}}function v(){const o=h("id");if(!o){document.getElementById("comm-header").innerHTML='<p style="color:#FF2D55;font-size:14px">No community ID specified. <a href="/community" style="color:#06b6d4">Back to communities</a></p>';return}const t=$().find(e=>e.id===o);if(!t){document.getElementById("comm-header").innerHTML=`<p style="color:#FF2D55;font-size:14px">Community <code>${I(o)}</code> not found. <a href="/community" style="color:#06b6d4">Back to communities</a></p>`;return}const i=document.getElementById("bc-name");i&&(i.textContent=t.name),document.title=`${t.name} — Shadow Warden AI`;const a=document.getElementById("comm-id-display"),c=document.getElementById("comm-name-display"),m=document.getElementById("comm-desc-display"),l=document.getElementById("comm-created"),s=document.getElementById("comm-member-count");a&&(a.textContent=t.id),c&&(c.textContent=t.name),m&&(m.textContent=t.description||""),l&&(l.textContent=`Created ${new Date(t.created).toLocaleDateString("en-US",{year:"numeric",month:"long",day:"numeric"})}`);const n=(t.members||[]).length;s&&(s.textContent=`${n} member${n!==1?"s":""}`);const y=[{label:"📋 Overview",href:`/community/view?id=${encodeURIComponent(o)}`,active:!0},{label:"👥 Members",href:`/community/members?id=${encodeURIComponent(o)}`},{label:"🔒 Tunnel",href:`/community/tunnel?id=${encodeURIComponent(o)}`},{label:"🔌 Integrations",href:`/community/integrations?id=${encodeURIComponent(o)}`},{label:"⚙️ Settings",href:`/community/settings?id=${encodeURIComponent(o)}`}],d=document.getElementById("tab-nav");d&&(d.innerHTML=y.map(e=>`
          <a href="${e.href}"
             style="padding:9px 16px;border-radius:10px;font-size:13px;font-weight:600;text-decoration:none;white-space:nowrap;
                    ${e.active?"background:rgba(6,182,212,0.15);border:1px solid rgba(6,182,212,0.3);color:#06b6d4":"background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);color:#64748b"};
                    transition:all 0.15s"
             ${e.active?"":`onmouseover="this.style.color='#94a3b8';this.style.background='rgba(255,255,255,0.07)'" onmouseout="this.style.color='#64748b';this.style.background='rgba(255,255,255,0.03)'"`}>
            ${e.label}
          </a>
        `).join(""));const f=localStorage.getItem("sw_tier")||"pro",p={starter:{name:"Starter",color:"#64748b"},individual:{name:"Individual",color:"#06b6d4"},community_business:{name:"Community Business",color:"#BF5AF2"},pro:{name:"Pro",color:"#FF8C42"},enterprise:{name:"Enterprise",color:"#FFD60A"}},u=p[f]||p.pro,r=C(o),g=document.getElementById("stats-grid");g&&(g.innerHTML=[{label:"Members",value:n.toString(),color:"#06b6d4",icon:"👥"},{label:"Tunnel Messages",value:r.toString(),color:"#BF5AF2",icon:"🔒"},{label:"Current Plan",value:u.name,color:u.color,icon:"⭐",link:"/account"},{label:"Community ID",value:t.id,color:"#30D158",icon:"🪪",mono:!0}].map(e=>`
          <div style="background:#0d1220;border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:16px">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
              <span style="font-size:16px">${e.icon}</span>
              <span style="font-size:11px;color:#475569;text-transform:uppercase;letter-spacing:0.05em;font-weight:600">${e.label}</span>
            </div>
            ${e.link?`<a href="${e.link}" style="font-size:${e.mono?"12px":"18px"};font-weight:700;color:${e.color};${e.mono?"font-family:monospace":""};margin:0;text-decoration:none" onmouseover="this.style.opacity='0.8'" onmouseout="this.style.opacity='1'">${e.value}</a>`:`<p style="font-size:${e.mono?"12px":"22px"};font-weight:700;color:${e.color};${e.mono?"font-family:monospace":""};margin:0">${e.value}</p>`}
          </div>
        `).join(""));const b=document.getElementById("quick-actions");b&&(b.innerHTML=`
          <a href="/community/tunnel?id=${encodeURIComponent(o)}"
             style="display:block;padding:20px;background:#0d1220;border:1px solid rgba(255,255,255,0.06);border-radius:16px;text-decoration:none;transition:border-color 0.2s"
             onmouseover="this.style.borderColor='rgba(6,182,212,0.25)'" onmouseout="this.style.borderColor='rgba(255,255,255,0.06)'">
            <p style="font-size:24px;margin-bottom:8px">🔒</p>
            <p style="font-size:15px;font-weight:700;color:#f1f5f9;margin:0 0 4px">Open Tunnel</p>
            <p style="font-size:12px;color:#64748b;margin:0">End-to-end encrypted channel${r>0?` · ${r} messages`:""}</p>
          </a>
          <a href="/community/members?id=${encodeURIComponent(o)}"
             style="display:block;padding:20px;background:#0d1220;border:1px solid rgba(255,255,255,0.06);border-radius:16px;text-decoration:none;transition:border-color 0.2s"
             onmouseover="this.style.borderColor='rgba(191,90,242,0.25)'" onmouseout="this.style.borderColor='rgba(255,255,255,0.06)'">
            <p style="font-size:24px;margin-bottom:8px">👥</p>
            <p style="font-size:15px;font-weight:700;color:#f1f5f9;margin:0 0 4px">Manage Members</p>
            <p style="font-size:12px;color:#64748b;margin:0">Invite, remove, merge communities</p>
          </a>
        `)}v();
