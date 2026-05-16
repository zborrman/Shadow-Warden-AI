const C="sw_communities";function I(e){return new URLSearchParams(window.location.search).get(e)||""}function $(){try{return JSON.parse(localStorage.getItem(C)||"[]")}catch{return[]}}function v(e){return e.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")}function E(e){try{return JSON.parse(localStorage.getItem(`sw_tunnel_${e}`)||"[]").length}catch{return 0}}function w(){const e=I("id");if(!e){document.getElementById("comm-header").innerHTML='<p style="color:#FF2D55;font-size:14px">No community ID specified. <a href="/community" style="color:#06b6d4">Back to communities</a></p>';return}const t=$().find(o=>o.id===e);if(!t){document.getElementById("comm-header").innerHTML=`<p style="color:#FF2D55;font-size:14px">Community <code>${v(e)}</code> not found. <a href="/community" style="color:#06b6d4">Back to communities</a></p>`;return}const a=document.getElementById("bc-name");a&&(a.textContent=t.name),document.title=`${t.name} — Shadow Warden AI`;const c=document.getElementById("comm-id-display"),m=document.getElementById("comm-name-display"),l=document.getElementById("comm-desc-display"),s=document.getElementById("comm-created"),d=document.getElementById("comm-member-count");c&&(c.textContent=t.id),m&&(m.textContent=t.name),l&&(l.textContent=t.description||""),s&&(s.textContent=`Created ${new Date(t.created).toLocaleDateString("en-US",{year:"numeric",month:"long",day:"numeric"})}`);const r=(t.members||[]).length;d&&(d.textContent=`${r} member${r!==1?"s":""}`);const x=[{label:"📋 Overview",href:`/community/view?id=${encodeURIComponent(e)}`,active:!0},{label:"👥 Members",href:`/community/members?id=${encodeURIComponent(e)}`},{label:"🔒 Tunnel",href:`/community/tunnel?id=${encodeURIComponent(e)}`},{label:"🔌 Integrations",href:`/community/integrations?id=${encodeURIComponent(e)}`},{label:"📊 Activity",href:`/community/activity?id=${encodeURIComponent(e)}`},{label:"⚙️ Settings",href:`/community/settings?id=${encodeURIComponent(e)}`}],p=document.getElementById("tab-nav");p&&(p.innerHTML=x.map(o=>`
          <a href="${o.href}"
             style="padding:9px 16px;border-radius:10px;font-size:13px;font-weight:600;text-decoration:none;white-space:nowrap;
                    ${o.active?"background:rgba(6,182,212,0.15);border:1px solid rgba(6,182,212,0.3);color:#06b6d4":"background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);color:#64748b"};
                    transition:all 0.15s"
             ${o.active?"":`onmouseover="this.style.color='#94a3b8';this.style.background='rgba(255,255,255,0.07)'" onmouseout="this.style.color='#64748b';this.style.background='rgba(255,255,255,0.03)'"`}>
            ${o.label}
          </a>
        `).join(""));const h=localStorage.getItem("sw_tier")||"pro",u={starter:{name:"Starter",color:"#64748b"},individual:{name:"Individual",color:"#06b6d4"},community_business:{name:"Community Business",color:"#BF5AF2"},pro:{name:"Pro",color:"#FF8C42"},enterprise:{name:"Enterprise",color:"#FFD60A"}},g=u[h]||u.pro,i=E(e),b=document.getElementById("stats-grid");b&&(b.innerHTML=[{label:"Members",value:r.toString(),color:"#06b6d4",icon:"👥"},{label:"Tunnel Messages",value:i.toString(),color:"#BF5AF2",icon:"🔒"},{label:"Current Plan",value:g.name,color:g.color,icon:"⭐",link:"/account"},{label:"Community ID",value:t.id,color:"#30D158",icon:"🪪",mono:!0}].map(o=>`
          <div style="background:#0d1220;border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:16px">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
              <span style="font-size:16px">${o.icon}</span>
              <span style="font-size:11px;color:#475569;text-transform:uppercase;letter-spacing:0.05em;font-weight:600">${o.label}</span>
            </div>
            ${o.link?`<a href="${o.link}" style="font-size:${o.mono?"12px":"18px"};font-weight:700;color:${o.color};${o.mono?"font-family:monospace":""};margin:0;text-decoration:none" onmouseover="this.style.opacity='0.8'" onmouseout="this.style.opacity='1'">${o.value}</a>`:`<p style="font-size:${o.mono?"12px":"22px"};font-weight:700;color:${o.color};${o.mono?"font-family:monospace":""};margin:0">${o.value}</p>`}
          </div>
        `).join(""));const y=document.getElementById("quick-actions");y&&(y.innerHTML=`
          <a href="/community/tunnel?id=${encodeURIComponent(e)}"
             style="display:block;padding:20px;background:#0d1220;border:1px solid rgba(255,255,255,0.06);border-radius:16px;text-decoration:none;transition:border-color 0.2s"
             onmouseover="this.style.borderColor='rgba(6,182,212,0.25)'" onmouseout="this.style.borderColor='rgba(255,255,255,0.06)'">
            <p style="font-size:24px;margin-bottom:8px">🔒</p>
            <p style="font-size:15px;font-weight:700;color:#f1f5f9;margin:0 0 4px">Open Tunnel</p>
            <p style="font-size:12px;color:#64748b;margin:0">End-to-end encrypted channel${i>0?` · ${i} messages`:""}</p>
          </a>
          <a href="/community/members?id=${encodeURIComponent(e)}"
             style="display:block;padding:20px;background:#0d1220;border:1px solid rgba(255,255,255,0.06);border-radius:16px;text-decoration:none;transition:border-color 0.2s"
             onmouseover="this.style.borderColor='rgba(191,90,242,0.25)'" onmouseout="this.style.borderColor='rgba(255,255,255,0.06)'">
            <p style="font-size:24px;margin-bottom:8px">👥</p>
            <p style="font-size:15px;font-weight:700;color:#f1f5f9;margin:0 0 4px">Manage Members</p>
            <p style="font-size:12px;color:#64748b;margin:0">Invite, remove, merge communities</p>
          </a>
        `)}w();document.getElementById("copy-code-btn")?.addEventListener("click",()=>{const e=new URLSearchParams(window.location.search).get("id")||"";navigator.clipboard.writeText(e).then(()=>{const n=document.getElementById("copy-code-btn");n&&(n.textContent="✓ Copied!",setTimeout(()=>{n.textContent="Copy Code"},1800))})});const f=document.getElementById("share-code-text");if(f){const e=new URLSearchParams(window.location.search).get("id")||"";e&&(f.textContent=e)}
