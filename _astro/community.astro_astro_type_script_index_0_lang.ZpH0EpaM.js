const x="sw_communities",f="sw_user_id",w="sw_tier",h={starter:{name:"Starter",color:"#64748b",maxComm:0,obs:!1,slack:!1},individual:{name:"Individual",color:"#06b6d4",maxComm:1,obs:!1,slack:!1},community_business:{name:"Community Business",color:"#BF5AF2",maxComm:3,obs:!0,slack:!1},pro:{name:"Pro",color:"#FF8C42",maxComm:10,obs:!0,slack:!0},enterprise:{name:"Enterprise",color:"#FFD60A",maxComm:-1,obs:!0,slack:!0}};function $(){return localStorage.getItem(w)||"pro"}function E(){return h[$()]||h.pro}function v(){let e=localStorage.getItem(f);if(!e){const r=crypto.getRandomValues(new Uint8Array(2));e=`USER-${Array.from(r).map(n=>n.toString(16).padStart(2,"0")).join("").toUpperCase()}`,localStorage.setItem(f,e)}return e}function C(){try{return JSON.parse(localStorage.getItem(x)||"[]")}catch{return[]}}function b(e){return e.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}function I(e){try{return JSON.parse(localStorage.getItem(`sw_tunnel_${e}`)||"[]").length}catch{return 0}}function y(){const e=v(),r=document.getElementById("my-user-id");r&&(r.textContent=e);const t=E(),n=C(),a=document.getElementById("communities-list");if(!a)return;const c=document.getElementById("tier-banner");if(c){const o=n.length,i=t.maxComm,l=i<=0?i===-1?0:100:Math.min(o/i*100,100);c.innerHTML=`
          <div style="display:flex;align-items:center;gap-12px;gap:12px;flex-wrap:wrap">
            <span style="padding:4px 10px;border-radius:20px;font-size:11px;font-weight:700;font-family:monospace;background:${t.color}14;border:1px solid ${t.color}35;color:${t.color}">
              ${t.name.toUpperCase()}
            </span>
            ${i===-1?`<span style="font-size:13px;color:#64748b">${o} communities (unlimited)</span>`:i===0?'<span style="font-size:13px;color:#FF2D55">0 private communities on this plan</span>':`<span style="font-size:13px;color:#64748b">${o} / ${i} communities used</span>`}
            ${i>0?`
            <div style="flex:1;min-width:80px;max-width:160px;height:4px;border-radius:2px;background:#1e293b;overflow:hidden">
              <div style="height:100%;width:${l}%;background:${l>=100?"#FF2D55":t.color};border-radius:2px;transition:width 0.5s"></div>
            </div>`:""}
            <a href="/account" style="margin-left:auto;font-size:12px;color:#475569;text-decoration:none" onmouseover="this.style.color='#06b6d4'" onmouseout="this.style.color='#475569'">
              Change plan →
            </a>
          </div>`}const k=t.maxComm!==-1&&n.length>=t.maxComm,d=document.getElementById("new-comm-btn");if(d&&k&&(d.setAttribute("href","/price"),d.textContent=t.maxComm===0?"Upgrade to create":"↑ Upgrade for more",d.style.background="rgba(255,255,255,0.06)",d.style.color="#94a3b8"),n.length===0){a.innerHTML=`
          <div style="text-align:center;padding:80px 20px;border:1px dashed rgba(255,255,255,0.08);border-radius:20px">
            <div style="font-size:52px;margin-bottom:16px">🏛️</div>
            <p style="color:#e2e8f0;font-size:18px;font-weight:700;margin-bottom:8px">No communities yet</p>
            <p style="color:#475569;font-size:14px;margin-bottom:28px;line-height:1.65">
              Create your first secure collaboration space.<br>
              Each community gets a unique <code style="color:#06b6d4;font-family:monospace">COMM-XXXX</code> identifier.
            </p>
            <a href="/community/new" style="display:inline-block;padding:13px 32px;background:linear-gradient(135deg,#06b6d4,#0e7490);color:white;border-radius:12px;text-decoration:none;font-weight:700;font-size:14px">
              + Create First Community
            </a>
          </div>`;return}a.innerHTML=`
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px">
          ${n.map(o=>{const i=(o.members||[]).length,l=I(o.id);return`
            <div style="background:#0d1220;border:1px solid rgba(255,255,255,0.06);border-radius:16px;padding:20px;display:flex;flex-direction:column;gap:12px;transition:border-color 0.2s"
                 onmouseover="this.style.borderColor='rgba(6,182,212,0.25)'"
                 onmouseout="this.style.borderColor='rgba(255,255,255,0.06)'">
              <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">
                <div style="min-width:0">
                  <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
                    <p style="font-size:10px;font-family:monospace;color:#06b6d4;letter-spacing:0.05em;margin:0">${b(o.id)}</p>
                    ${o.isJoined?'<span style="padding:1px 6px;border-radius:4px;background:rgba(48,209,88,0.12);border:1px solid rgba(48,209,88,0.25);font-size:9px;font-weight:700;color:#30D158;font-family:monospace">JOINED</span>':""}
                  </div>
                  <h3 style="font-size:16px;font-weight:700;color:#f1f5f9;line-height:1.3;margin:0">${b(o.name)}</h3>
                </div>
                <span style="padding:3px 10px;border-radius:20px;background:rgba(6,182,212,0.08);border:1px solid rgba(6,182,212,0.18);font-size:10px;font-weight:700;color:#06b6d4;font-family:monospace;white-space:nowrap;flex-shrink:0">
                  ${i} member${i!==1?"s":""}
                </span>
              </div>
              ${o.description?`<p style="font-size:13px;color:#64748b;line-height:1.55;margin:0">${b(o.description)}</p>`:""}
              <div style="display:flex;gap:8px">
                <a href="/community/view?id=${encodeURIComponent(o.id)}"
                   style="flex:1;text-align:center;padding:9px 8px;background:rgba(6,182,212,0.1);border:1px solid rgba(6,182,212,0.2);border-radius:10px;color:#06b6d4;text-decoration:none;font-size:12px;font-weight:600;transition:background 0.15s"
                   onmouseover="this.style.background='rgba(6,182,212,0.2)'" onmouseout="this.style.background='rgba(6,182,212,0.1)'">
                  Overview
                </a>
                <a href="/community/tunnel?id=${encodeURIComponent(o.id)}"
                   style="flex:1;text-align:center;padding:9px 8px;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:10px;color:#94a3b8;text-decoration:none;font-size:12px;font-weight:600;transition:background 0.15s"
                   onmouseover="this.style.background='rgba(255,255,255,0.07)'" onmouseout="this.style.background='rgba(255,255,255,0.03)'">
                  🔒 Tunnel${l>0?` (${l})`:""}
                </a>
                <a href="/community/members?id=${encodeURIComponent(o.id)}"
                   style="flex:1;text-align:center;padding:9px 8px;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:10px;color:#94a3b8;text-decoration:none;font-size:12px;font-weight:600;transition:background 0.15s"
                   onmouseover="this.style.background='rgba(255,255,255,0.07)'" onmouseout="this.style.background='rgba(255,255,255,0.03)'">
                  Members
                </a>
              </div>
              <p style="font-size:11px;color:#334155;font-family:monospace;margin:0">
                Created ${new Date(o.created).toLocaleDateString()}
              </p>
            </div>`}).join("")}
        </div>`}y();const u=document.getElementById("join-modal"),g=document.getElementById("join-input"),p=document.getElementById("join-err"),s=document.getElementById("join-ok");function S(){g.value="",p.style.display="none",s.style.display="none",u.style.display="flex",setTimeout(()=>g.focus(),50)}function m(){u.style.display="none"}document.getElementById("join-comm-btn")?.addEventListener("click",S);document.getElementById("join-cancel")?.addEventListener("click",m);u.addEventListener("click",e=>{e.target===u&&m()});document.getElementById("join-confirm")?.addEventListener("click",()=>{const e=g.value.trim().toUpperCase();if(p.style.display="none",s.style.display="none",!e.match(/^COMM-[0-9A-F]{4}$/)){p.textContent="Format must be COMM-XXXX (e.g. COMM-1A2B)",p.style.display="block";return}const r=v(),t=C(),n=t.find(c=>c.id===e);if(n){n.members||(n.members=[]),n.members.includes(r)?s.textContent=`✓ You're already a member of "${n.name}".`:(n.members.push(r),localStorage.setItem(x,JSON.stringify(t)),s.textContent=`✓ Joined "${n.name}" successfully!`),s.style.display="block",setTimeout(()=>{m(),y()},1400);return}const a={id:e,name:`Community ${e}`,description:"Joined via community code",members:[r],created:new Date().toISOString(),isJoined:!0};t.push(a),localStorage.setItem(x,JSON.stringify(t)),s.textContent=`✓ Joined ${e} — community added to your list.`,s.style.display="block",setTimeout(()=>{m(),y()},1400)});g?.addEventListener("keydown",e=>{e.key==="Enter"&&document.getElementById("join-confirm")?.click(),e.key==="Escape"&&m()});
