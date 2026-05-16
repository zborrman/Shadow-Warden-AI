const u="sw_communities",m="sw_user_id",x="sw_tier",c={starter:{name:"Starter",color:"#64748b",maxComm:0,obs:!1,slack:!1},individual:{name:"Individual",color:"#06b6d4",maxComm:1,obs:!1,slack:!1},community_business:{name:"Community Business",color:"#BF5AF2",maxComm:3,obs:!0,slack:!1},pro:{name:"Pro",color:"#FF8C42",maxComm:10,obs:!0,slack:!0},enterprise:{name:"Enterprise",color:"#FFD60A",maxComm:-1,obs:!0,slack:!0}};function b(){return localStorage.getItem(x)||"pro"}function f(){return c[b()]||c.pro}function y(){let t=localStorage.getItem(m);if(!t){const s=crypto.getRandomValues(new Uint8Array(2));t=`USER-${Array.from(s).map(r=>r.toString(16).padStart(2,"0")).join("").toUpperCase()}`,localStorage.setItem(m,t)}return t}function h(){try{return JSON.parse(localStorage.getItem(u)||"[]")}catch{return[]}}function d(t){return t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}function C(t){try{return JSON.parse(localStorage.getItem(`sw_tunnel_${t}`)||"[]").length}catch{return 0}}function v(){const t=y(),s=document.getElementById("my-user-id");s&&(s.textContent=t);const o=f(),r=h(),l=document.getElementById("communities-list");if(!l)return;const p=document.getElementById("tier-banner");if(p){const e=r.length,n=o.maxComm,a=n<=0?n===-1?0:100:Math.min(e/n*100,100);p.innerHTML=`
          <div style="display:flex;align-items:center;gap-12px;gap:12px;flex-wrap:wrap">
            <span style="padding:4px 10px;border-radius:20px;font-size:11px;font-weight:700;font-family:monospace;background:${o.color}14;border:1px solid ${o.color}35;color:${o.color}">
              ${o.name.toUpperCase()}
            </span>
            ${n===-1?`<span style="font-size:13px;color:#64748b">${e} communities (unlimited)</span>`:n===0?'<span style="font-size:13px;color:#FF2D55">0 private communities on this plan</span>':`<span style="font-size:13px;color:#64748b">${e} / ${n} communities used</span>`}
            ${n>0?`
            <div style="flex:1;min-width:80px;max-width:160px;height:4px;border-radius:2px;background:#1e293b;overflow:hidden">
              <div style="height:100%;width:${a}%;background:${a>=100?"#FF2D55":o.color};border-radius:2px;transition:width 0.5s"></div>
            </div>`:""}
            <a href="/account" style="margin-left:auto;font-size:12px;color:#475569;text-decoration:none" onmouseover="this.style.color='#06b6d4'" onmouseout="this.style.color='#475569'">
              Change plan →
            </a>
          </div>`}const g=o.maxComm!==-1&&r.length>=o.maxComm,i=document.getElementById("new-comm-btn");if(i&&g&&(i.setAttribute("href","/price"),i.textContent=o.maxComm===0?"Upgrade to create":"↑ Upgrade for more",i.style.background="rgba(255,255,255,0.06)",i.style.color="#94a3b8"),r.length===0){l.innerHTML=`
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
          </div>`;return}l.innerHTML=`
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px">
          ${r.map(e=>{const n=(e.members||[]).length,a=C(e.id);return`
            <div style="background:#0d1220;border:1px solid rgba(255,255,255,0.06);border-radius:16px;padding:20px;display:flex;flex-direction:column;gap:12px;transition:border-color 0.2s"
                 onmouseover="this.style.borderColor='rgba(6,182,212,0.25)'"
                 onmouseout="this.style.borderColor='rgba(255,255,255,0.06)'">
              <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">
                <div>
                  <p style="font-size:10px;font-family:monospace;color:#06b6d4;margin-bottom:4px;letter-spacing:0.05em">${d(e.id)}</p>
                  <h3 style="font-size:16px;font-weight:700;color:#f1f5f9;line-height:1.3;margin:0">${d(e.name)}</h3>
                </div>
                <span style="padding:3px 10px;border-radius:20px;background:rgba(6,182,212,0.08);border:1px solid rgba(6,182,212,0.18);font-size:10px;font-weight:700;color:#06b6d4;font-family:monospace;white-space:nowrap;flex-shrink:0">
                  ${n} member${n!==1?"s":""}
                </span>
              </div>
              ${e.description?`<p style="font-size:13px;color:#64748b;line-height:1.55;margin:0">${d(e.description)}</p>`:""}
              <div style="display:flex;gap:8px">
                <a href="/community/view?id=${encodeURIComponent(e.id)}"
                   style="flex:1;text-align:center;padding:9px 8px;background:rgba(6,182,212,0.1);border:1px solid rgba(6,182,212,0.2);border-radius:10px;color:#06b6d4;text-decoration:none;font-size:12px;font-weight:600;transition:background 0.15s"
                   onmouseover="this.style.background='rgba(6,182,212,0.2)'" onmouseout="this.style.background='rgba(6,182,212,0.1)'">
                  Overview
                </a>
                <a href="/community/tunnel?id=${encodeURIComponent(e.id)}"
                   style="flex:1;text-align:center;padding:9px 8px;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:10px;color:#94a3b8;text-decoration:none;font-size:12px;font-weight:600;transition:background 0.15s"
                   onmouseover="this.style.background='rgba(255,255,255,0.07)'" onmouseout="this.style.background='rgba(255,255,255,0.03)'">
                  🔒 Tunnel${a>0?` (${a})`:""}
                </a>
                <a href="/community/members?id=${encodeURIComponent(e.id)}"
                   style="flex:1;text-align:center;padding:9px 8px;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:10px;color:#94a3b8;text-decoration:none;font-size:12px;font-weight:600;transition:background 0.15s"
                   onmouseover="this.style.background='rgba(255,255,255,0.07)'" onmouseout="this.style.background='rgba(255,255,255,0.03)'">
                  Members
                </a>
              </div>
              <p style="font-size:11px;color:#334155;font-family:monospace;margin:0">
                Created ${new Date(e.created).toLocaleDateString()}
              </p>
            </div>`}).join("")}
        </div>`}v();
