const l="sw_communities",d="sw_user_id";function p(){let e=localStorage.getItem(d);if(!e){const n=crypto.getRandomValues(new Uint8Array(2));e=`USER-${Array.from(n).map(o=>o.toString(16).padStart(2,"0")).join("").toUpperCase()}`,localStorage.setItem(d,e)}return e}function g(){try{return JSON.parse(localStorage.getItem(l)||"[]")}catch{return[]}}function i(e){return e.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}function c(e){try{return JSON.parse(localStorage.getItem(`sw_tunnel_${e}`)||"[]").length}catch{return 0}}function m(){const e=p(),n=document.getElementById("my-user-id");n&&(n.textContent=e);const r=g(),o=document.getElementById("communities-list");if(o){if(r.length===0){o.innerHTML=`
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
          </div>`;return}o.innerHTML=`
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px">
          ${r.map(t=>{const a=(t.members||[]).length,s=c(t.id);return`
            <div style="background:#0d1220;border:1px solid rgba(255,255,255,0.06);border-radius:16px;padding:20px;display:flex;flex-direction:column;gap:12px;transition:border-color 0.2s"
                 onmouseover="this.style.borderColor='rgba(6,182,212,0.25)'"
                 onmouseout="this.style.borderColor='rgba(255,255,255,0.06)'">
              <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">
                <div>
                  <p style="font-size:10px;font-family:monospace;color:#06b6d4;margin-bottom:4px;letter-spacing:0.05em">${i(t.id)}</p>
                  <h3 style="font-size:16px;font-weight:700;color:#f1f5f9;line-height:1.3;margin:0">${i(t.name)}</h3>
                </div>
                <span style="padding:3px 10px;border-radius:20px;background:rgba(6,182,212,0.08);border:1px solid rgba(6,182,212,0.18);font-size:10px;font-weight:700;color:#06b6d4;font-family:monospace;white-space:nowrap;flex-shrink:0">
                  ${a} member${a!==1?"s":""}
                </span>
              </div>
              ${t.description?`<p style="font-size:13px;color:#64748b;line-height:1.55;margin:0">${i(t.description)}</p>`:""}
              <div style="display:flex;gap:8px">
                <a href="/community/view?id=${encodeURIComponent(t.id)}"
                   style="flex:1;text-align:center;padding:9px 8px;background:rgba(6,182,212,0.1);border:1px solid rgba(6,182,212,0.2);border-radius:10px;color:#06b6d4;text-decoration:none;font-size:12px;font-weight:600;transition:background 0.15s"
                   onmouseover="this.style.background='rgba(6,182,212,0.2)'" onmouseout="this.style.background='rgba(6,182,212,0.1)'">
                  Overview
                </a>
                <a href="/community/tunnel?id=${encodeURIComponent(t.id)}"
                   style="flex:1;text-align:center;padding:9px 8px;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:10px;color:#94a3b8;text-decoration:none;font-size:12px;font-weight:600;transition:background 0.15s"
                   onmouseover="this.style.background='rgba(255,255,255,0.07)'" onmouseout="this.style.background='rgba(255,255,255,0.03)'">
                  🔒 Tunnel${s>0?` (${s})`:""}
                </a>
                <a href="/community/members?id=${encodeURIComponent(t.id)}"
                   style="flex:1;text-align:center;padding:9px 8px;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:10px;color:#94a3b8;text-decoration:none;font-size:12px;font-weight:600;transition:background 0.15s"
                   onmouseover="this.style.background='rgba(255,255,255,0.07)'" onmouseout="this.style.background='rgba(255,255,255,0.03)'">
                  Members
                </a>
              </div>
              <p style="font-size:11px;color:#334155;font-family:monospace;margin:0">
                Created ${new Date(t.created).toLocaleDateString()}
              </p>
            </div>`}).join("")}
        </div>`}}m();
