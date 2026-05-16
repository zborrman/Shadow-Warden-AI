const x="sw_communities",C="sw_user_id",I="sw_tier",k={starter:{name:"Starter",color:"#64748b",maxComm:0,obs:!1,slack:!1},individual:{name:"Individual",color:"#06b6d4",maxComm:1,obs:!1,slack:!1},community_business:{name:"Community Business",color:"#BF5AF2",maxComm:3,obs:!0,slack:!1},pro:{name:"Pro",color:"#FF8C42",maxComm:10,obs:!0,slack:!0},enterprise:{name:"Enterprise",color:"#FFD60A",maxComm:-1,obs:!0,slack:!0}};function E(){return localStorage.getItem(I)||"pro"}function j(){return k[E()]||k.pro}function w(){let e=localStorage.getItem(C);if(!e){const i=crypto.getRandomValues(new Uint8Array(2));e=`USER-${Array.from(i).map(t=>t.toString(16).padStart(2,"0")).join("").toUpperCase()}`,localStorage.setItem(C,e)}return e}function $(){try{return JSON.parse(localStorage.getItem(x)||"[]")}catch{return[]}}function u(e){return e.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}function M(e){try{return JSON.parse(localStorage.getItem(`sw_tunnel_${e}`)||"[]").length}catch{return 0}}function y(){const e=w(),i=document.getElementById("my-user-id");i&&(i.textContent=e);const n=j(),t=$(),d=document.getElementById("communities-list");if(!d)return;const c=document.getElementById("tier-banner");if(c){const o=t.length,s=n.maxComm,p=s<=0?s===-1?0:100:Math.min(o/s*100,100);c.innerHTML=`
          <div style="display:flex;align-items:center;gap-12px;gap:12px;flex-wrap:wrap">
            <span style="padding:4px 10px;border-radius:20px;font-size:11px;font-weight:700;font-family:monospace;background:${n.color}14;border:1px solid ${n.color}35;color:${n.color}">
              ${n.name.toUpperCase()}
            </span>
            ${s===-1?`<span style="font-size:13px;color:#64748b">${o} communities (unlimited)</span>`:s===0?'<span style="font-size:13px;color:#FF2D55">0 private communities on this plan</span>':`<span style="font-size:13px;color:#64748b">${o} / ${s} communities used</span>`}
            ${s>0?`
            <div style="flex:1;min-width:80px;max-width:160px;height:4px;border-radius:2px;background:#1e293b;overflow:hidden">
              <div style="height:100%;width:${p}%;background:${p>=100?"#FF2D55":n.color};border-radius:2px;transition:width 0.5s"></div>
            </div>`:""}
            <a href="/account" style="margin-left:auto;font-size:12px;color:#475569;text-decoration:none" onmouseover="this.style.color='#06b6d4'" onmouseout="this.style.color='#475569'">
              Change plan →
            </a>
          </div>`}const h=n.maxComm!==-1&&t.length>=n.maxComm,l=document.getElementById("new-comm-btn");l&&h&&(l.setAttribute("href","/price"),l.textContent=n.maxComm===0?"Upgrade to create":"↑ Upgrade for more",l.style.background="rgba(255,255,255,0.06)",l.style.color="#94a3b8");const r=(document.getElementById("comm-search")?.value||"").toLowerCase(),v=r?t.filter(o=>o.name.toLowerCase().includes(r)||o.id.toLowerCase().includes(r)):t;if(t.length===0){d.innerHTML=`
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
          </div>`;return}if(v.length===0){d.innerHTML=`<p style="color:#475569;font-size:14px;padding:24px 0">No communities match "${u(r)}".</p>`;return}d.innerHTML=`
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px">
          ${v.map(o=>{const s=(o.members||[]).length,p=M(o.id);return`
            <div style="background:#0d1220;border:1px solid rgba(255,255,255,0.06);border-radius:16px;padding:20px;display:flex;flex-direction:column;gap:12px;transition:border-color 0.2s"
                 onmouseover="this.style.borderColor='rgba(6,182,212,0.25)'"
                 onmouseout="this.style.borderColor='rgba(255,255,255,0.06)'">
              <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">
                <div style="min-width:0">
                  <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
                    <p style="font-size:10px;font-family:monospace;color:#06b6d4;letter-spacing:0.05em;margin:0">${u(o.id)}</p>
                    ${o.isJoined?'<span style="padding:1px 6px;border-radius:4px;background:rgba(48,209,88,0.12);border:1px solid rgba(48,209,88,0.25);font-size:9px;font-weight:700;color:#30D158;font-family:monospace">JOINED</span>':""}
                  </div>
                  <h3 style="font-size:16px;font-weight:700;color:#f1f5f9;line-height:1.3;margin:0">${u(o.name)}</h3>
                </div>
                <span style="padding:3px 10px;border-radius:20px;background:rgba(6,182,212,0.08);border:1px solid rgba(6,182,212,0.18);font-size:10px;font-weight:700;color:#06b6d4;font-family:monospace;white-space:nowrap;flex-shrink:0">
                  ${s} member${s!==1?"s":""}
                </span>
              </div>
              ${o.description?`<p style="font-size:13px;color:#64748b;line-height:1.55;margin:0">${u(o.description)}</p>`:""}
              <div style="display:flex;gap:8px">
                <a href="/community/view?id=${encodeURIComponent(o.id)}"
                   style="flex:1;text-align:center;padding:9px 8px;background:rgba(6,182,212,0.1);border:1px solid rgba(6,182,212,0.2);border-radius:10px;color:#06b6d4;text-decoration:none;font-size:12px;font-weight:600;transition:background 0.15s"
                   onmouseover="this.style.background='rgba(6,182,212,0.2)'" onmouseout="this.style.background='rgba(6,182,212,0.1)'">
                  Overview
                </a>
                <a href="/community/tunnel?id=${encodeURIComponent(o.id)}"
                   style="flex:1;text-align:center;padding:9px 8px;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:10px;color:#94a3b8;text-decoration:none;font-size:12px;font-weight:600;transition:background 0.15s"
                   onmouseover="this.style.background='rgba(255,255,255,0.07)'" onmouseout="this.style.background='rgba(255,255,255,0.03)'">
                  🔒 Tunnel${p>0?` (${p})`:""}
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
        </div>`}y();document.getElementById("comm-search")?.addEventListener("input",y);const f=document.getElementById("join-modal"),b=document.getElementById("join-input"),g=document.getElementById("join-err"),a=document.getElementById("join-ok");function S(){b.value="",g.style.display="none",a.style.display="none",f.style.display="flex",setTimeout(()=>b.focus(),50)}function m(){f.style.display="none"}document.getElementById("join-comm-btn")?.addEventListener("click",S);document.getElementById("join-cancel")?.addEventListener("click",m);f.addEventListener("click",e=>{e.target===f&&m()});document.getElementById("join-confirm")?.addEventListener("click",()=>{const e=b.value.trim().toUpperCase();if(g.style.display="none",a.style.display="none",!e.match(/^COMM-[0-9A-F]{4}$/)){g.textContent="Format must be COMM-XXXX (e.g. COMM-1A2B)",g.style.display="block";return}const i=w(),n=$(),t=n.find(c=>c.id===e);if(t){if((t.members||[]).some(r=>(typeof r=="string"?r:r.id)===i)){a.textContent=`✓ You're already a member of "${t.name}".`,a.style.display="block",setTimeout(()=>{m(),y()},1400);return}if((t.join_requests||[]).some(r=>r.userId===i)){a.textContent=`📨 Join request already pending for "${t.name}". Waiting for approval.`,a.style.display="block";return}t.join_requests||(t.join_requests=[]),t.join_requests.push({userId:i,ts:Date.now()}),t.activityLog||(t.activityLog=[]),t.activityLog.unshift({ts:Date.now(),action:"join_request_sent",userId:i,detail:`${i} requested to join`}),localStorage.setItem(x,JSON.stringify(n)),a.textContent=`📨 Join request sent to "${t.name}". An admin must approve it.`,a.style.display="block",setTimeout(()=>m(),2200);return}const d={id:e,name:`Community ${e}`,description:"Joined via community code",members:[{id:i,role:"member"}],join_requests:[],activityLog:[{ts:Date.now(),action:"member_joined",userId:i,detail:`${i} joined via code`}],disappearingMessages:!1,created:new Date().toISOString(),isJoined:!0};n.push(d),localStorage.setItem(x,JSON.stringify(n)),a.textContent=`✓ Joined ${e} — community added to your list.`,a.style.display="block",setTimeout(()=>{m(),y()},1400)});b?.addEventListener("keydown",e=>{e.key==="Enter"&&document.getElementById("join-confirm")?.click(),e.key==="Escape"&&m()});
