const q="sw_communities",_="sw_tier";let u="",f="";const B={starter:{name:"Starter",color:"#64748b",maxMem:0},individual:{name:"Individual",color:"#06b6d4",maxMem:5},community_business:{name:"Community Business",color:"#BF5AF2",maxMem:10},pro:{name:"Pro",color:"#FF8C42",maxMem:50},enterprise:{name:"Enterprise",color:"#FFD60A",maxMem:-1}};function D(){return localStorage.getItem(_)||"pro"}function U(){return B[D()]||B.pro}function z(e){return new URLSearchParams(window.location.search).get(e)||""}function $(){try{return JSON.parse(localStorage.getItem(q)||"[]")}catch{return[]}}function C(e){localStorage.setItem(q,JSON.stringify(e))}function M(e){return String(e).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")}function T(e){return typeof e=="string"?{id:e,role:"member"}:{id:e.id||e,role:e.role||"member"}}function I(e){return(e||[]).map(T)}function F(e,d,r,o){e.activityLog||(e.activityLog=[]),e.activityLog.unshift({ts:Date.now(),action:d,userId:r,detail:o}),e.activityLog.length>200&&(e.activityLog.length=200)}function R(e){const d=e.find(r=>r.id===f);return d?d.role:"none"}const S={owner:"background:rgba(255,214,10,0.12);border:1px solid rgba(255,214,10,0.3);color:#FFD60A",admin:"background:rgba(6,182,212,0.1);border:1px solid rgba(6,182,212,0.25);color:#06b6d4",member:"background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);color:#64748b"};function j(e){const d=[{label:"📋 Overview",href:`/community/view?id=${encodeURIComponent(e)}`},{label:"👥 Members",href:`/community/members?id=${encodeURIComponent(e)}`,active:!0},{label:"🔒 Tunnel",href:`/community/tunnel?id=${encodeURIComponent(e)}`},{label:"🔌 Integrations",href:`/community/integrations?id=${encodeURIComponent(e)}`},{label:"📊 Activity",href:`/community/activity?id=${encodeURIComponent(e)}`},{label:"⚙️ Settings",href:`/community/settings?id=${encodeURIComponent(e)}`}],r=document.getElementById("tab-nav");r&&(r.innerHTML=d.map(o=>`
        <a href="${o.href}"
           style="padding:9px 16px;border-radius:10px;font-size:13px;font-weight:600;text-decoration:none;white-space:nowrap;
                  ${o.active?"background:rgba(6,182,212,0.15);border:1px solid rgba(6,182,212,0.3);color:#06b6d4":"background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);color:#64748b"};
                  transition:all 0.15s"
           ${o.active?"":`onmouseover="this.style.color='#94a3b8';this.style.background='rgba(255,255,255,0.07)'" onmouseout="this.style.color='#64748b';this.style.background='rgba(255,255,255,0.03)'"`}>
          ${o.label}
        </a>
      `).join(""))}function O(e,d){const r=document.getElementById("join-requests-section"),o=document.getElementById("requests-list"),t=document.getElementById("req-count");if(!r||!o)return;const s=e.join_requests||[];if(d!=="owner"&&d!=="admin"){r.style.display="none";return}if(s.length===0){r.style.display="none";return}r.style.display="block",t&&(t.textContent=`(${s.length})`),o.innerHTML=`<div style="display:flex;flex-direction:column;gap:8px">
        ${s.map((c,i)=>`
          <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:rgba(191,90,242,0.06);border:1px solid rgba(191,90,242,0.15);border-radius:10px;gap:12px">
            <div>
              <span style="font-size:13px;font-family:monospace;font-weight:700;color:#e2e8f0">${M(c.userId)}</span>
              <span style="font-size:11px;color:#475569;margin-left:10px">${new Date(c.ts).toLocaleString()}</span>
            </div>
            <div style="display:flex;gap:8px">
              <button data-req-i="${i}" data-req-action="approve"
                      style="padding:5px 12px;background:rgba(48,209,88,0.1);border:1px solid rgba(48,209,88,0.25);border-radius:6px;color:#30D158;font-size:11px;font-weight:700;cursor:pointer">
                Approve
              </button>
              <button data-req-i="${i}" data-req-action="decline"
                      style="padding:5px 12px;background:rgba(255,45,85,0.08);border:1px solid rgba(255,45,85,0.2);border-radius:6px;color:#FF2D55;font-size:11px;font-weight:700;cursor:pointer">
                Decline
              </button>
            </div>
          </div>
        `).join("")}
      </div>`,o.querySelectorAll("button[data-req-action]").forEach(c=>{c.addEventListener("click",()=>{const i=parseInt(c.dataset.reqI||"0"),l=c.dataset.reqAction,m=$(),p=m.find(a=>a.id===u);if(!p)return;const y=p.join_requests||[],b=y[i];if(b){if(l==="approve"){const a=I(p.members);a.find(n=>n.id===b.userId)||(a.push({id:b.userId,role:"member"}),p.members=a,F(p,"join_request_approved",f,`Approved ${b.userId}`))}else F(p,"join_request_declined",f,`Declined ${b.userId}`);p.join_requests=y.filter((a,n)=>n!==i),C(m),E()}})})}function A(){const d=$().find(n=>n.id===u);if(!d)return;const r=U(),o=I(d.members),t=R(o),s=document.getElementById("members-list"),c=document.getElementById("member-count"),i=r.maxMem,l=i!==-1&&o.length>=i,m=(document.getElementById("member-search")?.value||"").toLowerCase();if(c){const n=i===-1?`(${o.length})`:`(${o.length}/${i})`;c.textContent=n,c.style.color=l?"#FF2D55":"#475569"}const p=document.getElementById("member-limit-bar");if(p&&i>0){const n=Math.min(o.length/i*100,100);p.innerHTML=`
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
            <div style="flex:1;height:4px;border-radius:2px;background:#1e293b;overflow:hidden">
              <div style="height:100%;width:${n}%;background:${n>=100?"#FF2D55":r.color};border-radius:2px;transition:width 0.5s"></div>
            </div>
            <span style="font-size:11px;font-family:monospace;color:${l?"#FF2D55":"#475569"};white-space:nowrap">
              ${o.length}/${i} · <span style="color:${r.color}">${r.name}</span>
            </span>
          </div>
          ${l?`<div style="padding:10px 14px;background:rgba(255,140,66,0.08);border:1px solid rgba(255,140,66,0.2);border-radius:10px;margin-bottom:14px">
            <p style="font-size:12px;color:#FF8C42;margin:0">Limit reached. <a href="/price" style="color:#FF8C42;font-weight:700">Upgrade →</a></p>
          </div>`:""}`,p.style.display="block"}const y=document.getElementById("add-member-btn");if(y&&(y.disabled=l,y.style.cursor=l?"not-allowed":"pointer",y.style.opacity=l?"0.4":"1"),!s)return;const b=m?o.filter(n=>n.id.toLowerCase().includes(m)||n.role.includes(m)):o;if(b.length===0){s.innerHTML=`<p style="color:#475569;font-size:13px">${m?"No members match your search.":"No members yet. Add someone above."}</p>`;return}const a=t==="owner"||t==="admin";s.innerHTML=`<div style="display:flex;flex-direction:column;gap:8px">
        ${b.map(n=>{const g=n.id===f,h=n.role==="owner",x=S[n.role]||S.member;return`
            <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-radius:10px;gap:10px">
              <div style="display:flex;align-items:center;gap:10px;min-width:0">
                <span style="font-size:13px;font-family:monospace;font-weight:600;color:#e2e8f0">${M(n.id)}${g?' <span style="font-size:10px;color:#475569">(you)</span>':""}</span>
              </div>
              <div style="display:flex;align-items:center;gap:8px;flex-shrink:0">
                ${a&&!h&&n.id!==f?`
                  <select data-member="${M(n.id)}" class="role-select"
                          style="background:#0a0a12;border:1px solid rgba(255,255,255,0.1);border-radius:6px;padding:4px 8px;color:#94a3b8;font-size:11px;font-weight:600;cursor:pointer;outline:none">
                    <option value="member" ${n.role==="member"?"selected":""}>Member</option>
                    <option value="admin" ${n.role==="admin"?"selected":""}>Admin</option>
                  </select>
                `:`<span style="padding:3px 9px;border-radius:6px;font-size:11px;font-weight:700;${x}">${n.role.toUpperCase()}</span>`}
                ${a&&!h?`
                  <button data-member="${M(n.id)}" class="remove-btn"
                          style="padding:4px 10px;background:rgba(255,45,85,0.08);border:1px solid rgba(255,45,85,0.2);border-radius:6px;color:#FF2D55;font-size:11px;font-weight:700;cursor:pointer;transition:all 0.15s"
                          onmouseover="this.style.background='rgba(255,45,85,0.18)'" onmouseout="this.style.background='rgba(255,45,85,0.08)'">
                    Remove
                  </button>
                `:""}
              </div>
            </div>`}).join("")}
      </div>`,s.querySelectorAll(".role-select").forEach(n=>{n.addEventListener("change",()=>{const g=n.dataset.member,h=n.value;if(!g)return;const x=$(),w=x.find(k=>k.id===u);if(!w)return;const L=I(w.members),v=L.find(k=>k.id===g);if(v){const k=v.role;v.role=h,w.members=L,F(w,"role_changed",f,`${g} role: ${k} → ${h}`),C(x),E()}})}),s.querySelectorAll(".remove-btn").forEach(n=>{n.addEventListener("click",()=>{const g=n.dataset.member;if(!g)return;const h=$(),x=h.find(v=>v.id===u);if(!x)return;const w=I(x.members);w.find(v=>v.id===g)?.role!=="owner"&&(x.members=w.filter(v=>v.id!==g),F(x,"member_removed",f,`Removed ${g}`),C(h),E())})})}function E(){const d=$().find(t=>t.id===u);if(!d)return;const r=I(d.members),o=R(r);O(d,o),A()}function X(){if(u=z("id"),f=localStorage.getItem("sw_user_id")||"USER-ANON",!u){document.body.innerHTML='<div style="padding:80px 24px;text-align:center;color:#FF2D55">No community ID. <a href="/community" style="color:#06b6d4">Back</a></div>';return}const d=$().find(o=>o.id===u);if(!d){document.body.innerHTML='<div style="padding:80px 24px;text-align:center;color:#FF2D55">Community not found. <a href="/community" style="color:#06b6d4">Back</a></div>';return}const r=document.getElementById("bc-comm");r&&(r.textContent=d.name,r.href=`/community/view?id=${encodeURIComponent(u)}`),document.title=`Members · ${d.name} — Shadow Warden AI`,j(u),E(),document.getElementById("member-search")?.addEventListener("input",A),document.getElementById("add-member-btn")?.addEventListener("click",()=>{const o=document.getElementById("member-id-input"),t=document.getElementById("add-err"),s=o.value.trim().toUpperCase();if(!s.match(/^USER-[0-9A-F]{4}$/)){t&&(t.textContent="Format: USER-XXXX (e.g. USER-1A2B)",t.style.display="block");return}t&&(t.style.display="none");const c=$(),i=c.find(m=>m.id===u);if(!i)return;const l=I(i.members);if(l.find(m=>m.id===s)){t&&(t.textContent="Already a member.",t.style.display="block");return}l.push({id:s,role:"member"}),i.members=l,F(i,"member_joined",f,`Added ${s}`),C(c),o.value="",E()}),document.getElementById("merge-btn")?.addEventListener("click",()=>{const o=document.getElementById("merge-id-input"),t=document.getElementById("merge-err"),s=o.value.trim().toUpperCase();if(!s.match(/^COMM-[0-9A-F]{4}$/)){t&&(t.textContent="Format: COMM-XXXX",t.style.color="#FF2D55",t.style.display="block");return}if(s===u){t&&(t.textContent="Cannot merge with itself.",t.style.color="#FF2D55",t.style.display="block");return}const c=$(),i=c.find(a=>a.id===u),l=c.find(a=>a.id===s);if(!l){t&&(t.textContent=`${s} not found in your communities.`,t.style.color="#FF2D55",t.style.display="block");return}const m=I(i.members),p=I(l.members),y=new Set(m.map(a=>a.id));let b=0;for(const a of p)!y.has(a.id)&&a.role!=="owner"&&(m.push({id:a.id,role:"member"}),b++);i.members=m,F(i,"community_merged",f,`Merged ${b} members from ${s}`),C(c),o.value="",t&&(t.textContent=`✓ Merged ${b} new members from ${s}.`,t.style.color="#30D158",t.style.display="block"),E()})}X();
