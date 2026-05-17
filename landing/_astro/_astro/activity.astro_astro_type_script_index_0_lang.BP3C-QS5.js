const f="sw_communities";function x(e){return new URLSearchParams(window.location.search).get(e)||""}function u(){try{return JSON.parse(localStorage.getItem(f)||"[]")}catch{return[]}}function v(e){localStorage.setItem(f,JSON.stringify(e))}function m(e){return e.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")}function h(e){return(e||[]).map(n=>typeof n=="string"?{id:n,role:"member"}:n)}function w(e){return{community_created:"🏛️",member_joined:"👤",member_removed:"❌",member_left:"🚪",role_changed:"🔑",join_request_sent:"📨",join_request_approved:"✅",join_request_declined:"❌",community_merged:"🔗",messages_cleared:"🗑️"}[e]||"📋"}function $(e){const n=[{label:"📋 Overview",href:`/community/view?id=${encodeURIComponent(e)}`},{label:"👥 Members",href:`/community/members?id=${encodeURIComponent(e)}`},{label:"🔒 Tunnel",href:`/community/tunnel?id=${encodeURIComponent(e)}`},{label:"🔌 Integrations",href:`/community/integrations?id=${encodeURIComponent(e)}`},{label:"📊 Activity",href:`/community/activity?id=${encodeURIComponent(e)}`,active:!0},{label:"⚙️ Settings",href:`/community/settings?id=${encodeURIComponent(e)}`}],o=document.getElementById("tab-nav");o&&(o.innerHTML=n.map(t=>`
          <a href="${t.href}"
             style="padding:9px 16px;border-radius:10px;font-size:13px;font-weight:600;text-decoration:none;white-space:nowrap;
                    ${t.active?"background:rgba(6,182,212,0.15);border:1px solid rgba(6,182,212,0.3);color:#06b6d4":"background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);color:#64748b"};
                    transition:all 0.15s"
             ${t.active?"":`onmouseover="this.style.color='#94a3b8';this.style.background='rgba(255,255,255,0.07)'" onmouseout="this.style.color='#64748b';this.style.background='rgba(255,255,255,0.03)'"`}>
            ${t.label}
          </a>
        `).join(""))}function g(e){const n=document.getElementById("stats-bar");if(!n)return;const o=e.length,t=new Date;t.setHours(0,0,0,0);const r=e.filter(i=>i.ts>=t.getTime()).length,s=e.length>0?Math.max(...e.map(i=>i.ts)):null,l=s?new Date(s).toLocaleString():"—",c=[{label:"Total Events",value:o.toString(),color:"#06b6d4"},{label:"Today's Events",value:r.toString(),color:"#BF5AF2"},{label:"Last Activity",value:l,color:"#64748b",small:!0}];n.innerHTML=c.map(i=>`
        <div style="background:#0d1220;border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:16px">
          <p style="font-size:11px;color:#475569;text-transform:uppercase;letter-spacing:0.05em;font-weight:600;margin:0 0 8px">${i.label}</p>
          <p style="font-size:${i.small?"12px":"22px"};font-weight:700;color:${i.color};margin:0;${i.small?"font-family:monospace;word-break:break-all":""}">${m(i.value)}</p>
        </div>
      `).join("")}function b(e){const n=document.getElementById("activity-list");if(!n)return;if(!e||e.length===0){n.innerHTML=`
          <div style="text-align:center;padding:48px 24px">
            <p style="font-size:32px;margin-bottom:12px">📋</p>
            <p style="font-size:14px;color:#475569;margin:0">No activity yet. Actions in this community will appear here.</p>
          </div>`;return}const o=[...e].sort((t,r)=>r.ts-t.ts);n.innerHTML=`<div style="display:flex;flex-direction:column;gap:0">
        ${o.map((t,r)=>`
          <div style="display:flex;align-items:flex-start;gap:14px;padding:14px 0;${r<o.length-1?"border-bottom:1px solid rgba(255,255,255,0.05)":""}">
            <div style="width:36px;height:36px;border-radius:10px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.07);display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0">
              ${w(t.action||"")}
            </div>
            <div style="flex:1;min-width:0">
              <div style="display:flex;align-items:center;gap-x:10px;flex-wrap:wrap;gap:4px 10px;margin-bottom:4px">
                <span style="font-size:12px;font-family:monospace;color:#06b6d4;font-weight:600">${m(t.userId||"—")}</span>
                <span style="font-size:11px;color:#334155;font-family:monospace">${new Date(t.ts).toLocaleString()}</span>
              </div>
              <p style="font-size:13px;color:#64748b;margin:0;word-break:break-word">${m(t.detail||t.action||"")}</p>
            </div>
          </div>
        `).join("")}
      </div>`}function I(){const e=x("id");if(!e){document.body.innerHTML='<div style="padding:80px 24px;text-align:center;color:#FF2D55">No community ID. <a href="/community" style="color:#06b6d4">Back</a></div>';return}const o=u().find(a=>a.id===e);if(!o){document.body.innerHTML='<div style="padding:80px 24px;text-align:center;color:#FF2D55">Community not found. <a href="/community" style="color:#06b6d4">Back</a></div>';return}const t=document.getElementById("bc-comm");t&&(t.textContent=o.name,t.href=`/community/view?id=${encodeURIComponent(e)}`),document.title=`${o.name} — Activity — Shadow Warden AI`,$(e);const r=o.activityLog||[];g(r),b(r);const s=h(o.members||[]),l=localStorage.getItem("sw_user_id")||"",c=s.find(a=>a.role==="owner"),i=c&&l&&c.id===l,d=document.getElementById("clear-log-btn");d&&i&&(d.style.display="block",d.addEventListener("click",()=>{if(!confirm("Clear the entire activity log? This cannot be undone."))return;const a=u(),p=a.find(y=>y.id===e);p&&(p.activityLog=[],v(a),g([]),b([]))}))}I();
