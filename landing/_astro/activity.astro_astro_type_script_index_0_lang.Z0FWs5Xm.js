var e=`sw_communities`;function t(e){return new URLSearchParams(window.location.search).get(e)||``}function n(){try{return JSON.parse(localStorage.getItem(e)||`[]`)}catch{return[]}}function r(t){localStorage.setItem(e,JSON.stringify(t))}function i(e){return e.replace(/&/g,`&amp;`).replace(/</g,`&lt;`).replace(/>/g,`&gt;`)}function a(e){return(e||[]).map(e=>typeof e==`string`?{id:e,role:`member`}:e)}function o(e){return{community_created:`🏛️`,member_joined:`👤`,member_removed:`❌`,member_left:`🚪`,role_changed:`🔑`,join_request_sent:`📨`,join_request_approved:`✅`,join_request_declined:`❌`,community_merged:`🔗`,messages_cleared:`🗑️`}[e]||`📋`}function s(e){let t=[{label:`📋 Overview`,href:`/community/view?id=${encodeURIComponent(e)}`},{label:`👥 Members`,href:`/community/members?id=${encodeURIComponent(e)}`},{label:`🔒 Tunnel`,href:`/community/tunnel?id=${encodeURIComponent(e)}`},{label:`🔌 Integrations`,href:`/community/integrations?id=${encodeURIComponent(e)}`},{label:`📊 Activity`,href:`/community/activity?id=${encodeURIComponent(e)}`,active:!0},{label:`⚙️ Settings`,href:`/community/settings?id=${encodeURIComponent(e)}`}],n=document.getElementById(`tab-nav`);n&&(n.innerHTML=t.map(e=>`
          <a href="${e.href}"
             style="padding:9px 16px;border-radius:10px;font-size:13px;font-weight:600;text-decoration:none;white-space:nowrap;
                    ${e.active?`background:rgba(6,182,212,0.15);border:1px solid rgba(6,182,212,0.3);color:#06b6d4`:`background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);color:#64748b`};
                    transition:all 0.15s"
             ${e.active?``:`onmouseover="this.style.color='#94a3b8';this.style.background='rgba(255,255,255,0.07)'" onmouseout="this.style.color='#64748b';this.style.background='rgba(255,255,255,0.03)'"`}>
            ${e.label}
          </a>
        `).join(``))}function c(e){let t=document.getElementById(`stats-bar`);if(!t)return;let n=e.length,r=new Date;r.setHours(0,0,0,0);let a=e.filter(e=>e.ts>=r.getTime()).length,o=e.length>0?Math.max(...e.map(e=>e.ts)):null,s=o?new Date(o).toLocaleString():`—`;t.innerHTML=[{label:`Total Events`,value:n.toString(),color:`#06b6d4`},{label:`Today's Events`,value:a.toString(),color:`#BF5AF2`},{label:`Last Activity`,value:s,color:`#64748b`,small:!0}].map(e=>`
        <div style="background:#0d1220;border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:16px">
          <p style="font-size:11px;color:#475569;text-transform:uppercase;letter-spacing:0.05em;font-weight:600;margin:0 0 8px">${e.label}</p>
          <p style="font-size:${e.small?`12px`:`22px`};font-weight:700;color:${e.color};margin:0;${e.small?`font-family:monospace;word-break:break-all`:``}">${i(e.value)}</p>
        </div>
      `).join(``)}function l(e){let t=document.getElementById(`activity-list`);if(!t)return;if(!e||e.length===0){t.innerHTML=`
          <div style="text-align:center;padding:48px 24px">
            <p style="font-size:32px;margin-bottom:12px">📋</p>
            <p style="font-size:14px;color:#475569;margin:0">No activity yet. Actions in this community will appear here.</p>
          </div>`;return}let n=[...e].sort((e,t)=>t.ts-e.ts);t.innerHTML=`<div style="display:flex;flex-direction:column;gap:0">
        ${n.map((e,t)=>`
          <div style="display:flex;align-items:flex-start;gap:14px;padding:14px 0;${t<n.length-1?`border-bottom:1px solid rgba(255,255,255,0.05)`:``}">
            <div style="width:36px;height:36px;border-radius:10px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.07);display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0">
              ${o(e.action||``)}
            </div>
            <div style="flex:1;min-width:0">
              <div style="display:flex;align-items:center;gap-x:10px;flex-wrap:wrap;gap:4px 10px;margin-bottom:4px">
                <span style="font-size:12px;font-family:monospace;color:#06b6d4;font-weight:600">${i(e.userId||`—`)}</span>
                <span style="font-size:11px;color:#334155;font-family:monospace">${new Date(e.ts).toLocaleString()}</span>
              </div>
              <p style="font-size:13px;color:#64748b;margin:0;word-break:break-word">${i(e.detail||e.action||``)}</p>
            </div>
          </div>
        `).join(``)}
      </div>`}function u(){let e=t(`id`);if(!e){document.body.innerHTML=`<div style="padding:80px 24px;text-align:center;color:#FF2D55">No community ID. <a href="/community" style="color:#06b6d4">Back</a></div>`;return}let i=n().find(t=>t.id===e);if(!i){document.body.innerHTML=`<div style="padding:80px 24px;text-align:center;color:#FF2D55">Community not found. <a href="/community" style="color:#06b6d4">Back</a></div>`;return}let o=document.getElementById(`bc-comm`);o&&(o.textContent=i.name,o.href=`/community/view?id=${encodeURIComponent(e)}`),document.title=`${i.name} — Activity — Shadow Warden AI`,s(e);let u=i.activityLog||[];c(u),l(u);let d=a(i.members||[]),f=localStorage.getItem(`sw_user_id`)||``,p=d.find(e=>e.role===`owner`),m=p&&f&&p.id===f,h=document.getElementById(`clear-log-btn`);h&&m&&(h.style.display=`block`,h.addEventListener(`click`,()=>{if(!confirm(`Clear the entire activity log? This cannot be undone.`))return;let t=n(),i=t.find(t=>t.id===e);i&&(i.activityLog=[],r(t),c([]),l([]))}))}u();