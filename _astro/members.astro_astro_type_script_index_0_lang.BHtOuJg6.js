var e=`sw_communities`,t=``,n=``,r={starter:{name:`Starter`,color:`#556072`,maxMem:0},individual:{name:`Individual`,color:`#0e7490`,maxMem:5},community_business:{name:`Community Business`,color:`#9333ea`,maxMem:10}};function i(){return localStorage.getItem(`sw_tier`)||`starter`}function a(){return r[i()]||r.community_business}function o(e){return new URLSearchParams(window.location.search).get(e)||``}function s(){try{return JSON.parse(localStorage.getItem(e)||`[]`)}catch{return[]}}function c(t){localStorage.setItem(e,JSON.stringify(t))}function l(e){return String(e).replace(/&/g,`&amp;`).replace(/</g,`&lt;`).replace(/>/g,`&gt;`)}function u(e){return typeof e==`string`?{id:e,role:`member`}:{id:e.id||e,role:e.role||`member`}}function d(e){return(e||[]).map(u)}function f(e,t,n,r){e.activityLog||=[],e.activityLog.unshift({ts:Date.now(),action:t,userId:n,detail:r}),e.activityLog.length>200&&(e.activityLog.length=200)}function p(e){let t=e.find(e=>e.id===n);return t?t.role:`none`}var m={owner:`background:rgba(255,214,10,0.12);border:1px solid rgba(255,214,10,0.3);color:var(--acc-amber)`,admin:`background:rgba(6,182,212,0.1);border:1px solid rgba(6,182,212,0.25);color:#0e7490`,member:`background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);color:#556072`};function h(e){let t=[{label:`📋 Overview`,href:`/community/view?id=${encodeURIComponent(e)}`},{label:`👥 Members`,href:`/community/members?id=${encodeURIComponent(e)}`,active:!0},{label:`🔒 Tunnel`,href:`/community/tunnel?id=${encodeURIComponent(e)}`},{label:`🔌 Integrations`,href:`/community/integrations?id=${encodeURIComponent(e)}`},{label:`📊 Activity`,href:`/community/activity?id=${encodeURIComponent(e)}`},{label:`⚙️ Settings`,href:`/community/settings?id=${encodeURIComponent(e)}`}],n=document.getElementById(`tab-nav`);n&&(n.innerHTML=t.map(e=>`
        <a href="${e.href}"
           style="padding:9px 16px;border-radius:10px;font-size:13px;font-weight:600;text-decoration:none;white-space:nowrap;
                  ${e.active?`background:rgba(6,182,212,0.15);border:1px solid rgba(6,182,212,0.3);color:#0e7490`:`background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);color:#556072`};
                  transition:all 0.15s"
           ${e.active?``:`onmouseover="this.style.color='#556072';this.style.background='rgba(255,255,255,0.07)'" onmouseout="this.style.color='#556072';this.style.background='rgba(255,255,255,0.03)'"`}>
          ${e.label}
        </a>
      `).join(``))}function g(e,r){let i=document.getElementById(`join-requests-section`),a=document.getElementById(`requests-list`),o=document.getElementById(`req-count`);if(!i||!a)return;let u=e.join_requests||[];r!==`owner`&&r!==`admin`||u.length===0?i.style.display=`none`:(i.style.display=`block`,o&&(o.textContent=`(${u.length})`),a.innerHTML=`<div style="display:flex;flex-direction:column;gap:8px">
        ${u.map((e,t)=>`
          <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:rgba(191,90,242,0.06);border:1px solid rgba(191,90,242,0.15);border-radius:10px;gap:12px">
            <div>
              <span style="font-size:13px;font-family:monospace;font-weight:700;color:var(--ink-1)">${l(e.userId)}</span>
              <span style="font-size:11px;color:#475569;margin-left:10px">${new Date(e.ts).toLocaleString()}</span>
            </div>
            <div style="display:flex;gap:8px">
              <button data-req-i="${t}" data-req-action="approve"
                      style="padding:5px 12px;background:rgba(48,209,88,0.1);border:1px solid rgba(48,209,88,0.25);border-radius:6px;color:#15803d;font-size:11px;font-weight:700;cursor:pointer">
                Approve
              </button>
              <button data-req-i="${t}" data-req-action="decline"
                      style="padding:5px 12px;background:rgba(255,45,85,0.08);border:1px solid rgba(255,45,85,0.2);border-radius:6px;color:#be123c;font-size:11px;font-weight:700;cursor:pointer">
                Decline
              </button>
            </div>
          </div>
        `).join(``)}
      </div>`,a.querySelectorAll(`button[data-req-action]`).forEach(e=>{e.addEventListener(`click`,()=>{let r=parseInt(e.dataset.reqI||`0`),i=e.dataset.reqAction,a=s(),o=a.find(e=>e.id===t);if(!o)return;let l=o.join_requests||[],u=l[r];if(u){if(i===`approve`){let e=d(o.members);e.find(e=>e.id===u.userId)||(e.push({id:u.userId,role:`member`}),o.members=e,f(o,`join_request_approved`,n,`Approved ${u.userId}`))}else f(o,`join_request_declined`,n,`Declined ${u.userId}`);o.join_requests=l.filter((e,t)=>t!==r),c(a),v()}})}))}function _(){let e=s().find(e=>e.id===t);if(!e)return;let r=a(),i=d(e.members),o=p(i),u=document.getElementById(`members-list`),h=document.getElementById(`member-count`),g=r.maxMem,_=g!==-1&&i.length>=g,y=(document.getElementById(`member-search`)?.value||``).toLowerCase();h&&(h.textContent=g===-1?`(${i.length})`:`(${i.length}/${g})`,h.style.color=_?`#be123c`:`#475569`);let b=document.getElementById(`member-limit-bar`);if(b&&g>0){let e=Math.min(i.length/g*100,100);b.innerHTML=`
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
            <div style="flex:1;height:4px;border-radius:2px;background:var(--sw-surf-3);overflow:hidden">
              <div style="height:100%;width:${e}%;background:${e>=100?`#be123c`:r.color};border-radius:2px;transition:width 0.5s"></div>
            </div>
            <span style="font-size:11px;font-family:monospace;color:${_?`#be123c`:`#475569`};white-space:nowrap">
              ${i.length}/${g} · <span style="color:${r.color}">${r.name}</span>
            </span>
          </div>
          ${_?`<div style="padding:10px 14px;background:rgba(255,140,66,0.08);border:1px solid rgba(255,140,66,0.2);border-radius:10px;margin-bottom:14px">
            <p style="font-size:12px;color:#FF8C42;margin:0">Limit reached. <a href="/price" style="color:#FF8C42;font-weight:700">Upgrade →</a></p>
          </div>`:``}`,b.style.display=`block`}let x=document.getElementById(`add-member-btn`);if(x&&(x.disabled=_,x.style.cursor=_?`not-allowed`:`pointer`,x.style.opacity=_?`0.4`:`1`),!u)return;let S=y?i.filter(e=>e.id.toLowerCase().includes(y)||e.role.includes(y)):i;if(S.length===0){u.innerHTML=`<p style="color:#475569;font-size:13px">${y?`No members match your search.`:`No members yet. Add someone above.`}</p>`;return}let C=o===`owner`||o===`admin`;u.innerHTML=`<div style="display:flex;flex-direction:column;gap:8px">
        ${S.map(e=>{let t=e.id===n,r=e.role===`owner`,i=m[e.role]||m.member;return`
            <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-radius:10px;gap:10px">
              <div style="display:flex;align-items:center;gap:10px;min-width:0">
                <span style="font-size:13px;font-family:monospace;font-weight:600;color:var(--ink-1)">${l(e.id)}${t?` <span style="font-size:10px;color:#475569">(you)</span>`:``}</span>
              </div>
              <div style="display:flex;align-items:center;gap:8px;flex-shrink:0">
                ${C&&!r&&e.id!==n?`
                  <select data-member="${l(e.id)}" class="role-select"
                          style="background:var(--sw-bg);border:1px solid rgba(255,255,255,0.1);border-radius:6px;padding:4px 8px;color:var(--ink-3);font-size:11px;font-weight:600;cursor:pointer;outline:none">
                    <option value="member" ${e.role===`member`?`selected`:``}>Member</option>
                    <option value="admin" ${e.role===`admin`?`selected`:``}>Admin</option>
                  </select>
                `:`<span style="padding:3px 9px;border-radius:6px;font-size:11px;font-weight:700;${i}">${e.role.toUpperCase()}</span>`}
                ${C&&!r?`
                  <button data-member="${l(e.id)}" class="remove-btn"
                          style="padding:4px 10px;background:rgba(255,45,85,0.08);border:1px solid rgba(255,45,85,0.2);border-radius:6px;color:#be123c;font-size:11px;font-weight:700;cursor:pointer;transition:all 0.15s"
                          onmouseover="this.style.background='rgba(255,45,85,0.18)'" onmouseout="this.style.background='rgba(255,45,85,0.08)'">
                    Remove
                  </button>
                `:``}
              </div>
            </div>`}).join(``)}
      </div>`,u.querySelectorAll(`.role-select`).forEach(e=>{e.addEventListener(`change`,()=>{let r=e.dataset.member,i=e.value;if(!r)return;let a=s(),o=a.find(e=>e.id===t);if(!o)return;let l=d(o.members),u=l.find(e=>e.id===r);if(u){let e=u.role;u.role=i,o.members=l,f(o,`role_changed`,n,`${r} role: ${e} → ${i}`),c(a),v()}})}),u.querySelectorAll(`.remove-btn`).forEach(e=>{e.addEventListener(`click`,()=>{let r=e.dataset.member;if(!r)return;let i=s(),a=i.find(e=>e.id===t);if(!a)return;let o=d(a.members);o.find(e=>e.id===r)?.role!==`owner`&&(a.members=o.filter(e=>e.id!==r),f(a,`member_removed`,n,`Removed ${r}`),c(i),v())})})}function v(){let e=s().find(e=>e.id===t);e&&(g(e,p(d(e.members))),_())}function y(){if(t=o(`id`),n=localStorage.getItem(`sw_user_id`)||`USER-ANON`,!t){document.body.innerHTML=`<div style="padding:80px 24px;text-align:center;color:#be123c">No community ID. <a href="/community" style="color:#0e7490">Back</a></div>`;return}let e=s().find(e=>e.id===t);if(!e){document.body.innerHTML=`<div style="padding:80px 24px;text-align:center;color:#be123c">Community not found. <a href="/community" style="color:#0e7490">Back</a></div>`;return}let r=document.getElementById(`bc-comm`);r&&(r.textContent=e.name,r.href=`/community/view?id=${encodeURIComponent(t)}`),document.title=`Members · ${e.name} — Shadow Warden AI`,h(t),v(),document.getElementById(`member-search`)?.addEventListener(`input`,_),document.getElementById(`add-member-btn`)?.addEventListener(`click`,()=>{let e=document.getElementById(`member-id-input`),r=document.getElementById(`add-err`),i=e.value.trim().toUpperCase();if(!i.match(/^USER-[0-9A-F]{4}$/)){r&&(r.textContent=`Format: USER-XXXX (e.g. USER-1A2B)`,r.style.display=`block`);return}r&&(r.style.display=`none`);let a=s(),o=a.find(e=>e.id===t);if(!o)return;let l=d(o.members);l.find(e=>e.id===i)?r&&(r.textContent=`Already a member.`,r.style.display=`block`):(l.push({id:i,role:`member`}),o.members=l,f(o,`member_joined`,n,`Added ${i}`),c(a),e.value=``,v())}),document.getElementById(`merge-btn`)?.addEventListener(`click`,()=>{let e=document.getElementById(`merge-id-input`),r=document.getElementById(`merge-err`),i=e.value.trim().toUpperCase();if(!i.match(/^COMM-[0-9A-F]{4}$/)){r&&(r.textContent=`Format: COMM-XXXX`,r.style.color=`#be123c`,r.style.display=`block`);return}if(i===t){r&&(r.textContent=`Cannot merge with itself.`,r.style.color=`#be123c`,r.style.display=`block`);return}let a=s(),o=a.find(e=>e.id===t),l=a.find(e=>e.id===i);if(!l){r&&(r.textContent=`${i} not found in your communities.`,r.style.color=`#be123c`,r.style.display=`block`);return}let u=d(o.members),p=d(l.members),m=new Set(u.map(e=>e.id)),h=0;for(let e of p)!m.has(e.id)&&e.role!==`owner`&&(u.push({id:e.id,role:`member`}),h++);o.members=u,f(o,`community_merged`,n,`Merged ${h} members from ${i}`),c(a),e.value=``,r&&(r.textContent=`✓ Merged ${h} new members from ${i}.`,r.style.color=`#15803d`,r.style.display=`block`),v()})}y();