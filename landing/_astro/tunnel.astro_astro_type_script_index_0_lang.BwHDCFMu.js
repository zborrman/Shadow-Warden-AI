var e=`sw_communities`,t=``,n=``,r=!1;function i(e){return new URLSearchParams(window.location.search).get(e)||``}function a(){try{return JSON.parse(localStorage.getItem(e)||`[]`)}catch{return[]}}function o(t){localStorage.setItem(e,JSON.stringify(t))}function s(e){return`sw_tunnel_${e}`}function c(e){try{return JSON.parse(localStorage.getItem(s(e))||`[]`)}catch{return[]}}function l(e,t){localStorage.setItem(s(e),JSON.stringify(t))}function u(e){return String(e).replace(/&/g,`&amp;`).replace(/</g,`&lt;`).replace(/>/g,`&gt;`)}function d(e,t,n,r){e.activityLog||=[],e.activityLog.unshift({ts:Date.now(),action:t,userId:n,detail:r}),e.activityLog.length>200&&(e.activityLog.length=200)}function f(e){let t=[{label:`📋 Overview`,href:`/community/view?id=${encodeURIComponent(e)}`},{label:`👥 Members`,href:`/community/members?id=${encodeURIComponent(e)}`},{label:`🔒 Tunnel`,href:`/community/tunnel?id=${encodeURIComponent(e)}`,active:!0},{label:`🔌 Integrations`,href:`/community/integrations?id=${encodeURIComponent(e)}`},{label:`📊 Activity`,href:`/community/activity?id=${encodeURIComponent(e)}`},{label:`⚙️ Settings`,href:`/community/settings?id=${encodeURIComponent(e)}`}],n=document.getElementById(`tab-nav`);n&&(n.innerHTML=t.map(e=>`
        <a href="${e.href}"
           style="padding:9px 16px;border-radius:10px;font-size:13px;font-weight:600;text-decoration:none;white-space:nowrap;
                  ${e.active?`background:rgba(6,182,212,0.15);border:1px solid rgba(6,182,212,0.3);color:#0e7490`:`background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);color:#556072`};
                  transition:all 0.15s"
           ${e.active?``:`onmouseover="this.style.color='#556072';this.style.background='rgba(255,255,255,0.07)'" onmouseout="this.style.color='#556072';this.style.background='rgba(255,255,255,0.03)'"`}>
          ${e.label}
        </a>
      `).join(``))}function p(){let e=c(t);if(r){let n=Date.now()-864e5;e=e.filter(e=>new Date(e.ts).getTime()>n),l(t,e)}let i=document.getElementById(`messages`);i&&(e.length===0?i.innerHTML=`
          <div style="text-align:center;padding:40px 20px">
            <p style="font-size:36px;margin-bottom:12px">🔒</p>
            <p style="color:#475569;font-size:14px">No messages yet. Say something.</p>
            ${r?`<p style="color:#475569;font-size:11px;margin-top:8px">24h auto-delete is active</p>`:``}
          </div>`:(i.innerHTML=e.map(e=>{let t=e.sender===n,r=new Date(e.ts).toLocaleTimeString([],{hour:`2-digit`,minute:`2-digit`});return`
          <div style="display:flex;flex-direction:${t?`row-reverse`:`row`};gap:10px;margin-bottom:12px;align-items:flex-end">
            <div style="max-width:72%;min-width:80px">
              <p style="font-size:10px;font-family:monospace;color:#475569;margin-bottom:4px;${t?`text-align:right`:``}">
                ${u(e.sender)} · ${r}
              </p>
              <div style="padding:10px 14px;border-radius:${t?`14px 14px 4px 14px`:`14px 14px 14px 4px`};
                          ${t?`background:rgba(6,182,212,0.15);border:1px solid rgba(6,182,212,0.25)`:`background:var(--sw-surf-1);border:1px solid rgba(255,255,255,0.08)`}">
                <p style="font-size:10px;color:#15803d;font-family:monospace;margin:0 0 4px;font-weight:600">Demo · unencrypted</p>
                <p style="font-size:14px;color:var(--ink-1);margin:0;line-height:1.5;word-break:break-word">${u(e.text)}</p>
              </div>
            </div>
          </div>`}).join(``),i.scrollTop=i.scrollHeight))}function m(e){if(!e.trim())return;let r=c(t);r.push({sender:n,text:e.trim(),ts:new Date().toISOString()}),l(t,r),p()}function h(e){let t=document.getElementById(`disappearing-track`),n=document.getElementById(`disappearing-thumb`);t&&(t.style.background=e?`rgba(6,182,212,0.4)`:`#1e293b`),n&&(n.style.background=e?`#0e7490`:`#475569`,n.style.left=e?`20px`:`2px`)}function g(){if(t=i(`id`),n=localStorage.getItem(`sw_user_id`)||`USER-ANON`,!t){document.body.innerHTML=`<div style="padding:80px 24px;text-align:center;color:#be123c">No community ID. <a href="/community" style="color:#0e7490">Back</a></div>`;return}let e=a().find(e=>e.id===t);if(!e){document.body.innerHTML=`<div style="padding:80px 24px;text-align:center;color:#be123c">Community not found. <a href="/community" style="color:#0e7490">Back</a></div>`;return}let c=document.getElementById(`bc-comm`);c&&(c.textContent=e.name,c.href=`/community/view?id=${encodeURIComponent(t)}`),document.title=`Tunnel · ${e.name} — Shadow Warden AI`;let l=(e.publicKey||``).replace(`SW-PUB-`,``).substring(0,8)||`NO-KEY`,u=document.getElementById(`key-fingerprint`);u&&(u.textContent=l),r=!!e.disappearingMessages;let g=document.getElementById(`disappearing-toggle`);g&&(g.checked=r),h(r),g?.addEventListener(`change`,()=>{r=g.checked;let e=a(),n=e.find(e=>e.id===t);n&&(n.disappearingMessages=r,o(e)),h(r),p()}),f(t),p();let _=document.getElementById(`msg-input`);document.getElementById(`send-btn`)?.addEventListener(`click`,()=>{m(_.value),_.value=``,_.focus()}),_?.addEventListener(`keydown`,e=>{e.key===`Enter`&&!e.shiftKey&&(e.preventDefault(),m(_.value),_.value=``)}),document.getElementById(`clear-btn`)?.addEventListener(`click`,()=>{if(!confirm(`Clear all tunnel messages? This cannot be undone.`))return;localStorage.removeItem(s(t));let e=a(),r=e.find(e=>e.id===t);r&&(d(r,`messages_cleared`,n,`Tunnel messages cleared`),o(e)),p()}),document.getElementById(`export-key-btn`)?.addEventListener(`click`,()=>{let e=a().find(e=>e.id===t),n=e?.publicKey||`NO-KEY-GENERATED`,r=`-----BEGIN SHADOW WARDEN PUBLIC KEY-----
Community: ${t}
Algorithm: none (demo identifier, not a key)
Generated: ${new Date(e?.created||Date.now()).toISOString()}

${n}

Fingerprint: ${n.replace(`SW-PUB-`,``).substring(0,8)}
-----END SHADOW WARDEN PUBLIC KEY-----`,i=new Blob([r],{type:`text/plain`}),o=document.createElement(`a`);o.href=URL.createObjectURL(i),o.download=`sw-public-key-${t}.asc`,o.click(),URL.revokeObjectURL(o.href)})}g();