const m="https://api.shadow-warden-ai.com",g={jailbreak_attempt:"Jailbreak Attempt",prompt_injection:"Prompt Injection",secret_leak:"Secret / PII Leak",social_engineering:"Social Engineering",data_exfiltration:"Data Exfiltration",obfuscation:"Obfuscation"},w={BLOCK:"#FF2D55",HIGH:"#FF8C42",MEDIUM:"#FFD60A",ALLOW:"#30D158"};function h(t){return t>=1e6?(t/1e6).toFixed(1)+"M":t>=1e3?(t/1e3).toFixed(1)+"K":String(t)}function x(t,n,i=""){const e=performance.now(),o=0,r=s=>{const l=Math.min((s-e)/1200,1),p=1-Math.pow(1-l,3);t.textContent=h(Math.round(o+(n-o)*p))+i,l<1&&requestAnimationFrame(r)};requestAnimationFrame(r)}function $(t){const n=document.getElementById("trend-chart");if(!n)return;const i=Math.max(...t.map(s=>s.block+s.high+s.allow),1),a=n.clientWidth||480,e=140,o=Math.floor((a-t.length*4)/t.length),r=t.map((s,l)=>{s.block+s.high+s.allow;const p=l*(o+4),f=Math.round(s.block/i*e),d=Math.round(s.high/i*e),c=Math.round(s.allow/i*e),b=s.date.slice(5);return`
        <g transform="translate(${p},0)">
          <title>${s.date}: BLOCK=${s.block} HIGH=${s.high} ALLOW=${s.allow}</title>
          <rect x="0" y="${e-c}" width="${o}" height="${c}" fill="#1a2236" rx="2"/>
          <rect x="0" y="${e-c-d}" width="${o}" height="${d}" fill="#FF8C42" rx="2"/>
          <rect x="0" y="${e-c-d-f}" width="${o}" height="${f}" fill="#FF2D55" rx="2"/>
          <text x="${o/2}" y="${e+14}" text-anchor="middle" font-size="9" fill="#555" font-family="monospace">${b}</text>
        </g>
      `}).join("");n.innerHTML=`<svg width="${a}" height="${e+20}" viewBox="0 0 ${a} ${e+20}" xmlns="http://www.w3.org/2000/svg">
      <g>${r}</g>
    </svg>`}function v(t){const n=document.getElementById("top-threats");if(!n||!t.length)return;const i=t[0]?.count||1;n.innerHTML=t.map(a=>{const e=Math.round(a.count/i*100);return`
        <div>
          <div style="display:flex;justify-content:space-between;margin-bottom:4px">
            <span style="font-size:12px;color:#ccc">${g[a.type]??a.type.replace(/_/g," ")}</span>
            <span style="font-size:11px;color:#555;font-family:monospace">${h(a.count)}</span>
          </div>
          <div style="height:4px;border-radius:2px;background:#1a2236;overflow:hidden">
            <div style="height:100%;border-radius:2px;width:${e}%;background:linear-gradient(90deg,#BF5AF2,#0A84FF);transition:width 0.8s ease"></div>
          </div>
        </div>
      `}).join("")}function k(t){const n=document.getElementById("recent-feed");if(n){if(!t.length){n.innerHTML='<p style="font-size:12px;color:#444;padding:16px 0">No incidents in the last 7 days.</p>';return}n.innerHTML=t.map(i=>{const a=w[i.verdict]??"#555",e=i.flags.map(o=>g[o]??o.replace(/_/g," ")).join(", ")||"—";return`
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 0">
          <div style="display:flex;align-items:center;gap:10px;min-width:0">
            <span style="padding:2px 8px;border-radius:4px;background:${a}18;border:1px solid ${a}30;font-size:10px;font-weight:700;font-family:monospace;color:${a};white-space:nowrap">${i.verdict}</span>
            <span style="font-size:12px;color:#aaa;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${e}</span>
          </div>
          <div style="display:flex;align-items:center;gap:8px;flex-shrink:0">
            <span style="padding:2px 6px;border-radius:3px;background:#1a2236;font-size:10px;font-family:monospace;color:#666">${i.risk_level}</span>
            <span style="font-size:11px;color:#444;font-family:monospace">${i.date}</span>
          </div>
        </div>
      `}).join("")}}async function u(){try{const t=await fetch(`${m}/public/community`);if(!t.ok)throw new Error(t.statusText);const n=await t.json(),i=[{id:"kpi-members",val:n.members,suffix:""},{id:"kpi-entries",val:n.total_entries,suffix:""},{id:"kpi-blocked",val:n.blocked_total,suffix:""},{id:"kpi-block-rate",val:n.block_rate_pct,suffix:"%"}];for(const{id:a,val:e,suffix:o}of i){const r=document.getElementById(a);r&&x(r,Number(e),o)}$(n.trend_7d??[]),v(n.top_threats??[]),k(n.recent??[])}catch(t){console.warn("community stats fetch failed:",t);const n=[{id:"kpi-members",val:247,suffix:""},{id:"kpi-entries",val:1832,suffix:""},{id:"kpi-blocked",val:48291,suffix:""},{id:"kpi-block-rate",val:2.1,suffix:"%"}];for(const{id:i,val:a,suffix:e}of n){const o=document.getElementById(i);o&&x(o,a,e)}}}async function y(){try{const t=await fetch(`${m}/public/leaderboard`);if(!t.ok)return;const n=await t.json(),i=document.getElementById("leaderboard");if(!i||!n.leaderboard?.length)return;const a={ELITE:"#FFD60A",GUARDIAN:"#BF5AF2",TOP_SHARER:"#0A84FF",CONTRIBUTOR:"#30D158",NEWCOMER:"#555"};i.innerHTML=n.leaderboard.map(e=>{const o=a[e.badge]??"#555";return`
          <div style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid #0d1220">
            <span style="font-size:13px;font-weight:700;font-family:monospace;color:#333;width:20px;text-align:right">${e.rank}</span>
            <span style="font-size:18px">${e.badge_emoji}</span>
            <span style="padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;font-family:monospace;
                         color:${o};background:${o}18;border:1px solid ${o}30">${e.badge}</span>
            <span style="flex:1"></span>
            <span style="font-size:12px;color:#666;font-family:monospace">${e.entry_count} entries</span>
            <span style="font-size:13px;font-weight:700;font-family:monospace;color:${o};width:52px;text-align:right">${e.points}pt</span>
          </div>
        `}).join("")}catch{}}u();y();setInterval(u,6e4);setInterval(y,12e4);
