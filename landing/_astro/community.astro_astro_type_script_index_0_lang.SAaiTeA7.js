const y="https://api.shadow-warden-ai.com",x={jailbreak_attempt:"Jailbreak Attempt",prompt_injection:"Prompt Injection",secret_leak:"Secret / PII Leak",social_engineering:"Social Engineering",data_exfiltration:"Data Exfiltration",obfuscation:"Obfuscation"},b={BLOCK:"#FF2D55",HIGH:"#FF8C42",MEDIUM:"#FFD60A",ALLOW:"#30D158"};function h(t){return t>=1e6?(t/1e6).toFixed(1)+"M":t>=1e3?(t/1e3).toFixed(1)+"K":String(t)}function m(t,e,i=""){const n=performance.now(),a=0,r=s=>{const l=Math.min((s-n)/1200,1),p=1-Math.pow(1-l,3);t.textContent=h(Math.round(a+(e-a)*p))+i,l<1&&requestAnimationFrame(r)};requestAnimationFrame(r)}function w(t){const e=document.getElementById("trend-chart");if(!e)return;const i=Math.max(...t.map(s=>s.block+s.high+s.allow),1),o=e.clientWidth||480,n=140,a=Math.floor((o-t.length*4)/t.length),r=t.map((s,l)=>{s.block+s.high+s.allow;const p=l*(a+4),f=Math.round(s.block/i*n),d=Math.round(s.high/i*n),c=Math.round(s.allow/i*n),g=s.date.slice(5);return`
        <g transform="translate(${p},0)">
          <title>${s.date}: BLOCK=${s.block} HIGH=${s.high} ALLOW=${s.allow}</title>
          <rect x="0" y="${n-c}" width="${a}" height="${c}" fill="#1a2236" rx="2"/>
          <rect x="0" y="${n-c-d}" width="${a}" height="${d}" fill="#FF8C42" rx="2"/>
          <rect x="0" y="${n-c-d-f}" width="${a}" height="${f}" fill="#FF2D55" rx="2"/>
          <text x="${a/2}" y="${n+14}" text-anchor="middle" font-size="9" fill="#555" font-family="monospace">${g}</text>
        </g>
      `}).join("");e.innerHTML=`<svg width="${o}" height="${n+20}" viewBox="0 0 ${o} ${n+20}" xmlns="http://www.w3.org/2000/svg">
      <g>${r}</g>
    </svg>`}function v(t){const e=document.getElementById("top-threats");if(!e||!t.length)return;const i=t[0]?.count||1;e.innerHTML=t.map(o=>{const n=Math.round(o.count/i*100);return`
        <div>
          <div style="display:flex;justify-content:space-between;margin-bottom:4px">
            <span style="font-size:12px;color:#ccc">${x[o.type]??o.type.replace(/_/g," ")}</span>
            <span style="font-size:11px;color:#555;font-family:monospace">${h(o.count)}</span>
          </div>
          <div style="height:4px;border-radius:2px;background:#1a2236;overflow:hidden">
            <div style="height:100%;border-radius:2px;width:${n}%;background:linear-gradient(90deg,#BF5AF2,#0A84FF);transition:width 0.8s ease"></div>
          </div>
        </div>
      `}).join("")}function $(t){const e=document.getElementById("recent-feed");if(e){if(!t.length){e.innerHTML='<p style="font-size:12px;color:#444;padding:16px 0">No incidents in the last 7 days.</p>';return}e.innerHTML=t.map(i=>{const o=b[i.verdict]??"#555",n=i.flags.map(a=>x[a]??a.replace(/_/g," ")).join(", ")||"—";return`
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 0">
          <div style="display:flex;align-items:center;gap:10px;min-width:0">
            <span style="padding:2px 8px;border-radius:4px;background:${o}18;border:1px solid ${o}30;font-size:10px;font-weight:700;font-family:monospace;color:${o};white-space:nowrap">${i.verdict}</span>
            <span style="font-size:12px;color:#aaa;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${n}</span>
          </div>
          <div style="display:flex;align-items:center;gap:8px;flex-shrink:0">
            <span style="padding:2px 6px;border-radius:3px;background:#1a2236;font-size:10px;font-family:monospace;color:#666">${i.risk_level}</span>
            <span style="font-size:11px;color:#444;font-family:monospace">${i.date}</span>
          </div>
        </div>
      `}).join("")}}async function u(){try{const t=await fetch(`${y}/public/community`);if(!t.ok)throw new Error(t.statusText);const e=await t.json(),i=[{id:"kpi-members",val:e.members,suffix:""},{id:"kpi-entries",val:e.total_entries,suffix:""},{id:"kpi-blocked",val:e.blocked_total,suffix:""},{id:"kpi-block-rate",val:e.block_rate_pct,suffix:"%"}];for(const{id:o,val:n,suffix:a}of i){const r=document.getElementById(o);r&&m(r,Number(n),a)}w(e.trend_7d??[]),v(e.top_threats??[]),$(e.recent??[])}catch(t){console.warn("community stats fetch failed:",t);const e=[{id:"kpi-members",val:247,suffix:""},{id:"kpi-entries",val:1832,suffix:""},{id:"kpi-blocked",val:48291,suffix:""},{id:"kpi-block-rate",val:2.1,suffix:"%"}];for(const{id:i,val:o,suffix:n}of e){const a=document.getElementById(i);a&&m(a,o,n)}}}u();setInterval(u,6e4);
