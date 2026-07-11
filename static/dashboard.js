const IS_MAIN=window.DASH_MAIN===true;
const VARIANT=window.DASH_VARIANT||"production";
const fmt=n=>(n??0).toLocaleString("en-IN");
function fmtC(n){ // compact for money
  n=n||0;if(n>=1e7)return (n/1e7).toFixed(1)+"Cr";if(n>=1e5)return (n/1e5).toFixed(1)+"L";
  if(n>=1e3)return (n/1e3).toFixed(1)+"k";return fmt(n);}
function setText(id,v){const el=document.getElementById(id);if(el)el.textContent=v;}
function css(v){return getComputedStyle(document.documentElement).getPropertyValue(v).trim();}

let state={period:"7d",start:null,end:null,shift:"combined"},charts={},layout=[],metrics=[],lastData=null,editing=false,uid=0;
const COLORS={green:"#22c55e",amber:"#f59e0b",blue:"#0891b2",night:"#6366f1",red:"#f87171",violet:"#a78bfa"};

function chartInk(){return css('--muted')||'#888';}
if(window.Chart){Chart.defaults.color=chartInk();Chart.defaults.borderColor='rgba(128,128,128,.12)';Chart.defaults.font.family='Inter';}
new MutationObserver(()=>{if(window.Chart)Chart.defaults.color=chartInk();if(lastData)renderWidgets();})
  .observe(document.documentElement,{attributes:true,attributeFilter:['data-theme']});

// ---- sparkline path builder ----
function sparkPath(vals,w,h,pad){
  pad=pad||2;if(!vals.length)return "";
  if(vals.length===1){const y=(h/2).toFixed(1);return `M${pad},${y} L${(w-pad).toFixed(1)},${y}`;}
  const mn=Math.min(...vals),mx=Math.max(...vals),rng=(mx-mn)||1;
  return vals.map((v,i)=>{
    const x=(i/(vals.length-1))*(w-pad*2)+pad;
    const y=h-pad-((v-mn)/rng)*(h-pad*2);
    return (i?"L":"M")+x.toFixed(1)+","+y.toFixed(1);
  }).join(" ");
}
function drawSpark(id,vals,color,fill){
  const el=document.getElementById(id);if(!el)return;
  const vb=el.getAttribute("viewBox").split(" ").map(Number),w=vb[2],h=vb[3];
  const p=sparkPath(vals,w,h);
  let html="";
  if(fill&&vals.length){
    const mn=Math.min(...vals),mx=Math.max(...vals),rng=(mx-mn)||1;
    const last=vals.map((v,i)=>{const x=(i/(vals.length-1))*(w-4)+2;const y=h-2-((v-mn)/rng)*(h-4);return x.toFixed(1)+","+y.toFixed(1);});
    const gid="sg"+id;
    html+=`<defs><linearGradient id="${gid}" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="${color}" stop-opacity=".45"/><stop offset="1" stop-color="${color}" stop-opacity="0"/></linearGradient></defs>`;
    html+=`<path d="${p} L${w-2},${h} L2,${h} Z" fill="url(#${gid})"/>`;
  }
  html+=`<path d="${p}" fill="none" stroke="${color}" stroke-width="${fill?2.5:2}" stroke-linecap="round" stroke-linejoin="round"/>`;
  el.innerHTML=html;
}
function badge(id,pct,goodUp){
  const el=document.getElementById(id);if(!el)return;
  if(pct===null||pct===undefined){el.textContent="";el.className=el.className.replace(/ (up|down)/g,"");return;}
  const up=pct>=0;const good=goodUp?up:!up;
  el.textContent=(up?"↑ ":"↓ ")+Math.abs(pct)+"%";
  el.className=el.className.replace(/ (up|down)/g,"")+(good?" up":" down");
}

async function loadLayout(){
  const r=await fetch(`/api/dashboard/layout?variant=${VARIANT}`);const j=await r.json();
  layout=j.layout||[];metrics=j.metrics||[];
  const sel=document.getElementById("wMetric");
  if(sel)sel.innerHTML=metrics.map(m=>`<option value="${m.key}">${m.label}</option>`).join("");
}
async function saveLayout(){
  await fetch(`/api/dashboard/layout?variant=${VARIANT}`,{method:"POST",
    headers:{"Content-Type":"application/json","X-CSRF-Token":(document.querySelector("meta[name=csrf-token]")||{}).content},body:JSON.stringify({layout})});
}
function metricLabel(k){const m=metrics.find(x=>x.key===k);return m?m.label:k;}
function metricKind(k){const m=metrics.find(x=>x.key===k);return m?m.kind:"series";}

async function loadData(){
  let url=`/api/summary?period=${state.period}&shift=${state.shift}`;
  if(state.period==="custom"&&state.start&&state.end)url+=`&start=${state.start}&end=${state.end}`;
  const d=await(await fetch(url)).json();lastData=d;
  setText('rangeLabel',`${d.range.start} → ${d.range.end} · ${d.kpi.reports} shift reports`);
  const k=d.kpi,t=d.trends||{};
  // hero
  const hv=document.getElementById('kCrush');if(hv)hv.innerHTML=`${fmt(k.crushing)}<span class="u"> kg</span>`;
  badge('tCrush',t.crushing,true);
  setText('kUnits',fmt(k.consumption));badge('tUnits',t.consumption,true);
  setText('kInput',fmt(k.input_kg));badge('tInput',t.input_kg,true);
  setText('kClean',fmt(k.cleaning));badge('tClean',t.cleaning,true);
  setText('kWaste',fmt(k.waste));badge('tWaste',t.waste,false);
  // minor efficiency calcs
  setText('eYield',(k.yield_pct??0)+'%');
  setText('eWaste',(k.waste_pct??0)+'%');
  setText('eOPU',(k.output_per_unit??0)+' kg');
  if(k.power_cost_per_kg!=null){setText('eCPK','₹'+k.power_cost_per_kg);document.getElementById('effCPK').style.display='';}
  else{document.getElementById('effCPK').style.display='none';}
  if(IS_MAIN&&d.finance){
    setText('kProfit','₹'+fmtC(d.finance.profit));
    setText('kSales','₹'+fmtC(d.sales_inr));setText('kExport','₹'+fmtC(d.export_inr));
    setText('kIncome','₹'+fmtC(d.finance.income));setText('kExpense','₹'+fmtC(d.finance.expense));
  }
  // sparklines from series
  const S=d.series||[];
  drawSpark('heroSpark',S.map(x=>x.crushing),COLORS.green,true);
  drawSpark('sparkUnits',S.map(x=>x.consumption),COLORS.blue);
  drawSpark('sparkInput',S.map(x=>x.input_kg),COLORS.amber);
  drawSpark('sparkClean',S.map(x=>x.cleaning),COLORS.night);
  drawSpark('sparkWaste',S.map(x=>x.waste),COLORS.red);
  renderWidgets();
}

function renderWidgets(){
  const grid=document.getElementById("chartGrid");if(!grid)return;
  grid.innerHTML="";Object.values(charts).forEach(c=>{try{c.destroy()}catch(e){}});charts={};
  layout.forEach(w=>{
    if(w.hidden&&!editing)return;
    const card=document.createElement("div");
    card.className="chart-card"+(w.size==="large"?" wide":"")+(w.hidden?" dimmed":"");
    card.dataset.wid=w.id;
    card.innerHTML=`<div class="wcard-head"><h3>${metricLabel(w.metric)}</h3>
      <div class="wtools">
        <button type="button" class="wt" data-act="size">${w.size==="large"?"⬍":"⬌"}</button>
        <button type="button" class="wt" data-act="hide">${w.hidden?"🙈":"👁"}</button>
        <button type="button" class="wt" data-act="del">✕</button>
      </div></div><div class="wcanvas"><canvas></canvas></div>`;
    grid.appendChild(card);
    buildChart(card.querySelector("canvas"),w);
    card.querySelectorAll(".wt").forEach(b=>b.onclick=e=>{e.stopPropagation();
      const a=b.dataset.act;
      if(a==="size")w.size=w.size==="large"?"small":"large";
      else if(a==="hide")w.hidden=!w.hidden;
      else if(a==="del")layout=layout.filter(x=>x.id!==w.id);
      renderWidgets();});
    card.querySelector(".wtools").style.display=editing?"flex":"none";
    if(editing){card.classList.add("editing");card.setAttribute("draggable","true");}
  });
  if(editing)addDnD();
}

function buildChart(canvas,w){
  if(!lastData)return;const d=lastData,labels=d.series.map(s=>s.date);
  const kind=metricKind(w.metric),auto=t=>w.type==="auto"?t:w.type;let cfg=null;
  if(kind==="consumption"){cfg={type:auto("bar"),data:{labels,datasets:[
    {label:"Day",data:d.series.map(s=>s.day_consumption),backgroundColor:COLORS.amber,borderRadius:6},
    {label:"Night",data:d.series.map(s=>s.night_consumption),backgroundColor:COLORS.night,borderRadius:6}]},options:opts({stacked:true})};}
  else if(kind==="inputoutput"){cfg={type:auto("bar"),data:{labels,datasets:[
    {label:"Input KG",data:d.series.map(s=>s.input_kg),backgroundColor:COLORS.amber,borderRadius:6},
    {label:"Crushing Output KG",data:d.series.map(s=>s.output),backgroundColor:COLORS.green,borderRadius:6}]},options:opts()};}
  else if(kind==="finance"&&d.finance){cfg={type:auto("bar"),data:{labels:["Income","Expense","Profit"],datasets:[
    {data:[d.finance.income,d.finance.expense,d.finance.profit],backgroundColor:[COLORS.green,COLORS.red,COLORS.blue],borderRadius:6}]},options:opts({noLegend:true})};}
  else if(kind==="crushprod"){cfg={type:auto("bar"),data:{labels:d.crushing_products.map(p=>p.name),datasets:[
    {label:"KG",data:d.crushing_products.map(p=>p.kg),backgroundColor:COLORS.green,borderRadius:6}]},options:opts({horizontal:true})};}
  else if(kind==="cleanprod"){cfg={type:auto("bar"),data:{labels:d.cleaning_products.map(p=>p.name),datasets:[
    {label:"KG",data:d.cleaning_products.map(p=>p.kg),backgroundColor:COLORS.night,borderRadius:6}]},options:opts({horizontal:true})};}
  else{const map={crushing:"crushing",cleaning:"cleaning",waste:"waste"};const field=map[w.metric]||"crushing";
    const color=w.metric==="cleaning"?COLORS.night:(w.metric==="waste"?COLORS.red:COLORS.green);
    cfg={type:auto("line"),data:{labels,datasets:[{label:metricLabel(w.metric),data:d.series.map(s=>s[field]),
      borderColor:color,backgroundColor:color+"33",fill:true,tension:.4,pointRadius:0}]},options:opts()};}
  charts[w.id]=new Chart(canvas,cfg);
}
function opts(o={}){const c={responsive:true,maintainAspectRatio:false,
  plugins:{legend:{position:"bottom",display:!o.noLegend,labels:{usePointStyle:true,boxWidth:8}}},
  scales:{x:{grid:{display:false}},y:{grid:{color:'rgba(128,128,128,.1)'}}}};
  if(o.stacked){c.scales.x.stacked=true;c.scales.y.stacked=true;}
  if(o.horizontal)c.indexAxis="y";return c;}

// drag reorder
let dragEl=null;
function addDnD(){document.querySelectorAll("#chartGrid .chart-card").forEach(c=>{
  c.ondragstart=()=>{dragEl=c;c.classList.add("dragging");};
  c.ondragend=()=>{c.classList.remove("dragging");dragEl=null;reorderDOM();};
  c.ondragover=e=>{e.preventDefault();const a=after(e.clientY);const g=document.getElementById("chartGrid");
    if(a==null)g.appendChild(dragEl);else g.insertBefore(dragEl,a);};});}
function after(y){const els=[...document.querySelectorAll("#chartGrid .chart-card:not(.dragging)")];
  let cl={d:-1e9,el:null};els.forEach(c=>{const b=c.getBoundingClientRect();const o=y-b.top-b.height/2;
    if(o<0&&o>cl.d)cl={d:o,el:c};});return cl.el;}
function reorderDOM(){const order=[...document.querySelectorAll("#chartGrid .chart-card")].map(c=>c.dataset.wid);
  layout.sort((a,b)=>order.indexOf(a.id)-order.indexOf(b.id));}

function enterEdit(){editing=true;document.getElementById("editBar").style.display="flex";
  document.getElementById("editDashBtn").style.display="none";renderWidgets();}
function exitEdit(save){editing=false;document.getElementById("editBar").style.display="none";
  document.getElementById("editDashBtn").style.display="";if(save)saveLayout();renderWidgets();}
window.addWidget=function(){const m=document.getElementById("wMetric").value,ty=document.getElementById("wType").value,sz=document.getElementById("wSize").value;
  layout.push({id:m+"_"+(++uid),metric:m,type:ty,size:sz,hidden:false});
  document.getElementById("modal-widget").style.display="none";renderWidgets();};

document.getElementById("periodBtns").addEventListener("click",e=>{if(e.target.tagName!=="BUTTON")return;
  document.querySelectorAll("#periodBtns button").forEach(b=>b.classList.remove("active"));
  e.target.classList.add("active");state.period=e.target.dataset.period;
  document.getElementById("customRange").style.display=state.period==="custom"?"flex":"none";
  if(state.period!=="custom")loadData();});
document.getElementById("applyCustom").addEventListener("click",()=>{
  state.start=document.getElementById("startDate").value;state.end=document.getElementById("endDate").value;
  if(state.start&&state.end)loadData();});
document.getElementById("shiftBtns").addEventListener("click",e=>{if(e.target.tagName!=="BUTTON")return;
  document.querySelectorAll("#shiftBtns button").forEach(b=>b.classList.remove("active"));
  e.target.classList.add("active");state.shift=e.target.dataset.shift;loadData();});
document.getElementById("editDashBtn").addEventListener("click",enterEdit);
document.getElementById("saveDashBtn").addEventListener("click",()=>exitEdit(true));
document.getElementById("resetDashBtn").addEventListener("click",async()=>{
  await fetch(`/api/dashboard/layout?variant=${VARIANT}`,{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":(document.querySelector("meta[name=csrf-token]")||{}).content},body:JSON.stringify({layout:[]})});
  location.reload();});
document.getElementById("addWidgetBtn").addEventListener("click",()=>{document.getElementById("modal-widget").style.display="flex";});

async function loadLowStock(){try{const r=await fetch("/api/low_stock");const j=await r.json();
  const el=document.getElementById("lowStockBanner");if(!el)return;
  if(!j.alerts||!j.alerts.length){el.style.display="none";return;}
  el.innerHTML="⚠ Low stock — "+j.alerts.map(a=>`<b>${a.name}</b> ${a.qty}kg ≤ ${a.threshold}`).join(" · ");
  el.style.display="block";}catch(e){}}

(async function(){await loadLayout();await loadData();loadLowStock();})();
