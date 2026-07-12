const IS_MAIN=window.DASH_MAIN===true;
const VARIANT=window.DASH_VARIANT||"production";
const fmt=n=>(n??0).toLocaleString("en-IN");
function fmtC(n){ // compact for money
  n=n||0;if(n>=1e7)return (n/1e7).toFixed(1)+"Cr";if(n>=1e5)return (n/1e5).toFixed(1)+"L";
  if(n>=1e3)return (n/1e3).toFixed(1)+"k";return fmt(n);}
function setText(id,v){const el=document.getElementById(id);if(el)el.textContent=v;}
function css(v){return getComputedStyle(document.documentElement).getPropertyValue(v).trim();}

let state={period:"7d",start:null,end:null,shift:"combined"},charts={},layout=[],metrics=[],lastData=null,editing=false,uid=0,hiddenKpis=[];
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
  // hidden KPI list is stored as a special meta entry in the layout array
  const meta=layout.find(x=>x.id==="__kpimeta__");
  hiddenKpis=meta&&meta.hiddenKpis?meta.hiddenKpis:[];
  kpiOrder=meta&&meta.kpiOrder?meta.kpiOrder:[];
  kpiSizes=meta&&meta.kpiSizes?meta.kpiSizes:{};
  layout=layout.filter(x=>x.id!=="__kpimeta__");
  // drop widgets whose metric no longer exists (e.g. after the crushing/cleaning merge)
  const validKeys=new Set(metrics.map(m=>m.key));
  layout=layout.filter(w=>validKeys.has(w.metric));
  // if nothing valid remains, build a sensible default from available metrics
  if(!layout.length){
    const want=["consumption","crushmerged","cleanmerged","inputoutput"].concat(DASH_MAIN?["finance"]:[]);
    let n=0;layout=want.filter(k=>validKeys.has(k)).map(k=>({id:k+"_"+(++n),metric:k,type:"auto",size:k==="consumption"?"large":"small",hidden:false}));
  }
  const sel=document.getElementById("wMetric");
  if(sel)sel.innerHTML=metrics.map(m=>`<option value="${m.key}">${m.label}</option>`).join("");
  applyKpiVisibility();
}
async function saveLayout(){
  const out=layout.concat([{id:"__kpimeta__",hiddenKpis:hiddenKpis,kpiOrder:(editing?currentKpiOrder():kpiOrder),kpiSizes:kpiSizes}]);
  await fetch(`/api/dashboard/layout?variant=${VARIANT}`,{method:"POST",
    headers:{"Content-Type":"application/json","X-CSRF-Token":(document.querySelector("meta[name=csrf-token]")||{}).content},body:JSON.stringify({layout:out})});
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
        <select class="wt-type" title="Chart type">
          <option value="auto"${w.type==="auto"?" selected":""}>Auto</option>
          <option value="bar"${w.type==="bar"?" selected":""}>Bar</option>
          <option value="hbar"${w.type==="hbar"?" selected":""}>H-Bar</option>
          <option value="line"${w.type==="line"?" selected":""}>Line</option>
          <option value="doughnut"${w.type==="doughnut"?" selected":""}>Doughnut</option>
        </select>
        <button type="button" class="wt" data-act="size">${w.size==="large"?"⬍":"⬌"}</button>
        <button type="button" class="wt" data-act="hide">${w.hidden?"🙈":"👁"}</button>
        <button type="button" class="wt" data-act="del">✕</button>
      </div></div><div class="wcanvas"><canvas></canvas></div>`;
    grid.appendChild(card);
    buildChart(card.querySelector("canvas"),w);
    const typeSel=card.querySelector(".wt-type");
    if(typeSel)typeSel.onchange=e=>{e.stopPropagation();w.type=typeSel.value;renderWidgets();};
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
  const kind=metricKind(w.metric);
  // "hbar" is a horizontal bar: render as bar + indexAxis y
  const isH=w.type==="hbar";
  const auto=t=>w.type==="auto"?t:(w.type==="hbar"?"bar":w.type);
  const H=o=>{o=o||{};if(isH)o.horizontal=true;return o;};
  let cfg=null;
  if(kind==="consumption"){cfg={type:auto("bar"),data:{labels,datasets:[
    {label:"Day",data:d.series.map(s=>s.day_consumption),backgroundColor:COLORS.amber,borderRadius:6},
    {label:"Night",data:d.series.map(s=>s.night_consumption),backgroundColor:COLORS.night,borderRadius:6}]},options:opts(H({stacked:true}))};}
  else if(kind==="inputoutput"){cfg={type:auto("bar"),data:{labels,datasets:[
    {label:"Input KG",data:d.series.map(s=>s.input_kg),backgroundColor:COLORS.amber,borderRadius:6},
    {label:"Crushing Output KG",data:d.series.map(s=>s.output),backgroundColor:COLORS.green,borderRadius:6}]},options:opts(H())};}
  else if(kind==="finance"&&d.finance){cfg={type:auto("bar"),data:{labels:["Income","Expense","Profit"],datasets:[
    {data:[d.finance.income,d.finance.expense,d.finance.profit],backgroundColor:[COLORS.green,COLORS.red,COLORS.blue],borderRadius:6}]},options:opts(H({noLegend:true}))};}
  else if(kind==="crushprod"){cfg={type:auto("bar"),data:{labels:d.crushing_products.map(p=>p.name),datasets:[
    {label:"KG",data:d.crushing_products.map(p=>p.kg),backgroundColor:COLORS.green,borderRadius:6}]},options:opts(H({horizontal:w.type!=="bar"}))};}
  else if(kind==="cleanprod"){cfg={type:auto("bar"),data:{labels:d.cleaning_products.map(p=>p.name),datasets:[
    {label:"KG",data:d.cleaning_products.map(p=>p.kg),backgroundColor:COLORS.night,borderRadius:6}]},options:opts(H({horizontal:w.type!=="bar"}))};}
  else if(kind==="crushmerged"||kind==="cleanmerged"){
    const stack=kind==="crushmerged"?(d.crushing_stack||{}):(d.cleaning_stack||{});
    const palette=["#2a78d6","#1baf7a","#eda100","#e34948","#4a3aa7","#e87ba4","#eb6834","#008300"];
    const names=Object.keys(stack);
    if(w.type==="doughnut"){
      // doughnut = period totals per product
      const totals=names.map(n=>stack[n].reduce((a,b)=>a+b,0));
      cfg={type:"doughnut",data:{labels:names,datasets:[{data:totals,backgroundColor:palette.slice(0,names.length),borderWidth:2,borderColor:"#fff"}]},options:opts({noLegend:false})};
    }else{
      const ds=names.map((n,i)=>({label:n,data:stack[n],backgroundColor:palette[i%palette.length]}));
      const o=opts({stacked:true});if(isH)o.indexAxis="y";
      cfg={type:(w.type==="line"?"line":"bar"),data:{labels,datasets:ds},options:o};
    }
  }
  else{const map={crushing:"crushing",cleaning:"cleaning",waste:"waste"};const field=map[w.metric]||"crushing";
    const color=w.metric==="cleaning"?COLORS.night:(w.metric==="waste"?COLORS.red:COLORS.green);
    cfg={type:auto("line"),data:{labels,datasets:[{label:metricLabel(w.metric),data:d.series.map(s=>s[field]),
      borderColor:color,backgroundColor:color+"33",fill:true,tension:.4,pointRadius:0}]},options:opts(H())};}
  // doughnut needs single-color-per-slice; fix palette if user picked doughnut on a series metric
  if(w.type==="doughnut"&&cfg.data.datasets.length===1&&cfg.data.datasets[0].data.length){
    cfg.data.datasets[0].backgroundColor=[COLORS.green,COLORS.night,COLORS.amber,COLORS.red,COLORS.blue,"#a78bfa","#f472b6"];}
  charts[w.id]=new Chart(canvas,cfg);
}
function opts(o={}){const c={responsive:true,maintainAspectRatio:false,
  devicePixelRatio:Math.max(window.devicePixelRatio||1,2),
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
  document.getElementById("editDashBtn").style.display="none";renderWidgets();renderKpiEdit();}
function exitEdit(save){editing=false;document.getElementById("editBar").style.display="none";
  document.getElementById("editDashBtn").style.display="";if(save)saveLayout();renderWidgets();renderKpiEdit();}

// ---- KPI card editability (hide / reorder / resize bento cards) ----
let kpiOrder=[], kpiSizes={};
function applyKpiVisibility(){
  const grid=document.querySelector(".bento");
  if(!grid)return;
  // apply saved order
  if(kpiOrder.length){
    kpiOrder.forEach(m=>{const c=grid.querySelector(`.bento-card[data-metric="${m}"]`);if(c)grid.appendChild(c);});
  }
  document.querySelectorAll(".bento-card").forEach(c=>{
    const m=c.dataset.metric;
    if(hiddenKpis.includes(m)&&!editing)c.style.display="none";else c.style.display="";
    // apply saved size (small=1 col, wide=2 col via existing 'wide2' class)
    const sz=kpiSizes[m];
    if(sz==="wide")c.classList.add("wide2");else if(sz==="small")c.classList.remove("wide2");
  });
}
function currentKpiOrder(){return [...document.querySelectorAll(".bento-card")].map(c=>c.dataset.metric);}
function renderKpiEdit(){
  const grid=document.querySelector(".bento");
  document.querySelectorAll(".bento-card").forEach(c=>{
    let tools=c.querySelector(".kpi-tools");
    if(editing){
      c.classList.add("kpi-editing");c.style.position="relative";c.setAttribute("draggable","true");
      if(!tools){
        tools=document.createElement("div");tools.className="kpi-tools";
        tools.style.cssText="position:absolute;top:6px;right:6px;z-index:5;display:flex;gap:4px";
        const mk=(txt,act)=>{const b=document.createElement("button");b.type="button";b.className="wt";b.textContent=txt;b.dataset.act=act;return b;};
        tools.appendChild(mk("⬌","size"));tools.appendChild(mk("👁","hide"));
        c.appendChild(tools);
        tools.querySelectorAll("button").forEach(b=>b.onclick=e=>{e.stopPropagation();
          const m=c.dataset.metric,a=b.dataset.act;
          if(a==="hide"){if(hiddenKpis.includes(m))hiddenKpis=hiddenKpis.filter(x=>x!==m);else hiddenKpis.push(m);}
          else if(a==="size"){kpiSizes[m]=(kpiSizes[m]==="wide")?"small":"wide";}
          renderKpiEdit();});
      }
      const hidden=hiddenKpis.includes(c.dataset.metric);
      tools.querySelector('[data-act=hide]').textContent=hidden?"🙈":"👁";
      c.classList.toggle("dimmed",hidden);
      // drag to reorder
      c.ondragstart=e=>{e.dataTransfer.setData("text/plain",c.dataset.metric);c.classList.add("dragging");};
      c.ondragend=()=>{c.classList.remove("dragging");kpiOrder=currentKpiOrder();};
      c.ondragover=e=>{e.preventDefault();const dragging=grid.querySelector(".bento-card.dragging");
        if(dragging&&dragging!==c)grid.insertBefore(dragging,c);};
    }else{
      c.classList.remove("kpi-editing");c.removeAttribute("draggable");
      if(tools)tools.remove();
    }
  });
  applyKpiVisibility();
}
window.addWidget=function(){const m=document.getElementById("wMetric").value,ty=document.getElementById("wType").value,sz=document.getElementById("wSize").value;
  layout.push({id:m+"_"+(++uid),metric:m,type:ty,size:sz,hidden:false});
  document.getElementById("modal-widget").style.display="none";renderWidgets();};

// KPI show/hide picker
const KPI_LABELS={crushing:"Crushing Output",consumption:"MGVCL Units",input:"Input KG",cleaning:"Cleaning KG",waste:"Waste KG",profit:"Profit ₹"};
function openKpiPicker(){
  const list=document.getElementById("kpiPickList");if(!list)return;
  const cards=[...document.querySelectorAll(".bento-card")];
  list.innerHTML=cards.map(c=>{const m=c.dataset.metric;const shown=!hiddenKpis.includes(m);
    return `<label style="display:flex;align-items:center;gap:8px;cursor:pointer">
      <input type="checkbox" data-m="${m}" ${shown?"checked":""}> ${KPI_LABELS[m]||m}</label>`;}).join("");
  list.querySelectorAll("input").forEach(cb=>cb.onchange=()=>{
    const m=cb.dataset.m;
    if(cb.checked)hiddenKpis=hiddenKpis.filter(x=>x!==m);
    else if(!hiddenKpis.includes(m))hiddenKpis.push(m);
    applyKpiVisibility();});
  document.getElementById("modal-kpi").style.display="flex";
}

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
const akb=document.getElementById("addKpiBtn");if(akb)akb.addEventListener("click",openKpiPicker);

async function loadLowStock(){try{const r=await fetch("/api/low_stock");const j=await r.json();
  const el=document.getElementById("lowStockBanner");if(!el)return;
  if(!j.alerts||!j.alerts.length){el.style.display="none";return;}
  el.innerHTML="⚠ Low stock — "+j.alerts.map(a=>`<b>${a.name}</b> ${a.qty}kg ≤ ${a.threshold}`).join(" · ");
  el.style.display="block";}catch(e){}}

(async function(){await loadLayout();await loadData();loadLowStock();})();