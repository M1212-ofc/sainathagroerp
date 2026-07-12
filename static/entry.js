// Wt/bag defaults keyed by product name substring
function defaultWeight(name){
  const n=(name||"").toLowerCase();
  if(n.includes("bhunar")||n.includes("ભૂરૂ"))return 20;
  if(n.includes("ground grit")||n.includes("દળાયેલી"))return 30;
  return 25;
}
const DEFAULT_LINES = [
  { category:"crushing", name:"પાવડર (Powder)" },
  { category:"crushing", name:"લોટ જેવો પાવડર (Flour-like Powder)" },
  { category:"crushing", name:"દળાયેલી ગ્રીટ (Ground Grit)" },
  { category:"crushing", name:"પેટીનો ક્રસ્ટ (Peti Crust)" },
  { category:"cleaning", name:"ગ્રીટ નંબર ૧ (Grit No. 1)" },
  { category:"cleaning", name:"ગ્રીટ નંબર ૨ (Grit No. 2)" },
  { category:"cleaning", name:"ગ્રીટ નંબર ૩ (Grit No. 3)" },
  { category:"cleaning", name:"ગ્રીટ નંબર ૪ (Grit No. 4)" },
  { category:"cleaning", name:"ભૂરૂ (Bhunar)" },
];
const body=document.getElementById("linesBody");

function recalcTotals(){let ct=0,ck=0,lt=0,lk=0;
  body.querySelectorAll("tr").forEach(tr=>{const cat=tr.querySelector("select").value;
    const th=parseFloat(tr.querySelector(".calc-theli").value)||0;
    const tot=parseFloat(tr.querySelector(".total").value)||0;
    if(cat==="crushing"){ct+=th;ck+=tot;}else{lt+=th;lk+=tot;}});
  ctTheli.textContent=+ct.toFixed(2);ctKg.textContent=+ck.toFixed(2);
  clTheli.textContent=+lt.toFixed(2);clKg.textContent=+lk.toFixed(2);
  window._crushingKg=ck;              // expose crushing output for waste calc
  recalcWaste();}

function addRow(line={}){const tr=document.createElement("tr");
  const wt = (line.theli_weight!==undefined && line.theli_weight!=="" && line.theli_weight!==null)
             ? line.theli_weight : defaultWeight(line.name);
  tr.innerHTML=`<td><select name="line_cat">
    <option value="crushing" ${line.category==="crushing"?"selected":""}>Crushing</option>
    <option value="cleaning" ${line.category==="cleaning"?"selected":""}>Cleaning</option></select></td>
    <td><input type="text" name="line_name" value="${line.name||""}"></td>
    <td><input type="number" step="any" name="line_theli" value="${line.theli||""}" class="calc-theli"></td>
    <td><input type="number" step="any" name="line_weight" value="${wt}" class="calc-wt"></td>
    <td><input type="number" step="any" name="line_total" value="${line.total_kg||""}" class="total"></td>
    <td><button type="button" class="row-del">×</button></td>`;
  body.appendChild(tr);
  const nameEl=tr.querySelector('input[name=line_name]');
  const theli=tr.querySelector(".calc-theli"),weight=tr.querySelector(".calc-wt"),total=tr.querySelector(".total");
  const rc=()=>{const t=parseFloat(theli.value)||0,w=parseFloat(weight.value)||0;if(t&&w)total.value=+(t*w).toFixed(2);recalcTotals();};
  theli.addEventListener("input",rc);weight.addEventListener("input",rc);total.addEventListener("input",recalcTotals);
  tr.querySelector("select").addEventListener("change",recalcTotals);
  // if user changes the name and hasn't touched weight, refresh default weight
  nameEl.addEventListener("change",()=>{ if(!weight.dataset.touched){weight.value=defaultWeight(nameEl.value);rc();}});
  weight.addEventListener("input",()=>weight.dataset.touched="1");
  tr.querySelector(".row-del").addEventListener("click",()=>{tr.remove();recalcTotals();});}

document.getElementById("addLine").addEventListener("click",()=>addRow());
if(typeof existingLines!=="undefined"&&existingLines.length)existingLines.forEach(addRow);else DEFAULT_LINES.forEach(addRow);

// ---- Workers (attendance from master list) ----
const wbody=document.getElementById("workersBody");
const addSelect=document.getElementById("addWorkerSelect");
const MW=(typeof masterWorkers!=="undefined")?masterWorkers:[];
const MM_FORWORKER=(typeof masterMachines!=="undefined")?masterMachines:[];
function machineOptions(sel){
  let o='<option value="">— machine —</option>';
  MM_FORWORKER.forEach(m=>{o+=`<option value="${m.id}"${String(sel)===String(m.id)?" selected":""}>${m.name}</option>`;});
  return o;
}
function rebuildAddSelect(){
  const used=new Set([...wbody.querySelectorAll('input[name=worker_id]')].map(i=>i.value));
  addSelect.innerHTML='<option value="">— re-add a removed worker —</option>'+
    MW.filter(m=>!used.has(String(m.id))).map(m=>`<option value="${m.id}">${m.name}</option>`).join("");
}
function addWorkerRow(w){
  const idx=wbody.children.length+1;
  const att=w.attendance||"present";
  const hrs=(w.hours!==undefined&&w.hours!==null&&w.hours!=="")?w.hours:(w.default_hours||"");
  const tr=document.createElement("tr");
  tr.innerHTML=`<td><input type="number" name="worker_slno" value="${w.slno||idx}" style="width:44px">
    <input type="hidden" name="worker_id" value="${w.worker_id||w.id||""}"></td>
    <td><input type="text" name="worker_name" value="${(w.name||"").replace(/"/g,'&quot;')}" readonly style="background:transparent;border:none"></td>
    <td><select name="worker_attendance" class="att-sel">
      <option value="present"${att==="present"?" selected":""}>✅ Present</option>
      <option value="absent"${att==="absent"?" selected":""}>❌ Absent</option>
      <option value="half"${att==="half"?" selected":""}>◐ Half day</option>
    </select></td>
    <td><select name="worker_machine">${machineOptions(w.machine_id)}</select></td>
    <td><input type="number" step="any" name="worker_hours" value="${hrs}" style="width:80px" placeholder="hrs"></td>
    <td><input type="number" step="any" name="worker_ot" value="${w.ot_hours||''}" style="width:80px" placeholder="OT"></td>
    <td><button type="button" class="row-del">×</button></td>`;
  wbody.appendChild(tr);
  const sel=tr.querySelector(".att-sel"),hoursInput=tr.querySelector('input[name=worker_hours]');
  function syncHours(){if(sel.value==="absent"){hoursInput.value=0;hoursInput.disabled=true;}
    else{hoursInput.disabled=false;if(sel.value==="half"&&hoursInput.value){hoursInput.value=Math.round((parseFloat(hoursInput.value)||0));}}}
  sel.addEventListener("change",syncHours);syncHours();
  tr.querySelector(".row-del").addEventListener("click",()=>{tr.remove();rebuildAddSelect();});
  rebuildAddSelect();
}
document.getElementById("addWorkerBtn").addEventListener("click",()=>{
  const id=addSelect.value;if(!id)return;const m=MW.find(x=>String(x.id)===id);if(m)addWorkerRow(m);});
document.getElementById("addAllWorkers").addEventListener("click",()=>{
  const used=new Set([...wbody.querySelectorAll('input[name=worker_id]')].map(i=>i.value));
  MW.filter(m=>!used.has(String(m.id))).forEach(addWorkerRow);});
// initial load
if(typeof existingWorkers!=="undefined"&&existingWorkers.length){
  // editing an existing report -> load its saved attendance
  existingWorkers.forEach(addWorkerRow);
}else{
  // NEW entry -> auto-fill every master worker as Present (no clicking needed)
  MW.forEach(m=>addWorkerRow(m));
}
rebuildAddSelect();

// ---- Machines (per-machine output/units/labour/maintenance) ----
const mbody=document.getElementById("machinesBody");
const mAddSelect=document.getElementById("addMachineSelect");
const MM=(typeof masterMachines!=="undefined")?masterMachines:[];
function rebuildMachineSelect(){
  if(!mAddSelect)return;
  const used=new Set([...mbody.querySelectorAll('input[name=machine_id]')].map(i=>i.value));
  mAddSelect.innerHTML='<option value="">— re-add a removed machine —</option>'+
    MM.filter(m=>!used.has(String(m.id))).map(m=>`<option value="${m.id}">${m.name}</option>`).join("");
}
function addMachineRow(m){
  if(!mbody)return;
  const mid=m.id||m.machine_id||'';
  const tr=document.createElement("tr");
  tr.innerHTML=`<td><input type="text" name="machine_name" value="${(m.name||m.machine_name||'').replace(/"/g,'&quot;')}" readonly style="background:transparent;border:none">
      <input type="hidden" name="machine_id" value="${mid}"></td>
    <td><input type="number" step="any" name="machine_maint" value="${m.maint_cost||''}" style="width:110px" placeholder="0"></td>
    <td><span class="mc-workers" data-mid="${mid}" style="font-weight:600;color:var(--primary)">0</span> assigned</td>
    <td><button type="button" class="row-del">×</button></td>`;
  mbody.appendChild(tr);
  tr.querySelector(".row-del").addEventListener("click",()=>{tr.remove();rebuildMachineSelect();updateMachineWorkerCounts();});
  rebuildMachineSelect();updateMachineWorkerCounts();
}
// live count of workers assigned to each machine
function updateMachineWorkerCounts(){
  document.querySelectorAll('.mc-workers').forEach(span=>{
    const mid=span.dataset.mid;
    const n=[...document.querySelectorAll('select[name=worker_machine]')].filter(s=>String(s.value)===String(mid)).length;
    span.textContent=n;
  });
}
document.addEventListener('change',e=>{if(e.target&&e.target.name==='worker_machine')updateMachineWorkerCounts();});
if(mbody){
  if(document.getElementById("addMachineBtn"))
    document.getElementById("addMachineBtn").addEventListener("click",()=>{
      const id=mAddSelect.value;if(!id)return;const m=MM.find(x=>String(x.id)===id);if(m)addMachineRow(m);});
  if(document.getElementById("addAllMachines"))
    document.getElementById("addAllMachines").addEventListener("click",()=>{
      const used=new Set([...mbody.querySelectorAll('input[name=machine_id]')].map(i=>i.value));
      MM.filter(m=>!used.has(String(m.id))).forEach(addMachineRow);});
  // initial: existing logs (edit) or auto-load all machines
  if(typeof existingMachines!=="undefined"&&existingMachines.length){existingMachines.forEach(addMachineRow);}
  else{MM.forEach(m=>addMachineRow(m));}
  rebuildMachineSelect();
}

// ---- Meter auto-derive ----
const su=document.getElementById("startUnit"),cu=document.getElementById("closeUnit"),cons=document.getElementById("consumption");
function dc(){const s=parseFloat(su.value),c=parseFloat(cu.value);if(!isNaN(s)&&!isNaN(c)&&c>=s&&!cons.dataset.touched){cons.value=+(c-s).toFixed(2);cons.classList.add("auto-field");}}
su.addEventListener("input",dc);cu.addEventListener("input",dc);
cons.addEventListener("input",()=>{cons.dataset.touched="1";cons.classList.remove("auto-field");});

// ---- Input weight + Waste = Input − Crushing output ----
const rawBuckets=document.getElementById("rawBuckets");
const bucketWeight=document.getElementById("bucketWeight");
const inputWeight=document.getElementById("inputWeight");
const wasteKg=document.getElementById("wasteKg");
wasteKg.addEventListener("input",()=>wasteKg.dataset.touched="1");
function recalcWaste(){
  const b=parseFloat(rawBuckets.value)||0, bw=parseFloat(bucketWeight.value)||0;
  const inp=b*bw;
  inputWeight.value=inp?+inp.toFixed(2):"";
  const crushing=window._crushingKg||0;
  if(inp>0 && !wasteKg.dataset.touched){
    const w=inp-crushing;
    wasteKg.value=+(w).toFixed(2);
  }
  // live yield & waste %
  const yh=document.getElementById("yieldHint");
  if(yh){
    if(inp>0){
      const y=(crushing/inp*100), wpct=((parseFloat(wasteKg.value)||0)/inp*100);
      yh.innerHTML=`Yield: <b>${y.toFixed(1)}%</b> &nbsp;·&nbsp; Waste: <b>${wpct.toFixed(1)}%</b>`;
      yh.style.display="block";
    }else{yh.style.display="none";}
  }
}
rawBuckets.addEventListener("input",recalcWaste);
bucketWeight.addEventListener("input",recalcWaste);
recalcTotals();  // triggers first waste calc too

// ---- live raw stock check on production form ----
(function(){
  const rmSel=document.getElementById("rawMatSelect");
  const buckets=document.getElementById("rawBuckets");
  const bw=document.getElementById("bucketWeight");
  const hint=document.getElementById("rawStockHint");
  if(!rmSel||!hint)return;
  let curStock=null,curName="";
  async function fetchStock(){
    const id=rmSel.value;if(!id)return;
    try{const r=await fetch(`/api/stock?type=raw&raw_id=${id}`);const j=await r.json();
      curStock=j.qty;curName=j.name;curThr=j.threshold||0;render();}catch(e){}
  }
  let curThr=0;
  function render(){
    if(curStock===null)return;
    const inp=(parseFloat(buckets.value)||0)*(parseFloat(bw.value)||0);
    if(inp<=0){hint.className="stock-hint ok";hint.textContent=`In stock: ${curStock} kg of ${curName}`;return;}
    if(inp>curStock){hint.className="stock-hint neg";
      hint.textContent=`⚠ Using ${inp.toFixed(0)} kg but only ${curStock} kg of ${curName} in stock — will go negative.`;}
    else if((curStock-inp)<=curThr && curThr>0){hint.className="stock-hint low";
      hint.textContent=`After this: ${(curStock-inp).toFixed(0)} kg left (low-stock threshold ${curThr}).`;}
    else{hint.className="stock-hint ok";
      hint.textContent=`In stock: ${curStock} kg · after this: ${(curStock-inp).toFixed(0)} kg.`;}
  }
  rmSel.addEventListener("change",fetchStock);
  buckets.addEventListener("input",render);
  bw.addEventListener("input",render);
  fetchStock();
})();