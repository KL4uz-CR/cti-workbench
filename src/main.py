import sys,re,subprocess,shutil,os,json,base64,urllib.request,urllib.error,urllib.parse,time
from pathlib import Path
from PySide6.QtCore import QThread,Signal,Qt,QPointF
from PySide6.QtWidgets import *
from PySide6.QtGui import QPen,QBrush,QColor,QPainter,QFont,QPainterPath,QKeySequence,QShortcut
from core import normalize_ioc, safe_dict, tls_context, get_logger
APP="CTI Workbench"; VERSION="0.5.7 rev 2"
logger=get_logger()
DARK="""QWidget{background:#0F172A;color:#F8FAFC;font-family:'Segoe UI';font-size:14px}QFrame#card,QFrame#mini{background:#1E293B;border:1px solid #334155;border-radius:10px}QLineEdit,QComboBox{background:#1E293B;color:#F8FAFC;border:1px solid #475569;border-radius:8px;padding:10px}QLineEdit:focus{border:2px solid #38BDF8}QPushButton{background:#38BDF8;color:#0F172A;border:0;border-radius:8px;padding:10px 18px;font-weight:700}QPushButton:hover{background:#7DD3FC}QPushButton:disabled{background:#334155;color:#94A3B8}QTextEdit{background:#0F172A;color:#F8FAFC;border:1px solid #334155;border-radius:8px;padding:8px;font-family:'Cascadia Mono','Consolas'}QLabel#title{color:#38BDF8;font-size:24px;font-weight:700}QLabel#section{color:#7DD3FC;font-weight:700}QLabel#muted{color:#CBD5E1}QTabWidget::pane{border:1px solid #334155}QTabBar::tab{background:#0F172A;color:#F8FAFC;padding:9px 16px;border:1px solid #334155}QTabBar::tab:selected{background:#1E293B;color:#38BDF8;font-weight:700}QToolTip{background:#1E293B;color:#F8FAFC;border:1px solid #38BDF8}"""
def typ(v):
 return normalize_ioc(v)[2]

def whois_state(data,text):
 fields=("Registrar","Registered","Expires","Last Changed","Nameservers","Status")
 if any(data.get(k,"—") not in ("—","") for k in fields): return "Available"
 # Only call it a lookup failure when the upstream output associates an error
 # with WHOIS/RDAP. Generic ThreatFox/URLhaus warnings must not affect WHOIS.
 for line in text.splitlines():
  if re.search(r"whois|rdap",line,re.I) and re.search(r"error|failed|timeout|unavailable|refused|certificate",line,re.I):
   return "Lookup failed"
 return "No data"

def fld(t,n):
 # Rich surrounds table rows with Unicode box-drawing characters (e.g. │).
 # Parse line-by-line, strip those borders, then split the requested label/value.
 for line in t.splitlines():
  line=line.strip().strip("│┃║").strip()
  m=re.match(rf"^{re.escape(n)}(?:/ASN)?\s+(.+?)\s*$",line,re.I)
  if m:
   return m.group(1).strip().strip("│┃║").strip()
 return "—"

def domain_data(t):
 # Parse iocinfo domain DNS/WHOIS tables. Continuation lines are appended
 # to the preceding multi-value field (NS, TXT, Nameservers, Status).
 keys=["A Records","MX Records","NS Records","TXT Records","Registrar",
       "Registered","Expires","Last Changed","Nameservers","Status"]
 data={k:"—" for k in keys}
 current=None
 for raw in t.splitlines():
  line=raw.strip().strip("│┃║").strip()
  if not line: continue
  found=False
  for k in keys:
   m=re.match(rf"^{re.escape(k)}\s+(.+?)\s*$",line,re.I)
   if m:
    data[k]=m.group(1).strip().strip("│┃║").strip()
    current=k
    found=True
    break
  if found: continue
  # Rich wraps long values onto continuation rows.
  if current in ("NS Records","TXT Records","Nameservers","Status"):
   # Never let provider warnings/errors bleed into wrapped DNS/WHOIS fields.
   boundary=bool(re.match(r"^[╭╰┌└├┬┴─━═]+",line) or re.search(r"(DNS Records|WHOIS|ThreatFox|URLhaus)",line,re.I))
   errorline=bool(re.search(r"(HTTP\s+\d{3}|unauthorized|forbidden|urlopen error|certificate[_ ]verify[_ ]failed|unable to get local issuer|\bfailed:|\berror:)",line,re.I))
   if not boundary and not errorline:
    data[current]=(data[current]+" "+line).strip()
 return data

def source_state(text,name):
 m=re.search(rf"(?mi){re.escape(name)}:\s*(.+)$",text)
 if not m: return "No data reported", False
 v=m.group(1).strip()
 if re.search(r"401|unauthorized",v,re.I): return "Authentication required", True
 if re.search(r"403|forbidden",v,re.I): return "Access forbidden", True
 if re.search(r"certificate|ssl|tls",v,re.I): return "TLS certificate validation failed", True
 if re.search(r"urlopen error|connection|timeout",v,re.I): return "Source unavailable", True
 if re.search(r"\b(error|failed)\b",v,re.I): return "Source error", True
 return v,False

def url_host(v):
 from urllib.parse import urlsplit
 try: return urlsplit(v).hostname or "—"
 except Exception: return "—"

def url_data(t):
 # iocinfo normalizes URLs to a host and may return DNS A records.
 host="—"; ips="—"
 m=re.search(r"(?mi)^\s*hxxps?://\S+\s+\(url\s*→\s*([^\)]+)\)",t)
 if m: host=m.group(1).strip()
 a=fld(t,"A Records")
 if a!="—": ips=a
 return host,ips
def vt_api_key():
 key=os.environ.get("VT_API_KEY","").strip()
 if key: return key
 cfg=Path(__file__).resolve().parent.parent/"config"/"virustotal.json"
 try:
  if cfg.exists(): return str(json.loads(cfg.read_text(encoding="utf-8")).get("api_key","")).strip()
 except Exception: pass
 return ""

def vt_lookup(ioc_type,value):
 """Read an existing VirusTotal report. Never submits/rescans an IOC."""
 key=vt_api_key()
 if not key: return {"status":"Not configured"}
 if ioc_type=="Domain": endpoint="domains/"+value
 elif ioc_type=="IP Address": endpoint="ip_addresses/"+value
 elif ioc_type=="Hash": endpoint="files/"+value
 elif ioc_type=="URL":
  ident=base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
  endpoint="urls/"+ident
 else: return {"status":"Unsupported IOC type"}
 req=urllib.request.Request("https://www.virustotal.com/api/v3/"+endpoint,headers={"x-apikey":key,"Accept":"application/json","User-Agent":"CTI-Workbench/0.5.7"})
 try:
  with urllib.request.urlopen(req,timeout=20) as r: payload=json.loads(r.read().decode("utf-8","replace"))
  data=safe_dict(payload.get("data",{}))
  attrs=safe_dict(data.get("attributes",{}))
  stats=safe_dict(attrs.get("last_analysis_stats",{}))
  return {"status":"Available","malicious":stats.get("malicious",0),"suspicious":stats.get("suspicious",0),"harmless":stats.get("harmless",0),"undetected":stats.get("undetected",0),"reputation":attrs.get("reputation","—"),"last_analysis_date":attrs.get("last_analysis_date"),"categories":attrs.get("categories",{})}
 except urllib.error.HTTPError as e:
  if e.code==404:return {"status":"No existing report"}
  if e.code in (401,403):return {"status":"Authentication/permission error"}
  if e.code==429:return {"status":"Rate limit reached"}
  return {"status":f"HTTP {e.code}"}
 except Exception as e:
  logger.warning("VirusTotal lookup failed for %s: %s",ioc_type,e)
  return {"status":"Source unavailable","detail":str(e)}

def vt_metrics(v):
 status=v.get("status","No data")
 if status!="Available": return None
 mal=int(v.get("malicious",0) or 0); sus=int(v.get("suspicious",0) or 0)
 harmless=int(v.get("harmless",0) or 0); und=int(v.get("undetected",0) or 0)
 detected=mal+sus; total=detected+harmless+und
 # VT4Browsers' documented visual thresholds: 0 green, 1-3 amber, >3 red.
 level="clear" if detected==0 else ("review" if detected<=3 else "warning")
 return detected,total,level,mal,sus,harmless,und

def vt_text(v):
 m=vt_metrics(v)
 if not m: return v.get("status","No data")
 detected,total,level,mal,sus,harmless,und=m
 label={"clear":"NO DETECTIONS","review":"REVIEW RECOMMENDED","warning":"MULTIPLE DETECTIONS"}[level]
 icon={"clear":"✓","review":"⚠","warning":"⚠"}[level]
 return (f"{icon}  {detected} / {total}  —  {label}\n"
         f"Vendor detections\n\n"
         f"Malicious: {mal} · Suspicious: {sus}\n"
         f"Harmless: {harmless} · Undetected: {und}\n"
         f"Community reputation: {v.get('reputation','—')}")

def vt_object_path(ioc_type,value):
 if ioc_type=="Domain": return "domains/"+value
 if ioc_type=="IP Address": return "ip_addresses/"+value
 if ioc_type=="Hash": return "files/"+value
 if ioc_type=="URL":
  ident=base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
  return "urls/"+ident
 return None

def vt_relationship_request(path,relationship,limit=10):
 key=vt_api_key()
 if not key: return {"status":"Not configured","items":[]}
 url=f"https://www.virustotal.com/api/v3/{path}/{relationship}?limit={limit}"
 req=urllib.request.Request(url,headers={"x-apikey":key,"Accept":"application/json","User-Agent":"CTI-Workbench/0.5.7"})
 try:
  with urllib.request.urlopen(req,timeout=20,context=tls_context()) as r:
   payload=json.loads(r.read().decode("utf-8","replace"))
  data=payload.get("data")
  if data is None: return {"status":"No data","items":[]}
  if not isinstance(data,list): data=[data]
  meta=safe_dict(payload.get("meta",{}))
  return {"status":"Available","items":data,"count":meta.get("count",len(data))}
 except urllib.error.HTTPError as e:
  if e.code==404:return {"status":"No data","items":[]}
  if e.code in (401,403):return {"status":"Permission unavailable","items":[]}
  if e.code==429:return {"status":"Rate limit reached","items":[]}
  return {"status":f"HTTP {e.code}","items":[]}
 except Exception as e:
  logger.warning("VirusTotal relationship lookup failed (%s): %s",relationship,e)
  return {"status":"Source unavailable","items":[],"detail":str(e)}

def related_indicator_rows(ioc_type,value):
 """Return evidence-backed VT relationships only; no inferred relationships."""
 path=vt_object_path(ioc_type,value)
 if not path:return [],["Unsupported input type"]
 plans={
  "Domain":["resolutions","subdomains","communicating_files"],
  "IP Address":["resolutions","communicating_files","referrer_files"],
  "Hash":["contacted_domains","contacted_ips","contacted_urls","dropped_files"],
  "URL":["network_location","last_serving_ip_address"],
 }
 rows=[]; notes=[]; seen=set()
 for rel in plans.get(ioc_type,[]):
  result=vt_relationship_request(path,rel,10)
  if result["status"] not in ("Available","No data"):
   notes.append(f"{rel}: {result['status']}")
  for obj in result.get("items",[]):
   if not isinstance(obj,dict):
    logger.warning("VT relationship %s returned non-object item; skipping",rel); continue
   typ0=obj.get("type",""); attrs=safe_dict(obj.get("attributes",{})); val=None; outtype=None
   if typ0=="resolution":
    # For a domain pivot, resolution yields IPs; for an IP pivot, it yields domains.
    if ioc_type=="Domain": val=attrs.get("ip_address"); outtype="IP Address"
    else: val=attrs.get("host_name"); outtype="Domain"
   elif typ0=="domain": val=obj.get("id"); outtype="Domain"
   elif typ0=="ip_address": val=obj.get("id"); outtype="IP Address"
   elif typ0=="file": val=obj.get("id"); outtype="Hash"
   elif typ0=="url": val=attrs.get("url") or obj.get("id"); outtype="URL"
   if val:
    key=(outtype,str(val),rel)
    if key not in seen:
     seen.add(key); rows.append({"type":outtype,"indicator":str(val),"relationship":rel,"source":"VirusTotal"})
 return rows,notes

class RelatedWorker(QThread):
 done=Signal(object,object,float)
 def __init__(self,t,v):super().__init__();self.t=t;self.v=v
 def run(self):
  started=time.perf_counter();rows,notes=related_indicator_rows(self.t,self.v);self.done.emit(rows,notes,time.perf_counter()-started)

def abusech_api_key():
 key=os.environ.get("ABUSECH_AUTH_KEY","").strip()
 if key: return key
 cfg=Path(__file__).resolve().parent.parent/"config"/"abusech.json"
 try:
  if cfg.exists(): return str(json.loads(cfg.read_text(encoding="utf-8")).get("auth_key","")).strip()
 except Exception: pass
 return ""

def post_form_json(url,data,key,timeout=20):
 body=urllib.parse.urlencode(data).encode("utf-8")
 req=urllib.request.Request(url,data=body,headers={"Auth-Key":key,"Accept":"application/json","User-Agent":"CTI-Workbench/0.5.7"},method="POST")
 with urllib.request.urlopen(req,timeout=timeout,context=tls_context()) as r:
  raw=r.read().decode("utf-8","replace")
  return json.loads(raw)

def post_json(url,data,key,timeout=20):
 # ThreatFox documents a JSON request body. Keep this separate from URLhaus,
 # whose lookup endpoints accept form-encoded fields.
 body=json.dumps(data).encode("utf-8")
 req=urllib.request.Request(url,data=body,headers={"Auth-Key":key,"Accept":"application/json","Content-Type":"application/json","User-Agent":"CTI-Workbench/0.5.7"},method="POST")
 with urllib.request.urlopen(req,timeout=timeout,context=tls_context()) as r:
  raw=r.read().decode("utf-8","replace")
  ctype=(r.headers.get("Content-Type") or "").lower()
  try:
   return json.loads(raw)
  except json.JSONDecodeError:
   raise RuntimeError(f"ThreatFox returned a non-JSON response (HTTP {getattr(r,'status','?')}, Content-Type: {ctype or 'unknown'})")

def threatfox_lookup(ioc_type,value):
 key=abusech_api_key()
 if not key:return {"status":"Not configured"}
 try:
  if ioc_type=="Hash": data={"query":"search_hash","hash":value}
  else:
   term=url_host(value) if ioc_type=="URL" else value
   data={"query":"search_ioc","search_term":term,"exact_match":True}
  payload=post_json("https://threatfox-api.abuse.ch/api/v1/",data,key)
  qs=str(payload.get("query_status",""))
  rows=payload.get("data") or []
  if qs in ("no_result","no_results") or not rows:return {"status":"No match"}
  if qs!="ok":return {"status":qs or "Source error"}
  r=rows[0] if isinstance(rows,list) else rows
  return {"status":"IOC FOUND","count":len(rows) if isinstance(rows,list) else 1,"malware":r.get("malware_printable") or r.get("malware") or "—","threat":r.get("threat_type_desc") or r.get("threat_type") or "—","confidence":r.get("confidence_level","—"),"first_seen":r.get("first_seen","—"),"last_seen":r.get("last_seen") or "—","ioc":r.get("ioc","—")}
 except urllib.error.HTTPError as e:
  if e.code in (401,403):return {"status":"Authentication error"}
  if e.code==429:return {"status":"Rate limit reached"}
  return {"status":f"HTTP {e.code}"}
 except Exception as e:
  logger.warning("ThreatFox lookup failed for %s: %s",ioc_type,e)
  return {"status":"Source error","detail":str(e)}

def urlhaus_lookup(ioc_type,value):
 key=abusech_api_key()
 if not key:return {"status":"Not configured"}
 try:
  if ioc_type=="URL": endpoint="https://urlhaus-api.abuse.ch/v1/url/"; data={"url":value}
  elif ioc_type in ("Domain","IP Address"):
   endpoint="https://urlhaus-api.abuse.ch/v1/host/"; data={"host":value}
  elif ioc_type=="Hash":
   endpoint="https://urlhaus-api.abuse.ch/v1/payload/"; data={"sha256_hash" if len(value)==64 else "md5_hash":value}
  else:return {"status":"Unsupported IOC type"}
  payload=post_form_json(endpoint,data,key)
  qs=str(payload.get("query_status",""))
  if qs in ("no_results","no_result"):return {"status":"No match"}
  if qs!="ok":return {"status":qs or "Source error"}
  urls=payload.get("urls") or []
  first=urls[0] if isinstance(urls,list) and urls else payload
  return {"status":"IOC FOUND","count":len(urls) if isinstance(urls,list) and urls else 1,"url_status":first.get("url_status",payload.get("url_status","—")),"threat":first.get("threat",payload.get("threat","—")),"tags":first.get("tags",payload.get("tags")) or [],"date_added":first.get("date_added",payload.get("date_added","—")),"url":first.get("url",payload.get("url","—"))}
 except urllib.error.HTTPError as e:
  if e.code in (401,403):return {"status":"Authentication error"}
  if e.code==429:return {"status":"Rate limit reached"}
  return {"status":f"HTTP {e.code}"}
 except Exception as e:
  logger.warning("URLhaus lookup failed for %s: %s",ioc_type,e)
  return {"status":"Source unavailable","detail":str(e)}

def tf_text(v):
 if v.get("status")!="IOC FOUND":return v.get("status","No data")
 return (f"⚠ IOC FOUND · {v.get('count',1)} match(es)\n"
         f"Malware: {v.get('malware','—')}\nThreat: {v.get('threat','—')}\n"
         f"Confidence: {v.get('confidence','—')}%\nFirst seen: {v.get('first_seen','—')}\nLast seen: {v.get('last_seen','—')}")

def uh_text(v):
 if v.get("status")!="IOC FOUND":return v.get("status","No data")
 tags=v.get("tags") or []
 if isinstance(tags,list): tags=", ".join(map(str,tags)) or "—"
 return (f"⚠ IOC FOUND · {v.get('count',1)} match(es)\n"
         f"Status: {v.get('url_status','—')}\nThreat: {v.get('threat','—')}\n"
         f"Tags: {tags}\nDate added: {v.get('date_added','—')}")

class W(QThread):
 done=Signal(str,int,object,object,object,object)
 progress=Signal(int,str)
 def __init__(self,x,t):super().__init__();self.x=x;self.t=t
 def run(self):
  timings={};overall=time.perf_counter()
  root=Path(__file__).resolve().parent.parent; p=root/".venv"/"Scripts"/"iocinfo.exe"; exe=str(p) if p.exists() else shutil.which("iocinfo")
  e=os.environ.copy();e.update(PYTHONUTF8="1",PYTHONIOENCODING="utf-8",NO_COLOR="1",TERM="dumb")
  raw=""; code=0;ioc_started=time.perf_counter()
  if not exe:
   raw=f"iocinfo not found.\nChecked: {p}"; code=127
   logger.error("iocinfo executable not found; checked %s",p)
  elif not Path(exe).is_file():
   raw=f"iocinfo path is not a file: {exe}"; code=127
   logger.error("iocinfo path is not a file: %s",exe)
  else:
   try:
    logger.info("Analysis started: type=%s indicator=%s",self.t,self.x)
    q=subprocess.run([exe,self.x],capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=90,env=e,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
    raw=((q.stdout or "")+("\n"+q.stderr if q.stderr else "")).strip(); code=q.returncode
    logger.info("iocinfo completed: returncode=%s",code)
   except subprocess.TimeoutExpired:
    raw="iocinfo timed out after 90 seconds"; code=124
    logger.warning("iocinfo timed out after 90 seconds")
   except Exception as z:
    raw=str(z); code=1
    logger.exception("iocinfo execution failed")
  timings["DNS / WHOIS"]=time.perf_counter()-ioc_started
  self.progress.emit(2,"Querying VirusTotal")
  started=time.perf_counter();vt=vt_lookup(self.t,self.x);timings["VirusTotal"]=time.perf_counter()-started
  self.progress.emit(3,"Querying ThreatFox")
  started=time.perf_counter();tf=threatfox_lookup(self.t,self.x);timings["ThreatFox"]=time.perf_counter()-started
  self.progress.emit(4,"Querying URLhaus")
  started=time.perf_counter();uh=urlhaus_lookup(self.t,self.x);timings["URLhaus"]=time.perf_counter()-started
  timings["Initial pipeline"]=time.perf_counter()-overall
  self.progress.emit(5,"Discovering related indicators")
  self.done.emit(raw,code,vt,tf,uh,timings)
class Card(QFrame):
 def __init__(self,n):
  super().__init__();self.setObjectName("mini");v=QVBoxLayout(self);self.h=QLabel(n.upper());self.h.setObjectName("section");v.addWidget(self.h);self.b=QLabel("Waiting for analysis");self.b.setWordWrap(True);v.addWidget(self.b)
 def set(self,x):self.b.setText(x)
 def reset_visual(self):
  self.setStyleSheet("");self.b.setStyleSheet("");self.h.setStyleSheet("")
 def set_vt(self,v,dark=True,display_text=None):
  self.reset_visual();self.h.setText("VIRUSTOTAL");self.b.setText(display_text if display_text is not None else vt_text(v))
  m=vt_metrics(v)
  if not m: return
  _,_,level,*_=m
  palette={
   "clear":("#22C55E","#052E16","#DCFCE7"),
   "review":("#F59E0B","#451A03","#FEF3C7"),
   "warning":("#EF4444","#450A0A","#FEE2E2")
  }
  accent,darkbg,lightbg=palette[level]; bg=darkbg if dark else lightbg
  fg="#F8FAFC" if dark else "#0F172A"
  self.setStyleSheet(f"QFrame#mini{{background:{bg};border:2px solid {accent};border-radius:10px}}")
  self.h.setStyleSheet(f"color:{accent};font-weight:800")
  self.b.setStyleSheet(f"color:{fg};font-size:15px;font-weight:650")
 def set_intel(self,name,v,text,dark=True):
  self.reset_visual(); self.h.setText(name.upper()); self.b.setText(text)
  status=v.get("status","No data")
  if status=="IOC FOUND":
   accent="#F59E0B"; bg="#451A03" if dark else "#FEF3C7"; fg="#F8FAFC" if dark else "#0F172A"
   self.setStyleSheet(f"QFrame#mini{{background:{bg};border:2px solid {accent};border-radius:10px}}")
   self.h.setStyleSheet(f"color:{accent};font-weight:800")
   self.b.setStyleSheet(f"color:{fg};font-size:15px;font-weight:650")
  elif status=="No match":
   accent="#22C55E"; bg="#052E16" if dark else "#DCFCE7"; fg="#F8FAFC" if dark else "#0F172A"
   self.setStyleSheet(f"QFrame#mini{{background:{bg};border:2px solid {accent};border-radius:10px}}")
   self.h.setStyleSheet(f"color:{accent};font-weight:800")
   self.b.setText("✓ NO MATCH")
   self.b.setStyleSheet(f"color:{fg};font-size:15px;font-weight:650")
  elif status in ("Authentication error","Rate limit reached","Source unavailable","Source error") or str(status).startswith("HTTP "):
   accent="#EF4444"; bg="#450A0A" if dark else "#FEE2E2"; fg="#F8FAFC" if dark else "#0F172A"
   self.setStyleSheet(f"QFrame#mini{{background:{bg};border:2px solid {accent};border-radius:10px}}")
   self.h.setStyleSheet(f"color:{accent};font-weight:800"); self.b.setStyleSheet(f"color:{fg};font-weight:650")
 def set_analysis(self,text,finding,dark=True):
  self.reset_visual(); self.h.setText("ANALYSIS STATE"); self.b.setText(text)
  accent="#EF4444" if finding else "#22C55E"
  bg=("#450A0A" if dark else "#FEE2E2") if finding else ("#052E16" if dark else "#DCFCE7")
  fg="#F8FAFC" if dark else "#0F172A"
  self.setStyleSheet(f"QFrame#mini{{background:{bg};border:2px solid {accent};border-radius:10px}}")
  self.h.setStyleSheet(f"color:{accent};font-weight:800")
  self.b.setStyleSheet(f"color:{fg};font-size:15px;font-weight:650")

class GraphView(QGraphicsView):
 def __init__(self,analyze_cb):
  super().__init__(); self.analyze_cb=analyze_cb; self.scene_=QGraphicsScene(self); self.setScene(self.scene_); self.setRenderHint(QPainter.Antialiasing); self.setMinimumHeight(420); self.setDragMode(QGraphicsView.ScrollHandDrag); self.nodes={}
 def _tag(self,item,label,kind):
  item.setData(0,label); item.setData(1,kind); item.setToolTip(f"{kind}: {label}\nDouble-click to analyze"); self.nodes[item]=label; return item
 def _icon(self,pos,label,kind,color,central=False):
  x,y=pos.x(),pos.y(); pen=QPen(color,2.4 if central else 1.4); pen.setCapStyle(Qt.RoundCap); pen.setJoinStyle(Qt.RoundJoin); brush=QBrush(QColor(color.red(),color.green(),color.blue(),38))
  items=[]
  if central:
   # Target/indicator: diamond with a small crosshair, no enclosing node circle.
   p=QPainterPath(); p.moveTo(x,y-18); p.lineTo(x+18,y); p.lineTo(x,y+18); p.lineTo(x-18,y); p.closeSubpath()
   items.append(self.scene_.addPath(p,pen,brush)); items.append(self.scene_.addLine(x-7,y,x+7,y,pen)); items.append(self.scene_.addLine(x,y-7,x,y+7,pen))
  elif kind=="IP Address":
   # Host/network endpoint: monitor + stand.
   p=QPainterPath(); p.addRoundedRect(x-11,y-9,22,15,3,3); items.append(self.scene_.addPath(p,pen,brush)); items.append(self.scene_.addLine(x,y+6,x,y+10,pen)); items.append(self.scene_.addLine(x-6,y+10,x+6,y+10,pen))
  elif kind=="Domain":
   # Globe glyph without a surrounding badge.
   items.append(self.scene_.addEllipse(x-10,y-10,20,20,pen,QBrush(Qt.NoBrush))); items.append(self.scene_.addLine(x-10,y,x+10,y,pen)); items.append(self.scene_.addLine(x,y-10,x,y+10,pen)); items.append(self.scene_.addEllipse(x-5,y-10,10,20,pen,QBrush(Qt.NoBrush)))
  elif kind=="URL":
   # Chain-link glyph.
   p1=QPainterPath(); p1.moveTo(x-10,y+4); p1.cubicTo(x-14,y,x-9,y-8,x-4,y-8); p1.lineTo(x+1,y-8); p1.cubicTo(x+5,y-8,x+6,y-4,x+4,y-1)
   p2=QPainterPath(); p2.moveTo(x+10,y-4); p2.cubicTo(x+14,y,x+9,y+8,x+4,y+8); p2.lineTo(x-1,y+8); p2.cubicTo(x-5,y+8,x-6,y+4,x-4,y+1)
   items.append(self.scene_.addPath(p1,pen)); items.append(self.scene_.addPath(p2,pen)); items.append(self.scene_.addLine(x-5,y+5,x+5,y-5,pen))
  elif kind=="Hash":
   # Hash/fingerprint-like identifier mark.
   for dx in (-4,4): items.append(self.scene_.addLine(x+dx-2,y-10,x+dx+2,y+10,pen))
   for dy in (-4,4): items.append(self.scene_.addLine(x-10,y+dy+2,x+10,y+dy-2,pen))
  else:
   # Generic evidence node: hexagon.
   p=QPainterPath(); pts=[(0,-11),(9,-5),(9,5),(0,11),(-9,5),(-9,-5)]; p.moveTo(x+pts[0][0],y+pts[0][1]);
   for px,py in pts[1:]: p.lineTo(x+px,y+py)
   p.closeSubpath(); items.append(self.scene_.addPath(p,pen,brush))
  for item in items:self._tag(item,label,kind)
 def render_graph(self,center,center_type,rows,dark=True):
  import math
  self.scene_.clear(); self.nodes={}
  bg=QColor("#0F172A" if dark else "#F4F8FB"); fg=QColor("#F8FAFC" if dark else "#0F172A"); muted=QColor("#94A3B8" if dark else "#64748B")
  self.setBackgroundBrush(QBrush(bg))
  unique=[]; seen=set()
  for r in rows:
   k=(r.get("type"),r.get("indicator"),r.get("relationship"))
   if r.get("indicator")==center or k in seen: continue
   seen.add(k); unique.append(r)
  unique=unique[:24]
  radius=260; cx=0; cy=0; positions=[]; n=max(1,len(unique))
  for idx,r in enumerate(unique):
   a=(2*math.pi*idx/n)-math.pi/2; positions.append(QPointF(cx+radius*math.cos(a),cy+radius*math.sin(a)))
  edgepen=QPen(QColor("#475569" if dark else "#94A3B8"),1.35)
  for pos,r in zip(positions,unique):
   self.scene_.addLine(cx,cy,pos.x(),pos.y(),edgepen)
   mid=QPointF((cx+pos.x())/2,(cy+pos.y())/2); lab=self.scene_.addText(r.get("relationship","related"),QFont("Segoe UI",8)); lab.setDefaultTextColor(muted); lab.setPos(mid.x()-lab.boundingRect().width()/2,mid.y()-lab.boundingRect().height()/2)
  colors={"Domain":"#38BDF8","IP Address":"#22C55E","URL":"#A78BFA","Hash":"#F59E0B"}
  def add_node(pos,label,kind,central=False):
   color=QColor("#EF4444" if central else colors.get(kind,"#7DD3FC")); self._icon(pos,label,kind,color,central)
   shown=label if len(label)<=32 else label[:29]+"…"; t=self.scene_.addText(shown,QFont("Segoe UI",9,QFont.Bold if central else QFont.Normal)); t.setDefaultTextColor(fg); t.setPos(pos.x()-t.boundingRect().width()/2,pos.y()+(25 if central else 16)); self._tag(t,label,kind)
  add_node(QPointF(cx,cy),center,center_type,True)
  for pos,r in zip(positions,unique): add_node(pos,r.get("indicator",""),r.get("type","Unknown"),False)
  self.scene_.setSceneRect(self.scene_.itemsBoundingRect().adjusted(-70,-70,70,70)); self.fitInView(self.scene_.sceneRect(),Qt.KeepAspectRatio)
 def mouseDoubleClickEvent(self,event):
  item=self.itemAt(event.position().toPoint())
  while item is not None:
   val=item.data(0)
   if val:
    self.analyze_cb(str(val)); return
   item=item.parentItem()
  super().mouseDoubleClickEvent(event)
 def resizeEvent(self,event):
  super().resizeEvent(event)
  if not self.scene_.itemsBoundingRect().isNull(): self.fitInView(self.scene_.sceneRect(),Qt.KeepAspectRatio)

class AnalysisProgress(QDialog):
 STAGES=["DNS / WHOIS enrichment","VirusTotal","ThreatFox","URLhaus","Related indicators","Intelligence graph","Complete"]
 def __init__(self,parent,ioc):
  super().__init__(parent);self.setWindowTitle("Analysis Progress");self.setModal(True);self.setWindowFlag(Qt.WindowContextHelpButtonHint,False);self.setFixedWidth(500)
  self.setStyleSheet("QDialog{background:#0B1220;border:1px solid #334155} QLabel{background:transparent;color:#F8FAFC}")
  v=QVBoxLayout(self);v.setContentsMargins(28,24,28,24);v.setSpacing(9)
  self.title=QLabel("ANALYZING IOC");self.title.setAlignment(Qt.AlignCenter);self.title.setStyleSheet("font-size:18px;font-weight:800;letter-spacing:1px;color:#F8FAFC");v.addWidget(self.title)
  self.ioc=QLabel(ioc);self.ioc.setAlignment(Qt.AlignCenter);self.ioc.setWordWrap(True);self.ioc.setStyleSheet("color:#94A3B8;margin-bottom:8px");v.addWidget(self.ioc)
  self.rows=[]
  for name in self.STAGES:
   row=QLabel(f"○  {name}");row.setStyleSheet("color:#64748B;font-size:14px;padding:2px 8px");v.addWidget(row);self.rows.append(row)
  self.stage=QLabel("Starting analysis…");self.stage.setAlignment(Qt.AlignCenter);self.stage.setStyleSheet("color:#7DD3FC;font-weight:650;margin-top:8px");v.addWidget(self.stage)
  self.completed=0;self.update_stage(1,"Resolving DNS / WHOIS enrichment")
 def update_stage(self,completed,current):
  completed=max(1,min(7,int(completed)));self.completed=completed;self.stage.setText(current)
  for idx,(name,row) in enumerate(zip(self.STAGES,self.rows),start=1):
   if completed>=7 or idx<completed:
    row.setText(f"✓  {name}");row.setStyleSheet("color:#22C55E;font-size:14px;font-weight:650;padding:2px 8px")
   elif idx==completed:
    row.setText(f"●  {name}");row.setStyleSheet("color:#38BDF8;font-size:14px;font-weight:700;padding:2px 8px")
   else:
    row.setText(f"○  {name}");row.setStyleSheet("color:#64748B;font-size:14px;padding:2px 8px")
 def complete(self):
  self.update_stage(7,"Analysis complete");self.accept()
 def reject(self):
  if self.completed>=7:super().reject()

class Win(QMainWindow):
 def __init__(self):
  super().__init__();self.setWindowTitle(f"{APP} v{VERSION}");self.resize(1120,760);c=QWidget();self.setCentralWidget(c);o=QVBoxLayout(c)
  top=QHBoxLayout();box=QVBoxLayout();a=QLabel(APP);a.setObjectName("title");box.addWidget(a);b=QLabel("Evidence-first IOC enrichment for Windows");b.setObjectName("muted");box.addWidget(b);top.addLayout(box);top.addStretch();o.addLayout(top)
  f=QFrame();f.setObjectName("card");v=QVBoxLayout(f);h=QLabel("ADDRESS / INDICATOR ANALYSIS");h.setObjectName("section");v.addWidget(h);r=QHBoxLayout();self.i=QLineEdit();self.i.setClearButtonEnabled(True);self.i.setPlaceholderText("Enter an IP address, IP:port, domain, URL, MD5, SHA-1 or SHA-256");self.bt=QPushButton("Analyze");self.bt.clicked.connect(self.go);self.i.returnPressed.connect(self.go);r.addWidget(self.i,1);r.addWidget(self.bt);v.addLayout(r);self.st=QLabel("Supported inputs: IP address · IP:port · Domain · URL · MD5 · SHA-1 · SHA-256");self.st.setObjectName("muted");v.addWidget(self.st);o.addWidget(f)
  self.tabs=QTabWidget();o.addWidget(self.tabs,1);ov=QWidget();x=QVBoxLayout(ov);x.setSpacing(10)
  self.id=Card("ANALYZED INDICATOR");x.addWidget(self.id)
  self.cards=[Card(n) for n in ["Geolocation","Network / RDAP","DNS","VirusTotal","ThreatFox","URLhaus","Analysis state"]]
  x.addWidget(self.cards[6])
  src_label=QLabel("INTELLIGENCE SOURCES");src_label.setObjectName("section");x.addWidget(src_label)
  sg=QGridLayout();sg.setHorizontalSpacing(10)
  for col,idx in enumerate((3,4,5)):sg.addWidget(self.cards[idx],0,col)
  x.addLayout(sg)
  ctx_label=QLabel("CONTEXT");ctx_label.setObjectName("section");x.addWidget(ctx_label)
  cg=QGridLayout();cg.setHorizontalSpacing(10)
  for col,idx in enumerate((0,1,2)):cg.addWidget(self.cards[idx],0,col)
  x.addLayout(cg)
  self.timing_info=QLabel("Source timing will appear after analysis.");self.timing_info.setObjectName("muted");x.addWidget(self.timing_info)
  x.addStretch();self.tabs.addTab(ov,"Overview")
  graph=QWidget();gl=QVBoxLayout(graph);gh=QHBoxLayout();self.graph_info=QLabel("Analyze an indicator. VirusTotal relationships and the graph load automatically.");self.graph_info.setObjectName("muted");gh.addWidget(self.graph_info,1);gl.addLayout(gh);self.graph=GraphView(self.graph_analyze);gl.addWidget(self.graph,1);hint=QLabel("Node icons: target · Domain · IP Address · URL · Hash   |   Colors reinforce type · Double-click an icon to analyze it");hint.setObjectName("muted");gl.addWidget(hint);self.tabs.addTab(graph,"Intelligence Graph")
  rel=QWidget();rl=QVBoxLayout(rel)
  rh=QHBoxLayout();self.rel_info=QLabel("Analyze an indicator. VirusTotal relationships load automatically.");self.rel_info.setObjectName("muted");rh.addWidget(self.rel_info,1);rl.addLayout(rh)
  self.rel_table=QTableWidget(0,4);self.rel_table.setHorizontalHeaderLabels(["Type","Indicator","Relationship","Source"]);self.rel_table.setSelectionBehavior(QAbstractItemView.SelectRows);self.rel_table.setSelectionMode(QAbstractItemView.SingleSelection);self.rel_table.setEditTriggers(QAbstractItemView.NoEditTriggers);self.rel_table.horizontalHeader().setStretchLastSection(True);self.rel_table.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch);rl.addWidget(self.rel_table,1)
  rb=QHBoxLayout();self.rel_analyze=QPushButton("Analyze Selected");self.rel_copy=QPushButton("Copy");self.rel_copyall=QPushButton("Copy All");self.rel_export=QPushButton("Export CSV");
  self.rel_analyze.clicked.connect(self.analyze_selected);self.rel_copy.clicked.connect(self.copy_selected);self.rel_copyall.clicked.connect(self.copy_all_related);self.rel_export.clicked.connect(self.export_related)
  for zbtn in (self.rel_analyze,self.rel_copy,self.rel_copyall,self.rel_export):rb.addWidget(zbtn)
  rb.addStretch();rl.addLayout(rb);self.tabs.addTab(rel,"Related Indicators")
  rw=QWidget();rv=QVBoxLayout(rw);self.raw=QTextEdit();self.raw.setReadOnly(True);self.raw.setPlainText("Raw upstream evidence will appear here.");rv.addWidget(self.raw);self.tabs.addTab(rw,"Raw Data");self.current_ioc=None;self.current_type=None;self.related_cache=[];self.progress_dialog=None;self.timings={};QApplication.instance().setStyleSheet(DARK)
  self.shortcut_focus=QShortcut(QKeySequence("Ctrl+L"),self);self.shortcut_focus.activated.connect(self.focus_ioc)
  self.shortcut_copy=QShortcut(QKeySequence("Ctrl+C"),self);self.shortcut_copy.activated.connect(self.copy_current_ioc)
  self.shortcut_export=QShortcut(QKeySequence("Ctrl+E"),self);self.shortcut_export.activated.connect(self.export_related)
  self.bt.setToolTip("Analyze indicator (Enter)");self.i.setToolTip("Indicator input (Ctrl+L)");self.rel_export.setToolTip("Export related indicators (Ctrl+E)")
 def go(self):
  entered=self.i.text().strip();original,z,t=normalize_ioc(entered)
  if not entered or t=="Unknown":QMessageBox.warning(self,APP,"Enter a valid IOC.");return
  self.current_ioc=z;self.current_type=t;self.related_cache=[];self.timings={};self.timing_info.setText("Measuring source response times…");self.rel_table.setRowCount(0);self.rel_info.setText("Analysis in progress. Related indicators will load automatically.");self.graph_info.setText("Analysis in progress. Intelligence graph will load automatically.");self.graph.scene_.clear()
  self.bt.setEnabled(False);self.bt.setText("Analyzing…");self.progress_dialog=AnalysisProgress(self,z);self.progress_dialog.update_stage(1,"Resolving DNS / WHOIS enrichment");self.progress_dialog.show()
  self.w=W(z,t);self.w.progress.connect(self.progress_update);self.w.done.connect(lambda a,b,c,d,e,f:self.done(original,z,t,a,b,c,d,e,f));self.w.start()
 def done(self,original,z,t,s,code,vt,tfv,uhv,timings):
  self.timings=dict(timings or {});self.raw.setPlainText(s);self.rel_info.setText("Loading VirusTotal relationships…");self.graph_info.setText("Loading evidence-backed VirusTotal relationship graph…");self.progress_update(5,"Discovering related indicators")
  tf=tf_text(tfv); uh=uh_text(uhv)
  vt_display=vt_text(vt)+f"\n\nResponse: {self.timings.get('VirusTotal',0):.2f} s"
  tf=tf+f"\n\nResponse: {self.timings.get('ThreatFox',0):.2f} s"
  uh=uh+f"\n\nResponse: {self.timings.get('URLhaus',0):.2f} s"
  tf_bad=tfv.get("status") in ("Authentication error","Rate limit reached","Source unavailable") or str(tfv.get("status","")).startswith("HTTP ")
  uh_bad=uhv.get("status") in ("Authentication error","Rate limit reached","Source unavailable") or str(uhv.get("status","")).startswith("HTTP ")
  warnings=sum([tf_bad,uh_bad])
  final=("Completed" if not warnings else f"Completed with {warnings} source warning" + ("" if warnings==1 else "s"))
  if code!=0: final+=f" · upstream exit code {code}"
  for c in self.cards: c.reset_visual()
  vm=vt_metrics(vt)
  vt_status=vt.get('status','No data')
  if vm:
   detected,total,level,*_=vm
   if level=="clear": vt_status=f"✓ VirusTotal: {detected}/{total} detections"
   elif level=="review": vt_status=f"⚠ VirusTotal: {detected}/{total} detections · REVIEW"
   else: vt_status=f"⚠ VirusTotal: {detected}/{total} detections · WARNING"
  else: vt_status=f"VirusTotal: {vt_status}"
  intel=[]
  if tfv.get("status")=="IOC FOUND": intel.append("⚠ ThreatFox match")
  if uhv.get("status")=="IOC FOUND": intel.append("⚠ URLhaus match")
  # Keep the input area instructional. Operational results belong in Analysis State.
  summary = final + " · " + vt_status + ((" · "+" · ".join(intel)) if intel else "")
  finding = (vm is not None and vm[0] > 0) or tfv.get("status")=="IOC FOUND" or uhv.get("status")=="IOC FOUND"
  headline = "⚠ THREAT INTELLIGENCE FOUND" if finding else "✓ NO THREAT INTELLIGENCE FOUND"
  analysis_text = headline + "\n" + summary
  if t=="Domain":
   d=domain_data(s); ws=whois_state(d,s)
   identity=f"Original IOC: {original}\nNormalized: {z}" if original!=z else z
   self.id.set(f"{identity}\nType: Domain\nRegistrar: {d['Registrar']}\nRegistered: {d['Registered']}\nExpires: {d['Expires']}")
   self.cards[0].set(f"A: {d['A Records']}\nMX: {d['MX Records']}")
   self.cards[0].findChild(QLabel).setText("DNS RECORDS")
   self.cards[1].set(f"NS: {d['NS Records']}\nTXT: {d['TXT Records']}")
   self.cards[1].findChild(QLabel).setText("DNS DETAILS")
   self.cards[2].set(f"Status: {ws}\nRegistrar: {d['Registrar']}\nRegistered: {d['Registered']}\nExpires: {d['Expires']}\nLast Changed: {d['Last Changed']}")
   self.cards[2].findChild(QLabel).setText("WHOIS")
   self.cards[3].set_vt(vt,True,vt_display)
   self.cards[4].set_intel("ThreatFox",tfv,tf,True)
   self.cards[5].set_intel("URLhaus",uhv,uh,True)
   self.cards[6].set_analysis(analysis_text,finding,True)
  elif t=="URL":
   host,ips=url_data(s)
   if host=="—": host=url_host(z)
   identity=f"Original IOC: {original}\nNormalized: {z}" if original!=z else z
   self.id.set(f"{identity}\nType: URL\nHost: {host}\nResolved IP(s): {ips}")
   self.cards[0].findChild(QLabel).setText("URL TARGET")
   self.cards[0].set(f"Host: {host}\nScheme: {z.split(':',1)[0].upper() if ':' in z else '—'}")
   self.cards[1].findChild(QLabel).setText("DNS RESOLUTION")
   self.cards[1].set(f"A: {ips}")
   self.cards[2].findChild(QLabel).setText("UPSTREAM EVIDENCE")
   self.cards[2].set("See Raw Data for complete iocinfo evidence")
   self.cards[3].set_vt(vt,True,vt_display)
   self.cards[4].set_intel("ThreatFox",tfv,tf,True)
   self.cards[5].set_intel("URLhaus",uhv,uh,True)
   self.cards[6].set_analysis(analysis_text,finding,True)
  else:
   identity=f"Original IOC: {original}\nNormalized: {z}" if original!=z else z
   self.id.set(f"{identity}\nType: {t}\nOrganization: {fld(s,'Org')}\nASN: {fld(s,'ASN')}")
   self.cards[0].findChild(QLabel).setText("GEOLOCATION")
   self.cards[0].set(f"Location: {fld(s,'Location')}\nISP: {fld(s,'ISP')}\nFlags: {fld(s,'Flags')}")
   self.cards[1].findChild(QLabel).setText("NETWORK / RDAP")
   self.cards[1].set(f"Network: {fld(s,'Network')}\nCIDR: {fld(s,'CIDR')}\nRegistered: {fld(s,'Registered')}")
   self.cards[2].findChild(QLabel).setText("DNS")
   self.cards[2].set(f"Hostname: {fld(s,'Hostname')}")
   self.cards[3].set_vt(vt,True,vt_display)
   self.cards[4].set_intel("ThreatFox",tfv,tf,True)
   self.cards[5].set_intel("URLhaus",uhv,uh,True)
   self.cards[6].set_analysis(analysis_text,finding,True)

  # v0.5.3: one automatic relationship query feeds both the table and static graph.
  if vt.get("status") in ("Available","No existing report"):
   self.auto_rel=RelatedWorker(self.current_type,self.current_ioc);self.auto_rel.done.connect(self.auto_related_done);self.auto_rel.start()
  else:
   self.rel_info.setText("Related indicators unavailable: VirusTotal report is not available for relationship discovery.")
   self.graph_info.setText("Intelligence graph unavailable: no VirusTotal relationships were queried.")
   total=sum(self.timings.get(k,0) for k in ("DNS / WHOIS","VirusTotal","ThreatFox","URLhaus"))
   self.timing_info.setText("  ·  ".join([f"{k}: {self.timings[k]:.2f} s" for k in ("DNS / WHOIS","VirusTotal","ThreatFox","URLhaus") if k in self.timings])+f"  ·  Total: {total:.2f} s")
   self.finish_progress("Analysis complete — no relationship graph available")

 def progress_update(self,completed,current):
  if self.progress_dialog:self.progress_dialog.update_stage(completed,current)
 def finish_progress(self,message="Analysis complete"):
  self.bt.setEnabled(True);self.bt.setText("Analyze")
  if self.progress_dialog:
   self.progress_dialog.update_stage(7,message);self.progress_dialog.accept();self.progress_dialog=None

 def auto_related_done(self,rows,notes,elapsed=0.0):
  # Ignore stale results if the analyst started another IOC while this query was running.
  self.timings["Related indicators"]=elapsed;self.related_cache=rows;self.rel_table.setRowCount(0)
  filtered=[]
  for row in rows:
   if row.get("indicator")==self.current_ioc: continue
   filtered.append(row);n=self.rel_table.rowCount();self.rel_table.insertRow(n)
   for col,key in enumerate(("type","indicator","relationship","source")):self.rel_table.setItem(n,col,QTableWidgetItem(row[key]))
  msg=f"{len(filtered)} related indicator(s) returned by VirusTotal."
  if notes:msg+="  " + " · ".join(notes)
  self.rel_info.setText(msg)
  self.progress_update(6,"Building intelligence graph")
  graph_started=time.perf_counter();self.graph.render_graph(self.current_ioc,self.current_type,filtered,True);self.timings["Intelligence graph"]=time.perf_counter()-graph_started
  gmsg=f"{len(filtered)} related indicator(s) visualized from VirusTotal."
  if notes:gmsg+="  " + " · ".join(notes)
  self.graph_info.setText(gmsg)
  total=sum(self.timings.get(k,0) for k in ("DNS / WHOIS","VirusTotal","ThreatFox","URLhaus","Related indicators","Intelligence graph"))
  self.timing_info.setText("  ·  ".join([f"{k}: {self.timings[k]:.2f} s" for k in ("DNS / WHOIS","VirusTotal","ThreatFox","URLhaus","Related indicators","Intelligence graph") if k in self.timings])+f"  ·  Total: {total:.2f} s")
  self.finish_progress("Analysis complete")

 def load_related(self):
  if not self.current_ioc or not self.current_type:return
  self.rel_info.setText("Loading VirusTotal relationships…")
  self.auto_rel=RelatedWorker(self.current_type,self.current_ioc);self.auto_rel.done.connect(self.auto_related_done);self.auto_rel.start()
 def related_done(self,rows,notes,elapsed=0.0):
  self.auto_related_done(rows,notes,elapsed)
 def load_graph(self):
  if self.related_cache:self.graph.render_graph(self.current_ioc,self.current_type,self.related_cache,True)
 def graph_done(self,rows,notes,elapsed=0.0):
  self.auto_related_done(rows,notes,elapsed)
 def graph_analyze(self,value):
  if not value:return
  self.i.setText(value);self.tabs.setCurrentIndex(0);self.go()
 def focus_ioc(self):
  self.i.setFocus();self.i.selectAll()
 def copy_current_ioc(self):
  if self.current_ioc:QApplication.clipboard().setText(self.current_ioc)

 def selected_indicator(self):
  r=self.rel_table.currentRow()
  if r<0:return None
  return self.rel_table.item(r,1).text()
 def analyze_selected(self):
  v=self.selected_indicator()
  if not v:return
  self.i.setText(v);self.tabs.setCurrentIndex(0);self.go()
 def copy_selected(self):
  v=self.selected_indicator()
  if v:QApplication.clipboard().setText(v)
 def copy_all_related(self):
  vals=[]
  for r in range(self.rel_table.rowCount()):vals.append(self.rel_table.item(r,1).text())
  if vals:QApplication.clipboard().setText("\n".join(vals))
 def export_related(self):
  if not self.rel_table.rowCount():return
  path,_=QFileDialog.getSaveFileName(self,"Export Related Indicators","related-indicators.csv","CSV files (*.csv)")
  if not path:return
  import csv
  with open(path,"w",newline="",encoding="utf-8-sig") as f:
   w=csv.writer(f);w.writerow(["Type","Indicator","Relationship","Source"])
   for r in range(self.rel_table.rowCount()):w.writerow([self.rel_table.item(r,c).text() for c in range(4)])

if __name__=="__main__":
 app=QApplication(sys.argv);w=Win();w.showMaximized();sys.exit(app.exec())
