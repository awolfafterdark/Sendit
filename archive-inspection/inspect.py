#!/usr/bin/env python3
"""Read-only ZIP/IPA inspection. Never executes archive contents."""
import collections, hashlib, io, json, os, pathlib, plistlib, re, struct, sys, urllib.request, zipfile

REPORT = []
OUTPUT_BYTES = 0
def emit(kind, value):
    global OUTPUT_BYTES
    line = kind + " " + json.dumps(value, ensure_ascii=True, default=str)
    if OUTPUT_BYTES + len(line) > 400000:
        return
    OUTPUT_BYTES += len(line)
    REPORT.append(line)
    print(line, flush=True)

def macho(data):
    result = []
    magic = data[:4]
    slices = [(0, len(data))]
    if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"):
        endian = ">" if magic[:1] == b"\xca" else "<"
        wide = magic in (b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
        count = struct.unpack_from(endian + "I", data, 4)[0]
        if count > 32: return [{"error":"invalid fat architecture count"}]
        slices = []
        for i in range(count):
            pos = 8 + i * (32 if wide else 20)
            off, size = struct.unpack_from(endian + ("QQ" if wide else "II"), data, pos+8)
            slices.append((off, size))
    for base, size in slices:
        if base + 28 > len(data): continue
        m = data[base:base+4]
        if m not in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"): continue
        endian = "<" if m[:1] in (b"\xce", b"\xcf") else ">"
        wide = m in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
        _, cpu, sub, typ, ncmd, cmdbytes, flags = struct.unpack_from(endian+"7I", data, base)
        record = {"cpu":hex(cpu),"cpu_subtype":sub,"filetype":typ,"is_64bit":wide,"cryptids":[],"dylibs":[],"rpaths":[]}
        pos = base + (32 if wide else 28)
        end = min(len(data), base + size, pos + cmdbytes)
        if ncmd > 10000: continue
        for i in range(ncmd):
            if pos+8 > end: break
            cmd, length = struct.unpack_from(endian+"II",data,pos)
            if length < 8 or pos+length > end: break
            if cmd in (0x21,0x2c) and length >= 20:
                record["cryptids"].append(struct.unpack_from(endian+"I",data,pos+16)[0])
            if cmd in (0xc,0x80000018,0x8000001f,0x80000023,0x20) and length >= 24:
                offset=struct.unpack_from(endian+"I",data,pos+8)[0]
                if 0 <= offset < length:
                    record["dylibs"].append(data[pos+offset:pos+length].split(b"\0")[0].decode("utf-8","replace"))
            if cmd == 0x8000001c and length >= 12:
                offset=struct.unpack_from(endian+"I",data,pos+8)[0]
                if 0 <= offset < length:
                    record["rpaths"].append(data[pos+offset:pos+length].split(b"\0")[0].decode("utf-8","replace"))
            if cmd == 0x1d and length >= 16:
                sigoff, siglen=struct.unpack_from(endian+"II",data,pos+8)
                sig=data[base+sigoff:base+sigoff+siglen]
                record["code_signature_bytes"]=siglen
                if len(sig)>=12 and sig[:4] == b"\xfa\xde\x0c\xc0":
                    count=struct.unpack_from(">I",sig,8)[0]
                    for j in range(min(count,128)):
                        if 12+j*8+8 > len(sig): break
                        slot, offset=struct.unpack_from(">II",sig,12+j*8)
                        if offset+8 > len(sig): continue
                        blobmagic,bloblen=struct.unpack_from(">II",sig,offset)
                        if blobmagic==0xfade7171 and offset+bloblen<=len(sig):
                            try: record["entitlements"]=plistlib.loads(sig[offset+8:offset+bloblen])
                            except Exception: record["entitlements_error"]="unparseable XML entitlement blob"
            if cmd==0x32 and length>=24:
                platform,minimum,sdk=struct.unpack_from(endian+"III",data,pos+8)
                fmt=lambda v: "%d.%d.%d"%((v>>16)&65535,(v>>8)&255,v&255)
                record["build_version"]={"platform":platform,"minimum":fmt(minimum),"sdk":fmt(sdk)}
            pos += length
        result.append(record)
    return result

PLIST_KEYS = (
"CFBundleIdentifier","CFBundleName","CFBundleDisplayName","CFBundleExecutable",
"CFBundleShortVersionString","CFBundleVersion","MinimumOSVersion","UIDeviceFamily",
"UIFileSharingEnabled","LSSupportsOpeningDocumentsInPlace","UISupportsDocumentBrowser",
"CFBundleDocumentTypes","UTImportedTypeDeclarations","UTExportedTypeDeclarations",
"NSUbiquitousContainers","NSExtension","LSRequiresIPhoneOS","UIRequiredDeviceCapabilities",
"CFBundleURLTypes","NSPhotoLibraryUsageDescription","NSPhotoLibraryAddUsageDescription"
)
NESTED_COUNT=0
TEXT_COUNT=0
BINARY_COUNT=0
TOTAL_READ=0
def read_limited(z, info, cap):
    global TOTAL_READ
    if info.file_size > cap or TOTAL_READ + info.file_size > 1500*1024*1024:
        raise ValueError("inspection byte budget exceeded")
    with z.open(info) as f:
        data=f.read(cap+1)
    if len(data)>cap: raise ValueError("entry exceeded read limit")
    TOTAL_READ+=len(data)
    return data

def inspect_zip(source, label, depth=0):
    global NESTED_COUNT,TEXT_COUNT,BINARY_COUNT
    with zipfile.ZipFile(source) as z:
        entries=z.infolist()
        files=[x for x in entries if not x.is_dir() and not x.filename.startswith("__MACOSX/")]
        emit("ARCHIVE",{"name":label,"entries":len(entries),"file_count":len(files),
             "uncompressed_bytes":sum(x.file_size for x in files),
             "extension_counts":collections.Counter(pathlib.PurePosixPath(x.filename).suffix.lower() or "(no extension)" for x in files),
             "encrypted_entries":sum(bool(x.flag_bits&1) for x in files)})
        unsafe=[x.filename for x in entries if x.filename.startswith(("/", "\\")) or ".." in pathlib.PurePosixPath(x.filename).parts]
        if unsafe: emit("UNSAFE_PATHS",unsafe[:30])
        emit("TOP_LEVEL",dict(collections.Counter(x.filename.split("/")[0] for x in files)))
        emit("LARGEST_FILES",[{"path":x.filename,"bytes":x.file_size} for x in sorted(files,key=lambda x:x.file_size,reverse=True)[:20]])
        emit("INVENTORY",[{"path":x.filename,"bytes":x.file_size} for x in files if "/algo/" not in x.filename][:100])
        if len(files)>220: emit("INVENTORY_TRUNCATED",len(files)-220)
        known_exec=set()
        for x in files:
            p=pathlib.PurePosixPath(x.filename)
            if p.name=="Info.plist" and x.file_size<=2*1024*1024:
                try:
                    obj=plistlib.loads(read_limited(z,x,2*1024*1024))
                    if isinstance(obj,dict):
                        emit("PLIST",{"archive":label,"path":x.filename,"values":{k:obj[k] for k in PLIST_KEYS if k in obj}})
                        if isinstance(obj.get("CFBundleExecutable"),str):
                            known_exec.add(str(p.parent / obj["CFBundleExecutable"]))
                except Exception as e: emit("ENTRY_ERROR",{"path":x.filename,"error":type(e).__name__})
        for x in files:
            p=pathlib.PurePosixPath(x.filename)
            if x.flag_bits & 1: continue
            if p.suffix.lower() in (".ipa",".zip") and depth<2 and NESTED_COUNT<8 and x.file_size<=350*1024*1024:
                try:
                    NESTED_COUNT+=1
                    data=read_limited(z,x,350*1024*1024)
                    inspect_zip(io.BytesIO(data),label+"!/"+x.filename,depth+1)
                except Exception as e: emit("NESTED_ERROR",{"path":x.filename,"error":type(e).__name__})
            elif (x.filename in known_exec or p.suffix.lower()==".dylib") and BINARY_COUNT<35 and x.file_size<=250*1024*1024:
                try:
                    BINARY_COUNT+=1
                    data=read_limited(z,x,250*1024*1024)
                    emit("MACHO",{"archive":label,"path":x.filename,"sha256":hashlib.sha256(data).hexdigest(),"architectures":macho(data)})
                    patterns=[b"UIDocumentPickerViewController",b"documentPicker:didPickDocumentsAtURLs:",b"documentPicker:didPickDocumentAtURL:",
                              b"startAccessingSecurityScopedResource",b"stopAccessingSecurityScopedResource",b"NSFileCoordinator",
                              b"PHPickerViewController",b"UIImagePickerController",b"initForOpeningContentTypes:asCopy:",
                              b"initWithDocumentTypes:inMode:",b"asCopy",b"LSSupportsOpeningDocumentsInPlace"]
                    emit("PICKER_STRINGS",{"path":x.filename,"present":[s.decode() for s in patterns if s in data]})
                except Exception as e: emit("BINARY_ERROR",{"path":x.filename,"error":type(e).__name__})
            elif (p.suffix.lower() in (".ips",".crash",".log",".py",".sh",".swift",".m",".mm",".h",".yml",".yaml") or p.name.lower().startswith("readme")) and TEXT_COUNT<12 and x.file_size<=1024*1024:
                try:
                    TEXT_COUNT+=1
                    data=read_limited(z,x,1024*1024)
                    if b"\0" not in data[:4096]:
                        emit("TEXT",{"archive":label,"path":x.filename,"text":data[:14000].decode("utf-8","replace"),"truncated":len(data)>14000})
                except Exception as e: emit("TEXT_ERROR",{"path":x.filename,"error":type(e).__name__})


def compact(value, depth=0):
    if depth > 5:
        return "[depth limit]"
    if isinstance(value, bytes):
        if value.startswith(b"bplist") or value.startswith(b"<?xml"):
            try: return compact(plistlib.loads(value),depth+1)
            except Exception: pass
        try:
            decoded=value.decode("utf-8")
            return compact(decoded,depth+1)
        except Exception:
            return {"bytes":len(value),"header_hex":value[:16].hex()}
    if isinstance(value, dict):
        out={}
        for k,v in list(value.items())[:60]:
            if re.search(r"password|token|secret|authorization|receipt|signkey|sign_key",str(k),re.I):
                out[str(k)]="[value omitted]"
            else: out[str(k)]=compact(v,depth+1)
        return out
    if isinstance(value, (list,tuple)):
        return [compact(v,depth+1) for v in value[:10]]
    if isinstance(value,str):
        if value[:1] in ("{","[") and len(value)<200000:
            try:return compact(json.loads(value),depth+1)
            except Exception:pass
        value=re.sub(r"(https?://[^\s?]+)\?[^\s\"<>]*",r"\1?[query omitted]",value)
        return value[:900]+(" [truncated]" if len(value)>900 else "")
    return value

def inspect_storage(path):
    import sqlite3, tempfile, subprocess, shutil
    with zipfile.ZipFile(path) as z:
        files=[x for x in z.infolist() if not x.is_dir() and not x.filename.startswith("__MACOSX/")]
        emit("CRC_CHECK",{"bad_entry":z.testzip(),"files_checked":len(files)})
        groups={}
        roots={}
        for x in files:
            parts=x.filename.split("/")
            root=parts[0]
            rec=roots.setdefault(root,{"files":0,"bytes":0})
            rec["files"]+=1
            rec["bytes"]+=x.file_size
            category="/".join(parts[:3])
            g=groups.setdefault(category,{"files":0,"bytes":0})
            g["files"]+=1
            g["bytes"]+=x.file_size
        emit("CONTAINERS",roots)
        emit("DIRECTORY_TOTALS",groups)
        maps={}
        for x in files:
            root,relative=x.filename.split("/",1)
            maps.setdefault(root,{})[relative]=x
        if len(maps)==2:
            a,b=maps.values()
            common=sorted(set(a)&set(b))
            equal=[]
            different=[]
            for key in common:
                da=read_limited(z,a[key],20*1024*1024)
                db=read_limited(z,b[key],20*1024*1024)
                if hashlib.sha256(da).digest()==hashlib.sha256(db).digest():equal.append(key)
                else:different.append(key)
            emit("CONTAINER_COMPARISON",{"common_files":len(common),"identical":equal,"different":different,
                 "only_first":[k for k in a if k not in b][:25],"only_second_count":len(set(b)-set(a))})
        for i,x in enumerate(files):
            p=pathlib.PurePosixPath(x.filename)
            if p.suffix.lower()==".db":
                data=read_limited(z,x,10*1024*1024)
                if not data.startswith(b"SQLite format 3"):
                    emit("DATABASE_FORMAT",{"path":x.filename,"header_hex":data[:20].hex()})
                    continue
                with tempfile.NamedTemporaryFile(suffix=".db",dir=os.environ["RUNNER_TEMP"]) as f:
                    f.write(data);f.flush()
                    con=sqlite3.connect("file:"+f.name+"?mode=ro&immutable=1",uri=True)
                    try:
                        con.execute("PRAGMA trusted_schema=OFF")
                        tables=con.execute("SELECT name, sql FROM sqlite_master WHERE type='table'").fetchall()
                        emit("DATABASE",{"path":x.filename,"integrity":con.execute("PRAGMA quick_check").fetchone()[0],
                             "tables":[{"name":a,"schema":b} for a,b in tables]})
                        for table,_ in tables[:30]:
                            q='"'+table.replace('"','""')+'"'
                            count=con.execute("SELECT count(*) FROM "+q).fetchone()[0]
                            cur=con.execute("SELECT * FROM "+q+" LIMIT 5")
                            cols=[d[0] for d in cur.description]
                            rows=[compact(dict(zip(cols,row))) for row in cur.fetchall()]
                            emit("TABLE_SAMPLE",{"path":x.filename,"table":table,"count":count,"rows":rows})
                    finally:con.close()
            elif p.suffix.lower() in (".json",".prj",".archive",".archiver") and x.file_size<=1024*1024:
                data=read_limited(z,x,1024*1024)
                obj=None
                typ="unknown"
                try:obj=plistlib.loads(data);typ="plist"
                except Exception:
                    try:obj=json.loads(data);typ="json"
                    except Exception:pass
                emit("STRUCTURED_FILE",{"path":x.filename,"format":typ,
                     "value":compact(obj) if obj is not None else {"header_hex":data[:32].hex(),"ascii_samples":[compact(v.decode()) for v in re.findall(rb"[\x20-\x7e]{6,}",data)[:12]]}})
            elif p.suffix.lower()==".mmap":
                data=read_limited(z,x,1024*1024)
                strings=[v.decode() for v in re.findall(rb"[\x20-\x7e]{5,}",data)]
                domains=sorted(set(re.findall(r"https?://([A-Za-z0-9.-]+)", "\n".join(strings))))
                hints=[s for s in strings if re.search(r"bundle|version|com\.|purchase|vip|member|premium|document|container|app.?name",s,re.I)]
                emit("MMAP",{"path":x.filename,"header_hex":data[:32].hex(),"domains":domains,"relevant_strings":[compact(s) for s in hints[:55]],"printable_string_count":len(strings)})
            elif p.name=="off_sign_key":
                data=read_limited(z,x,1024*1024)
                emit("PRIVATE_FILE",{"path":x.filename,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),"format_hint":"binary plist" if data.startswith(b"bplist") else "other"})
            elif p.suffix.lower()==".mp4" and "/public/export/" in x.filename:
                probe=shutil.which("ffprobe")
                if not probe:
                    emit("VIDEO",{"path":x.filename,"bytes":x.file_size,"probe":"ffprobe unavailable"})
                    continue
                with tempfile.NamedTemporaryFile(suffix=".mp4",dir=os.environ["RUNNER_TEMP"]) as f:
                    with z.open(x) as src:shutil.copyfileobj(src,f)
                    f.flush()
                    run=subprocess.run([probe,"-v","error","-show_entries","format=duration,size:stream=codec_name,codec_type,width,height,r_frame_rate,duration","-of","json",f.name],capture_output=True,text=True,timeout=45)
                    try:obj=json.loads(run.stdout)
                    except Exception:obj={"error":run.stderr[:500]}
                    emit("VIDEO",{"path":x.filename,"metadata":obj})
        samples=[x for x in files if "/algo/" in x.filename][:3]
        for x in samples:
            data=read_limited(z,x,1024*1024)
            try:obj=json.loads(data)
            except Exception:obj={"header_hex":data[:32].hex(),"ascii_samples":[s.decode()[:100] for s in re.findall(rb"[\x20-\x7e]{5,}",data)[:8]]}
            emit("ALGORITHM_CACHE_SAMPLE",{"path":x.filename,"value":compact(obj)})

def main():
    cfg=json.loads(pathlib.Path("archive-inspection/source.json").read_text())
    url=cfg["download_url"]
    print("::add-mask::"+url,flush=True)
    path=pathlib.Path(os.environ["RUNNER_TEMP"])/"archive-2.zip"
    digest=hashlib.sha256()
    size=0
    try:
        req=urllib.request.Request(url,headers=cfg.get("headers",{}))
        with urllib.request.urlopen(req,timeout=120) as response,path.open("wb") as out:
            while True:
                chunk=response.read(1024*1024)
                if not chunk:break
                size+=len(chunk)
                if size>500*1024*1024:raise ValueError("download exceeds 500 MiB")
                digest.update(chunk)
                out.write(chunk)
    except Exception as e:
        emit("DOWNLOAD_FAILED",{"error":type(e).__name__,"http_status":getattr(e,"code",None)})
        return 1
    emit("DOWNLOAD",{"name":cfg["file_name"],"bytes":size,"sha256":digest.hexdigest(),"expected_bytes":cfg["size_bytes"]})
    if size!=cfg["size_bytes"]:
        emit("ERROR","download size does not match source")
        return 1
    try:
        inspect_zip(path,cfg["file_name"])
        inspect_storage(path)
        emit("INSPECTION_COMPLETE",{"bytes_read":TOTAL_READ,"nested_archives":NESTED_COUNT,"binary_files":BINARY_COUNT,"text_files":TEXT_COUNT})
    except Exception as e:
        emit("ERROR",{"error":type(e).__name__,"message":str(e)[:500]})
        return 1
    finally:
        report=pathlib.Path("archive-inspection-report.txt")
        report.write_text("\n".join(REPORT)+"\n")
        summary=os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary,"a") as out:
                out.write("# Archive inspection\n\n")
                out.write("Read-only examination of Archive 2.zip. See job logs for structured findings.\n\n")
                out.write("Downloaded bytes: "+str(size)+"\n\nSHA-256: "+digest.hexdigest()+"\n")
        path.unlink(missing_ok=True)
    return 0

if __name__=="__main__":
    sys.exit(main())
