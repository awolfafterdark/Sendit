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
        emit("INVENTORY",[{"path":x.filename,"bytes":x.file_size} for x in files[:220]])
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
