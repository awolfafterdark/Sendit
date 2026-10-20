import collections, hashlib, json, math, os, pathlib, re, shutil, subprocess, tempfile, urllib.request, zipfile
from coremltools.proto import Model_pb2
import coremltools
def emit(kind,value):
    print(kind+" "+json.dumps(value,ensure_ascii=True,default=str),flush=True)
cfg=json.loads(pathlib.Path("archive-inspection/source.json").read_text())
url=cfg["download_url"]
print("::add-mask::"+url,flush=True)
path=pathlib.Path(os.environ["RUNNER_TEMP"])/"archive-model-check.zip"
try:
    req=urllib.request.Request(url,headers=cfg.get("headers",{}))
    with urllib.request.urlopen(req,timeout=120) as response,path.open("wb") as out:
        shutil.copyfileobj(response,out)
except Exception as e:
    emit("DOWNLOAD_ERROR",{"type":type(e).__name__,"status":getattr(e,"code",None)})
    raise SystemExit(1)
if path.stat().st_size!=cfg["size_bytes"]:raise SystemExit("Archive size mismatch")
emit("TOOL_VERSION",coremltools.__version__)
seen=set()
with zipfile.ZipFile(path) as z:
    for info in z.infolist():
        if not info.filename.lower().endswith(".xymodel"):continue
        if info.file_size>50*1024*1024:continue
        data=z.read(info)
        sha=hashlib.sha256(data).hexdigest()
        if sha in seen:continue
        seen.add(sha)
        counts=collections.Counter(data)
        entropy=-sum((n/len(data))*math.log2(n/len(data)) for n in counts.values())
        rec={"name":pathlib.PurePosixPath(info.filename).name,"bytes":len(data),"sha256":sha,
             "first_64_bytes_hex":data[:64].hex(),"last_32_bytes_hex":data[-32:].hex(),"entropy_bits_per_byte":round(entropy,4)}
        strings=[s.decode("ascii") for s in re.findall(rb"[\x20-\x7e]{8,}",data)]
        hints=[s for s in strings if re.search(r"coreml|protobuf|input|output|conv|batchnorm|weight|onnx|pytorch|tensorflow|mlmodel|model|image|float|neural",s,re.I)]
        rec["format_strings"]=hints[:35]
        rec["printable_strings"]=len(strings)
        with tempfile.NamedTemporaryFile(suffix=".xymodel") as f:
            f.write(data);f.flush()
            rec["file_command"]=subprocess.run(["file","-b",f.name],capture_output=True,text=True,check=False).stdout.strip()
        parsed=False
        for off in (0,4,8,12,16,24,32,64,128,256):
            spec=Model_pb2.Model()
            try:
                spec.ParseFromString(data[off:])
                kind=spec.WhichOneof("Type")
                if not (0<spec.specificationVersion<100 and kind and spec.HasField("description")):
                    if off==0:rec["direct_parse"]="protobuf parsed, but not a valid recognized Core ML model"
                    continue
                def features(fs):
                    result=[]
                    for f in fs:
                        ft=f.type.WhichOneof("Type")
                        detail={"name":f.name,"type":ft}
                        if ft=="multiArrayType":
                            detail["shape"]=list(f.type.multiArrayType.shape)
                            detail["dtype"]=f.type.multiArrayType.dataType
                        if ft=="imageType":
                            detail.update({"width":f.type.imageType.width,"height":f.type.imageType.height,"color_space":f.type.imageType.colorSpace})
                        result.append(detail)
                    return result
                rec.update({"coreml_payload_offset":off,"specification_version":spec.specificationVersion,
                    "model_type":kind,"inputs":features(spec.description.input),"outputs":features(spec.description.output),
                    "metadata":{"short_description":spec.description.metadata.shortDescription,
                                "author":spec.description.metadata.author,"license":spec.description.metadata.license,
                                "user_defined":dict(spec.description.metadata.userDefined)}})
                if kind in ("neuralNetwork","neuralNetworkClassifier","neuralNetworkRegressor"):
                    nn=getattr(spec,kind)
                    rec["layer_count"]=len(nn.layers)
                    rec["layer_types"]=dict(collections.Counter(x.WhichOneof("layer") for x in nn.layers))
                parsed=True
                break
            except Exception as e:
                if off==0:rec["direct_parse"]=type(e).__name__
        rec["recognized_coreml_payload"]=parsed
        emit("MODEL_FORMAT",rec)
emit("MODEL_FORMAT_CHECK_COMPLETE",{"unique_models":len(seen),"inference_tested":False})
path.unlink()
