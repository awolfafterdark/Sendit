# Archive 2.zip — examination findings

Inspected with GitHub Actions on 20 October 2026.

- Successful run: https://github.com/awolfafterdark/Sendit/actions/runs/39476534178
- Inspection commit: f419f3b277b3edac03445accc6090b608b570838
- SHA-256: `7dad4e3ab27e92d2ac31d51874796fe6dc8b62b74ed92cc9e7e1134ce545d1fd`
- Compressed file size: 199,392,303 bytes.
- Total file data after decompression: 205,259,805 bytes.
- ZIP entries: 7,630, including 7,578 files and 52 directory entries.
- All ZIP CRC checks passed. No encrypted entries or unsafe relative paths were reported.
- All five SQLite databases returned `ok` from `PRAGMA quick_check`.

## What this archive contains

This is a pair of iOS app Documents-folder copies. The archive has no Payload/.app bundle, Info.plist, or packaged app executable.

One cached analytics record identifies the app as `FaceSwapper2_ipados`, version `2.2.2`, with bundle identifier `com.face.replace` and product ID `73`. Embedded project metadata also records app version 2.2.2. These are statements in the supplied files; no installed app or live service was inspected.

| Container folder | Files | Uncompressed bytes | Contents |
| --- | ---: | ---: | --- |
| `6E95A898-E7DE-4D0A-A864-1B939CE75A61` | 14 | 44,403,133 | Two databases, AI models, HTTP video cache, an analytics buffer, and one draft thumbnail. |
| `7D4D1228-E688-4577-AFCB-A7840723F6D9` | 7,564 | 160,856,672 | Three databases, the same AI models, three project files, three draft thumbnails, algorithm cache, two exported videos, and a private signing-related filename. |

The folder names alone do not establish which installation was original, signed, modified, or working.

## Projects and media

The smaller container's `EJMyDraftModel` table contains two draft records, but neither referenced .prj file is present in the archive. One corresponding thumbnail exists. This limits draft recovery from that folder.

The larger container contains three binary .prj files with `XYT_DATAFILE_1000` markers and embedded JSON/XML. Its database lists:

| Draft folder | Database duration | Export |
| --- | ---: | --- |
| `2026_10_10_14_27_01_646` | 5.083 seconds | Demo project; no export path recorded. |
| `2026_10_10_14_36_09_882` | 14.033 seconds | `20261010143646_1080P.MP4`, 12,416,904 bytes. |
| `2026_10_10_14_39_32_182` | 118.667 seconds | `20261010144602_1080P.MP4`, 102,402,325 bytes. |

The durations above come from the draft database, not a video decoder. The filenames include 1080P, but the encoded dimensions and codecs were not verified because ffprobe was unavailable on this runner.

The two non-demo source clips are referenced through `PHASSET://` identifiers. Their original source files are not separately identifiable in the supplied Documents copies. Restoring editable projects may require those original Photos assets. The exported MP4 files themselves are included.

There are six MP4 entries in total: two exports and four HTTP-cache entries across the two containers. One cached demo video is duplicated.

## AI models and algorithm cache

Each container has the same four model files:

- `face_det.xymodel`
- `object_det.xymodel`
- `salient_det.xymodel`
- `pet_det.xymodel`

Their metadata records version 5.3.2 and a CoreML backend. The four model files, model metadata JSON, and model archive match between the two containers by SHA-256. Together, each container's AIModel directory occupies 35,600,944 bytes.

The larger container contains 7,543 extensionless files under project algorithm-cache paths. Three examined samples are JSON face-detection records with landmark coordinates, face rectangles, rotations, and detection flags. Only those three cache contents were sampled; all entries were covered by the ZIP CRC check.

## Databases and state

- `APPStorage.db`: template groups, template catalog, and video-platform configuration.
- `EJAPPStorage.db`: drafts, product information, and a receipt-result table; the larger copy additionally has face-history and Photos-asset tables.
- `LKDB.db`: present only in the larger copy; stores product introductory-offer and discount structures.

The `EJStoreReceiptResult` table is empty in both copies. The larger copy has seven product-info rows, while the smaller copy has none. Product listings and prices are cached catalog data; they do not establish a purchased or active subscription.

The larger container also contains `Documents/private/off_sign_key`, a 673-byte binary plist. Its value was not printed or interpreted as a usable credential.

## Differences and limits

Eleven relative file paths occur in both containers. Seven have identical contents: the six AIModel files and one cached video. Four differ: the HTTP cache index, both shared database files, and the analytics mmap buffer.

The smaller analytics buffer contains a readable event identifying the app. The larger buffer yielded no printable strings in this inspection.

This archive can support analysis of saved data, project references, caches, and recorded state. It cannot establish the executable's picker callbacks, entitlements, provisioning, signing behavior, or live error path because the app bundle and runtime diagnostics are absent. A picker-failure diagnosis would require the corresponding IPA or relevant runtime logs.

## Method

The inspector downloaded the archive, verified its expected byte count, calculated SHA-256, checked ZIP CRCs, compared common files, opened SQLite files in read-only mode, decoded JSON/property-list metadata, and sampled project/cache structures. It did not execute archive contents, modify the original archive, or play the media.
