import { Inflate } from 'fflate';
import { LIMITS, validateFiles } from './inputs.js';
import { normalizePath, scopeReason, validateScope, DEFAULT_SCOPE } from './scope.js';

import { ZIP_BYTES } from './archive-limits.js';
export { ZIP_BYTES };
const crcTable = Uint32Array.from({length:256}, (_, n) => {
  for (let bit=0; bit<8; bit++) n = n & 1 ? 0xedb88320 ^ (n >>> 1) : n >>> 1;
  return n >>> 0;
});
function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = crcTable[(crc ^ byte) & 255] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}
const fail = () => { throw Error('zipInvalid'); };
function archivePath(bytes, flags) {
  if (!(flags & 0x800) && bytes.some(b=>b>127)) throw Error('zipEncoding');
  let path;
  try { path = new TextDecoder('utf-8',{fatal:true}).decode(bytes); } catch { throw Error('zipEncoding'); }
  if (path.includes('\\')) fail();
  const directory = path.endsWith('/');
  if (directory) path = path.slice(0,-1);
  try { normalizePath(path); } catch { fail(); }
  if (path.split('/').some(p=>/[:<>"|?*]|[. ]$/.test(p) || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(p))) fail();
  return {path,directory};
}

// Validate the complete central/local metadata before inflating any entry. No extraction to disk.
function indexArchive(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > ZIP_BYTES) throw Error('zipSize');
  const view = new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);
  const u16 = p => { if (p<0 || p+2>bytes.length) fail(); return view.getUint16(p,true); };
  const u32 = p => { if (p<0 || p+4>bytes.length) fail(); return view.getUint32(p,true); };
  let end = -1;
  for (let p=bytes.length-22; p>=Math.max(0,bytes.length-65557); p--)
    if (u32(p)===0x06054b50 && p+22+u16(p+20)===bytes.length) { end=p; break; }
  if (end<0 || u16(end+4) || u16(end+6) || u16(end+8)!==u16(end+10)) fail();
  const count=u16(end+10), size=u32(end+12), start=u32(end+16);
  if (count===65535 || size===0xffffffff || start===0xffffffff) throw Error('zipUnsupported');
  if (count>5000) throw Error('inventoryLimit');
  if (start+size!==end) fail();
  const entries=[], seen=new Map(), ranges=[];
  let p=start;
  for (let i=0; i<count; i++) {
    if (p+46>end || u32(p)!==0x02014b50) fail();
    const flags=u16(p+8), method=u16(p+10), crc=u32(p+16), packed=u32(p+20), length=u32(p+24);
    const nameLength=u16(p+28), extraLength=u16(p+30), commentLength=u16(p+32), offset=u32(p+42);
    if ((flags & ~0x80e) || ![0,8].includes(method) || u16(p+34)) throw Error('zipUnsupported');
    if ([packed,length,offset].includes(0xffffffff)) throw Error('zipUnsupported');
    if (p+46+nameLength+extraLength+commentLength>end) fail();
    const nameBytes=bytes.subarray(p+46,p+46+nameLength), item=archivePath(nameBytes,flags);
    const unixType=(u32(p+38)>>>16)&0xf000;
    if (u32(p+38)&0x400) throw Error('zipUnsupported');
    if ((u32(p+38)&0x10) && !item.directory) fail();
    if (unixType && ![0x8000,0x4000].includes(unixType)) throw Error('zipUnsupported');
    if ((unixType===0x4000 && !item.directory) || (unixType===0x8000 && item.directory)) fail();
    const key=item.path.toLowerCase();
    if (seen.has(key)) fail(); seen.set(key,item.directory);
    if (offset+30>start || u32(offset)!==0x04034b50 || u16(offset+6)!==flags || u16(offset+8)!==method) fail();
    const localNameLength=u16(offset+26), localExtraLength=u16(offset+28);
    const dataStart=offset+30+localNameLength+localExtraLength, dataEnd=dataStart+packed;
    if (dataEnd>start || localNameLength!==nameLength) fail();
    if (!bytes.subarray(offset+30,offset+30+nameLength).every((b,j)=>b===nameBytes[j])) fail();
    let recordEnd=dataEnd;
    if (flags & 8) {
      const descriptor=dataEnd+(u32(dataEnd)===0x08074b50 ? 4 : 0);
      if (descriptor+12>start || u32(descriptor)!==crc || u32(descriptor+4)!==packed || u32(descriptor+8)!==length) fail();
      recordEnd=descriptor+12;
    } else if (u32(offset+14)!==crc || u32(offset+18)!==packed || u32(offset+22)!==length) fail();
    if ((method===0 && packed!==length) || (item.directory && length)) fail();
    entries.push({...item,method,crc,packed,length,dataStart,dataEnd}); ranges.push([offset,recordEnd]);
    p+=46+nameLength+extraLength+commentLength;
  }
  if (p!==end) fail();
  ranges.sort((a,b)=>a[0]-b[0]);
  for (let i=1;i<ranges.length;i++) if (ranges[i][0]<ranges[i-1][1]) fail();
  for (const key of seen.keys()) {
    const parts=key.split('/'); parts.pop();
    while (parts.length) { if (seen.get(parts.join('/'))===false) fail(); parts.pop(); }
  }
  return entries;
}

export function importArchive(bytes, options={}) {
  const scope=validateScope(options.scope || DEFAULT_SCOPE), entries=indexArchive(bytes);
  const regular=entries.filter(e=>!e.directory), first=regular[0]?.path.split('/')[0];
  const root=options.stripRoot && regular.length && regular.every(e=>e.path.startsWith(first+'/')) ? first+'/' : '';
  const accepted=[], skipped=[];
  let total=0;
  for (const entry of regular) {
    const path=entry.path.slice(root.length), reason=scopeReason(path,scope);
    if (reason) { skipped.push({path,reason}); continue; }
    if (accepted.length>=LIMITS.files) throw Error('fileCount');
    if (entry.length>LIMITS.fileBytes) throw Error('fileSize');
    total+=entry.length; if (total>LIMITS.totalBytes) throw Error('totalSize');
    accepted.push({...entry,path});
  }
  if (!accepted.length) throw Error('noImportable');
  const files=[];
  for (const entry of accepted) {
    let output;
    if (entry.method===0) output=bytes.subarray(entry.dataStart,entry.dataEnd);
    else {
      const chunks=[]; let length=0, finished=false;
      const stream=new Inflate((chunk,final)=>{
        length+=chunk.length;
        if (length>LIMITS.fileBytes || length>entry.length) fail();
        chunks.push(chunk); if (final) finished=true;
      });
      try {
        // Small compressed chunks bound transient inflation even when declared sizes lie.
        for (let p=entry.dataStart;p<entry.dataEnd;p+=256)
          stream.push(bytes.subarray(p,Math.min(p+256,entry.dataEnd)),p+256>=entry.dataEnd);
      } catch { fail(); }
      if (!finished || length!==entry.length) fail();
      output=new Uint8Array(length); let cursor=0;
      for (const chunk of chunks) { output.set(chunk,cursor); cursor+=chunk.length; }
    }
    if (output.length!==entry.length || crc32(output)!==entry.crc) fail();
    let content;
    try { content=new TextDecoder('utf-8',{fatal:true}).decode(output); } catch { throw Error('decode'); }
    files.push({path:entry.path,content});
  }
  validateFiles(files);
  return {files,skipped,removed_root:root};
}
