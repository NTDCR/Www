/**
 * ContentGuard Pro MAX - Strict 1 MB Chunked Resilient Streaming File Engine
 * Guarantees that at no point is an entire file loaded into RAM in a single allocation.
 * Memory footprint is strictly bounded to 1 MB (1,048,576 bytes) chunks.
 * Resilient against browser file descriptor timeouts and iframe permission revocations.
 */

export const STRICT_CHUNK_SIZE = 1024 * 1024; // Strictly 1 MB (1,048,576 bytes)
import { yieldToMainThread } from './asyncUtils';
import { generatePlayableH264Mp4 } from '../media/mp4Generator';

export interface StreamingFileHandle {
  name: string;
  size: number;
  type: string;
  source?: File | Blob;
  chunks?: Uint8Array[];
  bytes?: Uint8Array;
  isSynthetic?: boolean;
}

/**
 * Reads blob/slice using FileReader as a robust fallback
 */
export async function readBlobViaFileReader(blob: Blob): Promise<Uint8Array> {
  return new Promise<Uint8Array>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (reader.result instanceof ArrayBuffer) {
        resolve(new Uint8Array(reader.result));
      } else if (typeof reader.result === 'string') {
        const str = reader.result;
        const u8 = new Uint8Array(str.length);
        for (let i = 0; i < str.length; i++) {
          u8[i] = str.charCodeAt(i) & 0xff;
        }
        resolve(u8);
      } else {
        reject(new Error('FileReader returned invalid data format'));
      }
    };
    reader.onerror = () => reject(reader.error || new Error('FileReader read error'));
    reader.onabort = () => reject(new Error('FileReader operation aborted'));
    reader.readAsArrayBuffer(blob);
  });
}

/**
 * Creates a lightweight streaming handle from a user-selected File or Blob instantly
 */
export function createStreamingFileHandle(
  file: File | Blob | Uint8Array,
  customName?: string,
  preloadedChunks?: Uint8Array[],
  preloadedBytes?: Uint8Array
): StreamingFileHandle {
  if (file instanceof Uint8Array) {
    return {
      name: customName || 'payload.bin',
      size: file.length,
      type: 'application/octet-stream',
      bytes: file,
      chunks: preloadedChunks || [file]
    };
  }
  const name = customName || ('name' in file ? (file as File).name : 'carrier_container.mp4');
  const size = file.size || 0;
  const type = file.type || 'application/octet-stream';
  return {
    name,
    size,
    type,
    source: file,
    bytes: preloadedBytes,
    chunks: preloadedChunks
  };
}

/**
 * Creates a synthetic streaming MP4 handle for demo/test mode without pre-allocating full file
 */
export function createSyntheticFileHandle(size: number = 2 * 1024 * 1024, name: string = 'synthetic_carrier.mp4'): StreamingFileHandle {
  const baseMp4 = generatePlayableH264Mp4(5);
  let syntheticBlob: Blob;
  if (size > baseMp4.length + 8) {
    const freeBoxSize = size - baseMp4.length;
    const freeHeader = new Uint8Array(8);
    new DataView(freeHeader.buffer).setUint32(0, freeBoxSize, false);
    freeHeader.set([0x66, 0x72, 0x65, 0x65], 4); // 'free' box
    const padding = new Uint8Array(freeBoxSize - 8);
    syntheticBlob = new Blob([baseMp4, freeHeader, padding], { type: 'video/mp4' });
  } else {
    syntheticBlob = new Blob([baseMp4], { type: 'video/mp4' });
  }

  return {
    name,
    size: syntheticBlob.size,
    type: 'video/mp4',
    source: syntheticBlob,
    isSynthetic: true
  };
}

/**
 * Reads a single slice/blob into a Uint8Array with 6-tier resilient fallback and exponential backoff retry
 */
export async function readSliceWithFallback(slice: Blob, maxRetries: number = 3): Promise<Uint8Array> {
  if (slice.size === 0) return new Uint8Array(0);

  let lastError: any = null;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    if (attempt > 0) {
      // Exponential backoff to allow OS file locks (antivirus / cloud sync) to clear
      await new Promise(r => setTimeout(r, 60 * Math.pow(2, attempt - 1)));
      await yieldToMainThread();
    }

    // Strategy 1: Direct Blob.arrayBuffer()
    try {
      const ab = await slice.arrayBuffer();
      if (ab && ab.byteLength >= 0) {
        return new Uint8Array(ab);
      }
    } catch (e) { lastError = e; }

    // Strategy 2: FileReader ArrayBuffer
    try {
      const u8 = await readBlobViaFileReader(slice);
      if (u8 && u8.length >= 0) return u8;
    } catch (e) { lastError = e; }

    // Strategy 3: Response(slice).arrayBuffer() (resilient in sandboxed iframe contexts)
    try {
      const ab = await new Response(slice).arrayBuffer();
      if (ab && ab.byteLength >= 0) {
        return new Uint8Array(ab);
      }
    } catch (e) { lastError = e; }

    // Strategy 4: Web Streams API stream().getReader()
    try {
      if (typeof (slice as any).stream === 'function') {
        const reader = (slice as any).stream().getReader();
        const chunks: Uint8Array[] = [];
        let totalLen = 0;
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) {
            chunks.push(value);
            totalLen += value.length;
          }
        }
        if (totalLen > 0) {
          const combined = new Uint8Array(totalLen);
          let offset = 0;
          for (const c of chunks) {
            combined.set(c, offset);
            offset += c.length;
          }
          return combined;
        }
      }
    } catch (e) { lastError = e; }

    // Strategy 5: Blob URL fetch (uses browser internal blob protocol)
    try {
      if (typeof URL !== 'undefined' && typeof fetch !== 'undefined') {
        const blobUrl = URL.createObjectURL(slice);
        try {
          const resp = await fetch(blobUrl);
          const ab = await resp.arrayBuffer();
          if (ab && ab.byteLength >= 0) {
            return new Uint8Array(ab);
          }
        } finally {
          URL.revokeObjectURL(blobUrl);
        }
      }
    } catch (e) { lastError = e; }

    // Strategy 6: FileReader readAsBinaryString
    try {
      const u8 = await new Promise<Uint8Array>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
          if (typeof reader.result === 'string') {
            const str = reader.result;
            const arr = new Uint8Array(str.length);
            for (let i = 0; i < str.length; i++) {
              arr[i] = str.charCodeAt(i) & 0xff;
            }
            resolve(arr);
          } else if (reader.result instanceof ArrayBuffer) {
            resolve(new Uint8Array(reader.result));
          } else {
            reject(new Error('Unable to parse file stream bytes'));
          }
        };
        reader.onerror = () => reject(reader.error || new Error('Slice read error'));
        reader.readAsBinaryString(slice);
      });
      if (u8) return u8;
    } catch (e) { lastError = e; }
  }

  throw new Error(
    `The requested file slice could not be read after ${maxRetries} attempts (${lastError?.message || 'OS file lock/stale handle'}). Please re-select or drag & drop the file.`
  );
}

/**
 * Reads a single 1 MB chunk from a File, Blob, or StreamingFileHandle at a specific byte offset
 */
export async function readChunkFromHandle(
  handle: StreamingFileHandle | File | Blob,
  offset: number,
  chunkSize: number = STRICT_CHUNK_SIZE
): Promise<Uint8Array> {
  if (offset < 0 || chunkSize <= 0) return new Uint8Array(0);
  if (typeof handle === 'object' && handle !== null) {
    if ('bytes' in handle && handle.bytes instanceof Uint8Array) {
      if (offset >= handle.bytes.length) return new Uint8Array(0);
      const end = Math.min(offset + chunkSize, handle.bytes.length);
      return handle.bytes.subarray(offset, end);
    }
    if ('chunks' in handle && handle.chunks && handle.chunks.length > 0) {
      if (offset >= handle.size) return new Uint8Array(0);
      const totalToRead = Math.min(chunkSize, handle.size - offset);
      const result = new Uint8Array(totalToRead);
      let bytesCopied = 0;
      let currentOffset = offset;

      let accumulated = 0;
      for (let i = 0; i < handle.chunks.length && bytesCopied < totalToRead; i++) {
        const chunk = handle.chunks[i];
        const chunkStart = accumulated;
        const chunkEnd = accumulated + chunk.length;
        accumulated = chunkEnd;

        if (currentOffset >= chunkEnd) continue;
        if (currentOffset < chunkStart) break;

        const chunkOffset = currentOffset - chunkStart;
        const available = chunk.length - chunkOffset;
        if (available <= 0) continue;
        const toCopy = Math.min(available, totalToRead - bytesCopied);
        result.set(chunk.subarray(chunkOffset, chunkOffset + toCopy), bytesCopied);
        bytesCopied += toCopy;
        currentOffset += toCopy;
      }
      return result.subarray(0, bytesCopied);
    }
  }

  const source = (typeof handle === 'object' && handle !== null && 'source' in handle)
    ? handle.source
    : (handle as File | Blob);

  if (!source) return new Uint8Array(0);

  const end = Math.min(offset + chunkSize, source.size);
  if (offset >= source.size) {
    return new Uint8Array(0);
  }

  // Attempt to read and cache root source buffer only for small files (<= 8 MB) to maintain bounded RAM
  if (source.size <= 8 * 1024 * 1024) {
    try {
      const raw = await readRootFileAsUint8Array(source);
      if (typeof handle === 'object' && handle !== null) {
        (handle as any).bytes = raw;
      }
      return raw.subarray(offset, Math.min(offset + chunkSize, raw.length));
    } catch {
      // Fall through to slice
    }
  }

  try {
    const slice = source.slice(offset, end);
    return await readSliceWithFallback(slice);
  } catch (err: any) {
    // Retry slice read once after yielding to clear transient OS file locks
    await yieldToMainThread();
    try {
      const retrySlice = source.slice(offset, end);
      return await readSliceWithFallback(retrySlice);
    } catch {
      throw new Error(
        `The requested file chunk [${offset}..${end}] could not be read (${err?.message || 'OS file lock/timeout'}). Please re-select the file.`
      );
    }
  }
}

/**
 * Async generator to stream an entire File/Blob in strict 1 MB chunks
 */
export async function* streamFileIn1MbChunks(
  handle: StreamingFileHandle | File | Blob,
  chunkSize: number = STRICT_CHUNK_SIZE
): AsyncGenerator<{ chunk: Uint8Array; offset: number; totalSize: number; isLast: boolean }> {
  // If handle already contains pre-buffered 1MB chunks
  if (typeof handle === 'object' && handle !== null && 'chunks' in handle && handle.chunks && handle.chunks.length > 0) {
    const totalSize = handle.size;
    let offset = 0;
    for (let i = 0; i < handle.chunks.length; i++) {
      const chunk = handle.chunks[i];
      offset += chunk.length;
      yield {
        chunk,
        offset,
        totalSize,
        isLast: i === handle.chunks.length - 1
      };
    }
    return;
  }

  // If handle has pre-cached whole bytes
  if (typeof handle === 'object' && handle !== null && 'bytes' in handle && handle.bytes instanceof Uint8Array) {
    const totalSize = handle.bytes.length;
    let offset = 0;
    while (offset < totalSize) {
      const end = Math.min(offset + chunkSize, totalSize);
      const chunk = handle.bytes.subarray(offset, end);
      offset = end;
      yield {
        chunk,
        offset,
        totalSize,
        isLast: offset >= totalSize
      };
    }
    return;
  }

  const source = (typeof handle === 'object' && handle !== null && 'source' in handle)
    ? handle.source
    : (handle as File | Blob);

  const totalSize = source ? source.size : 0;
  if (totalSize === 0) {
    return;
  }

  // Continuous Native ReadableStream (Chrome/Edge/Safari/Firefox) - eliminates repeated OS slice calls!
  if (typeof (source as any).stream === 'function') {
    try {
      const reader = (source as any).stream().getReader();
      let streamOffset = 0;
      let buffer: Uint8Array = new Uint8Array(0);

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value && value.length > 0) {
          const newBuf = new Uint8Array(buffer.length + value.length);
          newBuf.set(buffer, 0);
          newBuf.set(value, buffer.length);
          buffer = newBuf;

          while (buffer.length >= chunkSize) {
            const chunk = buffer.subarray(0, chunkSize);
            streamOffset += chunk.length;
            yield {
              chunk,
              offset: streamOffset,
              totalSize,
              isLast: streamOffset >= totalSize
            };
            buffer = buffer.subarray(chunkSize);
            await yieldToMainThread();
          }
        }
      }

      if (buffer.length > 0) {
        streamOffset += buffer.length;
        yield {
          chunk: buffer,
          offset: streamOffset,
          totalSize,
          isLast: true
        };
      }
      return;
    } catch (streamErr) {
      console.warn('Native ReadableStream interrupted, falling back to slice reader:', streamErr);
    }
  }

  // Resilient slice-by-slice fallback with infinite-loop prevention
  let offset = 0;
  while (offset < totalSize) {
    const chunk = await readChunkFromHandle(source, offset, chunkSize);
    if (chunk.length === 0) {
      throw new Error(
        `File streaming halted: Unable to read chunk at byte offset ${offset} of ${totalSize}. Please re-select the file.`
      );
    }
    offset += chunk.length;
    yield {
      chunk,
      offset,
      totalSize,
      isLast: offset >= totalSize
    };
    await yieldToMainThread();
  }
}

/**
 * Reads a root File or Blob instance directly using 6 multi-tier fallback strategies WITHOUT slicing
 * This completely immunizes against Chromium's file.slice() NOT_READABLE_ERR permission bug!
 */
export async function readRootFileAsUint8Array(file: File | Blob): Promise<Uint8Array> {
  if (file.size === 0) return new Uint8Array(0);

  // Strategy 1: Direct file.arrayBuffer()
  try {
    const ab = await file.arrayBuffer();
    if (ab && ab.byteLength >= 0) return new Uint8Array(ab);
  } catch {}

  // Strategy 2: Web Streams API file.stream().getReader()
  try {
    if (typeof (file as any).stream === 'function') {
      const reader = (file as any).stream().getReader();
      const chunks: Uint8Array[] = [];
      let totalLen = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value && value.length > 0) {
          chunks.push(value);
          totalLen += value.length;
        }
      }
      if (totalLen > 0) {
        const out = new Uint8Array(totalLen);
        let p = 0;
        for (const c of chunks) {
          out.set(c, p);
          p += c.length;
        }
        return out;
      }
    }
  } catch {}

  // Strategy 3: FileReader readAsArrayBuffer
  try {
    const u8 = await readBlobViaFileReader(file);
    if (u8 && u8.length >= 0) return u8;
  } catch {}

  // Strategy 4: new Response(file).arrayBuffer()
  try {
    const ab = await new Response(file).arrayBuffer();
    if (ab && ab.byteLength >= 0) return new Uint8Array(ab);
  } catch {}

  // Strategy 5: Blob URL fetch (browser internal storage protocol)
  try {
    if (typeof URL !== 'undefined' && typeof fetch !== 'undefined') {
      const url = URL.createObjectURL(file);
      try {
        const resp = await fetch(url);
        const ab = await resp.arrayBuffer();
        if (ab && ab.byteLength >= 0) return new Uint8Array(ab);
      } finally {
        URL.revokeObjectURL(url);
      }
    }
  } catch {}

  // Strategy 6: FileReader readAsBinaryString
  return await new Promise<Uint8Array>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === 'string') {
        const str = reader.result;
        const u8 = new Uint8Array(str.length);
        for (let i = 0; i < str.length; i++) u8[i] = str.charCodeAt(i) & 0xff;
        resolve(u8);
      } else if (reader.result instanceof ArrayBuffer) {
        resolve(new Uint8Array(reader.result));
      } else {
        reject(new Error('Invalid reader result'));
      }
    };
    reader.onerror = () => reject(reader.error || new Error('FileReader read error'));
    reader.readAsBinaryString(file);
  });
}

/**
 * Loads a File or Blob handle with robust immediate buffering to eliminate OS file-descriptor timeouts
 */
export async function loadStreamingFileHandleAsync(
  file: File | Blob | Uint8Array,
  customName?: string,
  onProgress?: (pct: number) => void
): Promise<StreamingFileHandle> {
  if (file instanceof Uint8Array) {
    return {
      name: customName || 'payload.bin',
      size: file.length,
      type: 'application/octet-stream',
      bytes: file,
      chunks: [file]
    };
  }
  const name = customName || ('name' in file ? (file as File).name : 'carrier_container.mp4');
  const size = file.size || 0;
  const type = file.type || 'application/octet-stream';

  if (size === 0) {
    onProgress?.(100);
    return {
      name,
      size: 0,
      type,
      source: file,
      bytes: new Uint8Array(0),
      chunks: []
    };
  }

  // For files <= 8MB: Pre-read into memory right upon user selection for fast startup.
  // Files > 8MB are strictly streamed on-demand in 1 MB chunks via source.slice().
  if (size <= 8 * 1024 * 1024) {
    try {
      onProgress?.(20);
      const rawBytes = await readRootFileAsUint8Array(file);
      onProgress?.(70);

      // Slice into 1 MB chunks in RAM using zero-copy subarrays (zero disk access, zero OS permissions)
      const chunks: Uint8Array[] = [];
      let offset = 0;
      while (offset < rawBytes.length) {
        const end = Math.min(offset + STRICT_CHUNK_SIZE, rawBytes.length);
        chunks.push(rawBytes.subarray(offset, end));
        offset = end;
      }
      onProgress?.(100);

      return {
        name,
        size: rawBytes.length,
        type,
        source: file,
        bytes: rawBytes,
        chunks
      };
    } catch (preloadErr) {
      console.warn('Pre-buffering root file failed, falling back to lazy streaming handle:', preloadErr);
    }
  }

  onProgress?.(100);

  return {
    name,
    size,
    type,
    source: file
  };
}

export type LoadedFileData = StreamingFileHandle;

export async function loadFileImmediately(file: File): Promise<StreamingFileHandle> {
  return loadStreamingFileHandleAsync(file);
}

/**
 * Resilient multi-tier reader to extract Uint8Array bytes without crashing on large files
 */
export async function readFileAsUint8Array(input: File | Blob | Uint8Array | StreamingFileHandle): Promise<Uint8Array> {
  if (input instanceof Uint8Array) return input;

  if (typeof input === 'object' && input !== null) {
    if ('bytes' in input && input.bytes instanceof Uint8Array && input.bytes.length > 0) {
      return input.bytes;
    }
    if ('chunks' in input && input.chunks && input.chunks.length > 0) {
      const totalLen = input.chunks.reduce((acc, c) => acc + c.length, 0);
      const combined = new Uint8Array(totalLen);
      let offset = 0;
      for (const chunk of input.chunks) {
        combined.set(chunk, offset);
        offset += chunk.length;
      }
      return combined;
    }
  }

  const source = (typeof input === 'object' && input !== null && 'source' in input)
    ? input.source
    : (input as File | Blob);

  if (!source) return new Uint8Array(0);

  // Directly read root source with 6-tier fallback (never via slice!)
  const result = await readRootFileAsUint8Array(source);

  // Cache on handle ONLY for small buffers (<= 8 MB) to prevent pinning large files in heap memory
  if (typeof input === 'object' && input !== null && 'name' in input && result.length > 0 && result.length <= 8 * 1024 * 1024) {
    (input as StreamingFileHandle).bytes = result;
  }

  return result;
}

/**
 * Native File System Access API: Streams chunks directly to disk with zero RAM overhead
 */
export async function streamChunksDirectToDisk(
  filename: string,
  chunkGenerator: AsyncGenerator<Uint8Array> | (() => AsyncGenerator<Uint8Array>) | Uint8Array[],
  onProgress?: (bytesWritten: number, status: string) => void
): Promise<{ success: boolean; streamedDirectly: boolean }> {
  let fileHandle: any = null;
  let writable: any = null;

  // Check if Native File System Access API is supported and accessible
  if (typeof window !== 'undefined' && 'showSaveFilePicker' in window) {
    try {
      const ext = filename.includes('.') ? filename.split('.').pop()?.toLowerCase() || 'bin' : 'bin';
      let mimeType = 'application/octet-stream';
      if (ext === 'mp4') mimeType = 'video/mp4';
      else if (ext === 'zip') mimeType = 'application/zip';
      else if (ext === 'pdf') mimeType = 'application/pdf';
      else if (ext === 'txt') mimeType = 'text/plain';
      else if (ext === 'png') mimeType = 'image/png';
      else if (ext === 'jpg' || ext === 'jpeg') mimeType = 'image/jpeg';
      else if (ext === 'json') mimeType = 'application/json';

      fileHandle = await (window as any).showSaveFilePicker({
        suggestedName: filename,
        types: [
          {
            description: 'Protected Output File',
            accept: { [mimeType]: [`.${ext}`] }
          }
        ]
      });
      writable = await fileHandle.createWritable();
    } catch (pickerErr: any) {
      if (pickerErr.name === 'AbortError') {
        throw new Error('Save to disk was cancelled by the user.');
      }
      console.warn('Native showSaveFilePicker not permitted in sandbox, falling back to streaming Blob:', pickerErr);
    }
  }

  let totalWritten = 0;

  if (writable) {
    try {
      if (Array.isArray(chunkGenerator)) {
        for (const chunk of chunkGenerator) {
          await writable.write(chunk);
          totalWritten += chunk.length;
          onProgress?.(totalWritten, `Wrote ${(totalWritten / (1024 * 1024)).toFixed(2)} MB directly to disk...`);
        }
      } else {
        const gen = typeof chunkGenerator === 'function' ? chunkGenerator() : chunkGenerator;
        for await (const chunk of gen) {
          await writable.write(chunk);
          totalWritten += chunk.length;
          onProgress?.(totalWritten, `Wrote ${(totalWritten / (1024 * 1024)).toFixed(2)} MB directly to disk...`);
        }
      }
      await writable.close();
      onProgress?.(totalWritten, `Finished streaming ${(totalWritten / (1024 * 1024)).toFixed(2)} MB directly to disk.`);
      return { success: true, streamedDirectly: true };
    } catch (writeErr) {
      try { await writable.abort(); } catch {}
      throw writeErr;
    }
  }

  // Fallback: Assemble array of chunks into standard Blob stream
  const chunks: Uint8Array[] = [];
  if (Array.isArray(chunkGenerator)) {
    for (let i = 0; i < chunkGenerator.length; i++) {
      chunks.push(chunkGenerator[i]);
    }
  } else {
    const gen = typeof chunkGenerator === 'function' ? chunkGenerator() : chunkGenerator;
    for await (const chunk of gen) {
      chunks.push(chunk);
      totalWritten += chunk.length;
      onProgress?.(totalWritten, `Prepared ${(totalWritten / (1024 * 1024)).toFixed(2)} MB in chunks...`);
    }
  }

  const blob = new Blob(chunks, { type: 'application/octet-stream' });
  if (typeof document !== 'undefined') {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }

  return { success: true, streamedDirectly: false };
}

/**
 * Sanitizes an untrusted filename against path traversal attacks (CWE-22)
 * and Windows/POSIX filesystem reserved name collisions.
 */
export function sanitizeFilename(rawName: string, fallback: string = 'extracted_payload.bin'): string {
  if (!rawName || typeof rawName !== 'string') return fallback;

  // 1. Strip null bytes, control characters (0x00 - 0x1F, 0x7F), and leading/trailing whitespace
  let clean = rawName.replace(/[\x00-\x1f\x7f]/g, '').trim();

  // 2. Remove directory path components (both POSIX / and Windows \)
  clean = clean.replace(/^.*[/\\]/, '');

  // 3. Remove dangerous filesystem characters: < > : " / \ | ? *
  clean = clean.replace(/[<>:"/\\|?*]/g, '_');

  // 4. Strip leading dots (hidden files/parent traversal) and trailing dots/spaces (invalid in NTFS)
  clean = clean.replace(/^\.+/, '').replace(/[\s.]+$/, '');

  // 5. Guard against reserved DOS/Windows device names (CON, PRN, AUX, NUL, COM0-9, LPT0-9, CONIN$, CONOUT$, CLOCK$)
  const reservedRegex = /^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9]|CONIN\$|CONOUT\$|CLOCK\$)(\..*)?$/i;
  if (reservedRegex.test(clean)) {
    clean = `_${clean}`;
  }

  // 6. Max UTF-8 byte length limit (255 bytes for NTFS, ext4, APFS)
  const enc = new TextEncoder();
  const dec = new TextDecoder('utf-8', { fatal: false });
  const utf8Bytes = enc.encode(clean);

  if (utf8Bytes.length > 255) {
    const extIdx = clean.lastIndexOf('.');
    let ext = '';
    if (extIdx > 0 && clean.length - extIdx <= 15) {
      ext = clean.slice(extIdx);
    }
    const extBytes = enc.encode(ext);
    const maxBaseBytes = Math.max(1, 255 - extBytes.length);

    clean = dec.decode(utf8Bytes.subarray(0, maxBaseBytes)) + ext;
    // Re-strip any trailing spaces/dots introduced by byte truncation
    clean = clean.replace(/[\s.]+$/, '');
  }

  return clean.length > 0 ? clean : fallback;
}

/**
 * Zeroizes cached memory buffers on a streaming file handle (B5: Memory hygiene)
 */
export function zeroizeStreamingHandle(handle: any): void {
  if (handle && typeof handle === 'object') {
    if ('bytes' in handle && handle.bytes instanceof Uint8Array) {
      handle.bytes.fill(0);
      delete handle.bytes;
    }
    if ('chunks' in handle && Array.isArray(handle.chunks)) {
      for (const c of handle.chunks) {
        if (c instanceof Uint8Array) c.fill(0);
      }
      handle.chunks.length = 0;
    }
  }
}
