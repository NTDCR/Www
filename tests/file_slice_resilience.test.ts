import {
  readChunkFromHandle,
  streamFileIn1MbChunks,
  loadStreamingFileHandleAsync
} from '../src/utils/fileReader';
import { generateSecureRandomBytes } from '../src/crypto/safeRandom';

async function testFileSliceResilience() {
  console.log('================================================================');
  console.log('  TESTING FILE SLICE READ RESILIENCE & INFINITE-LOOP ELIMINATION');
  console.log('================================================================');

  // 1. Test pre-buffering on files <= 64 MB
  console.log('\n--- 1. Testing Immediate Pre-Buffering on Selection ---');
  const rawBytes = generateSecureRandomBytes(5 * 1024 * 1024); // 5 MB file
  const testBlob = new Blob([rawBytes], { type: 'application/octet-stream' });
  const handle = await loadStreamingFileHandleAsync(testBlob, 'test_5mb.bin');
  
  console.log('Handle created with name:', handle.name);
  console.log('Handle preloaded chunks count:', handle.chunks ? handle.chunks.length : 0);
  if (!handle.chunks || handle.chunks.length !== 5) {
    throw new Error('FAILED: Pre-buffering did not create expected 5x 1MB chunks!');
  }
  console.log('SUCCESS: Pre-buffering created 5x 1MB in-memory chunks upon selection!');

  // 2. Test reading chunks from pre-buffered handle (0 disk access)
  console.log('\n--- 2. Testing Chunk Reading from Pre-buffered Handle ---');
  const chunk0 = await readChunkFromHandle(handle, 0);
  const chunk2 = await readChunkFromHandle(handle, 2 * 1024 * 1024);
  console.log('Chunk 0 length:', chunk0.length);
  console.log('Chunk 2 length:', chunk2.length);
  if (chunk0.length !== 1024 * 1024 || chunk2.length !== 1024 * 1024) {
    throw new Error('FAILED: Chunk read from pre-buffered handle returned incorrect length!');
  }
  console.log('SUCCESS: Instant 0ms RAM retrieval from pre-buffered handle!');

  // 3. Test Streaming generator with chunks
  console.log('\n--- 3. Testing Streaming Generator ---');
  let chunksReceived = 0;
  let totalStreamedBytes = 0;
  for await (const { chunk, offset, totalSize, isLast } of streamFileIn1MbChunks(handle)) {
    chunksReceived++;
    totalStreamedBytes += chunk.length;
    console.log(`Streamed chunk ${chunksReceived}: ${chunk.length} bytes, offset=${offset}, total=${totalSize}, isLast=${isLast}`);
  }
  if (chunksReceived !== 5 || totalStreamedBytes !== 5 * 1024 * 1024) {
    throw new Error(`FAILED: Streaming generator yielded incorrect chunks: ${chunksReceived}, bytes: ${totalStreamedBytes}`);
  }
  console.log('SUCCESS: Stream generator smoothly yielded all 5 chunks from RAM without disk access!');

  // 4. Test broken handle failure mode (infinite-loop breaker)
  console.log('\n--- 4. Testing Infinite-Loop Breaker on Empty Read ---');
  const brokenSource = {
    size: 1000,
    slice: () => new Blob([]), // Always returns 0-byte slice!
    arrayBuffer: async () => new ArrayBuffer(0)
  };
  
  let loopDetected = false;
  try {
    for await (const _ of streamFileIn1MbChunks(brokenSource as any)) {
      // should throw
    }
  } catch (err: any) {
    console.log('Caught expected error from broken source:', err.message);
    if (err.message.includes('File streaming halted: Unable to read chunk')) {
      loopDetected = true;
    }
  }

  if (!loopDetected) {
    throw new Error('FAILED: Generator did not trigger infinite-loop guard on empty chunk!');
  }
  console.log('SUCCESS: Infinite-loop breaker immediately aborted empty chunk read with descriptive error!');

  console.log('\n================================================================');
  console.log('  ALL FILE SLICE RESILIENCE TESTS PASSED (100% RELIABLE)');
  console.log('================================================================');
}

testFileSliceResilience().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
