import { chacha20Process } from '../src/crypto/xchacha20poly1305';
import { serpent256Ctr, serpentKeySchedule } from '../src/crypto/serpent';
import { ctr } from '@noble/ciphers/aes.js';
import { generateSecureRandomBytes } from '../src/crypto/safeRandom';
import { encodeRSStream, decodeRSStream } from '../src/crypto/reedSolomon';
import { normalizeEntropyToTarget } from '../src/crypto/entropy';

async function benchLayers() {
  const mb = 1024 * 1024;
  const data = generateSecureRandomBytes(mb);
  const key32 = generateSecureRandomBytes(32);
  const nonce12 = generateSecureRandomBytes(12);
  const iv16 = generateSecureRandomBytes(16);

  console.log('--- 1 MB Micro-Benchmarks ---');

  // ChaCha20
  let t0 = performance.now();
  chacha20Process(key32, nonce12, 0, data);
  console.log(`ChaCha20 (1 MB): ${(performance.now() - t0).toFixed(1)} ms`);

  // AES-256-CTR
  t0 = performance.now();
  const aes = ctr(key32, iv16);
  aes.encrypt(data);
  console.log(`AES-256-CTR (1 MB): ${(performance.now() - t0).toFixed(1)} ms`);

  // Serpent-256-CTR
  t0 = performance.now();
  const subkeys = serpentKeySchedule(key32);
  serpent256Ctr(data, key32, iv16, subkeys);
  console.log(`Serpent-256-CTR (1 MB): ${(performance.now() - t0).toFixed(1)} ms`);

  // Reed-Solomon RS(255, 223) Encode
  t0 = performance.now();
  const rsEncoded = encodeRSStream(data);
  console.log(`Reed-Solomon RS(255,223) Encode (1 MB): ${(performance.now() - t0).toFixed(1)} ms`);

  // Reed-Solomon RS(255, 223) Decode
  t0 = performance.now();
  decodeRSStream(rsEncoded.encodedData);
  console.log(`Reed-Solomon RS(255,223) Decode (1 MB): ${(performance.now() - t0).toFixed(1)} ms`);

  // Entropy Normalizer
  t0 = performance.now();
  await normalizeEntropyToTarget(data, 7.38);
  console.log(`Entropy Normalization (1 MB): ${(performance.now() - t0).toFixed(1)} ms`);
}

benchLayers().catch(console.error);
