# ContentGuard Pro MAX (v1.0.1)

> **Zero-Knowledge Air-Gapped Cryptographic Preservation & Plausible Deniability Platform**

ContentGuard Pro MAX is an enterprise-grade, air-gapped cryptographic and steganographic system engineered for high-consequence data preservation, plausible deniability, and multi-century confidentiality.

---

## Key Technical Specifications

* **Post-Quantum Cryptography**: NIST Level 5 Kyber-1024 KEM integrated into Layer 1 key encapsulation.
* **5-Layer Stacked-Cipher Cascade**:
  1. **Layer 1**: Kyber-1024 Post-Quantum KEM
  2. **Layer 2**: Serpent-256-CTR (32-Round Substitution-Permutation Network)
  3. **Layer 3**: XChaCha20-Poly1305 / XChaCha20 Stream Cipher
  4. **Layer 4**: AES-256-CTR (Hardware Galois Acceleration)
  5. **Layer 5**: ChaCha20 Stream Keystream Masking Layer
* **Plausible Deniability Architecture**:
  - Compulsory Dual-Vault packaging (Vault A: Primary Secret, Vault B: Decoy).
  - Quantum Cover Frame Padding: Symmetrically equalized codeword counts and zero leftover differential artifacts.
* **8-Location Spread-Spectrum Steganography**:
  - Injected across 7 standard ISO/IEC 14496-12 box locations + 1 private container (`sony`, `canon`, `mdat`, `free`, `stco`, `cgpm`, etc.).
  - Gaussian-Bell Bias LUT Interleaver shaping payload entropy to $\le 7.40\text{ bits/byte}$ ($p > 0.005$ Chi-Square conformance).
* **NASA/ISO Reed-Solomon RS(255,223) Forward Error Correction**:
  - Losslessly auto-repairs up to 16 bytes of bit-rot / packet corruption per 255-byte block.
* **100% Air-Gapped & Zero-Telemetry**:
  - Zero server dependencies, zero external CDNs, 100% browser-memory cryptographic execution.

---

## 🚀 Quick Start (Windows)

### 1-Click Instant Launch:
* Double-click **`start.bat`** in the root directory.
* Automatically launches the local gateway on `http://localhost:3000`.

### Production Preview:
* Double-click **`start-preview.bat`** to run the compiled production bundle on `http://localhost:4173`.

### Terminal Execution:
```bash
# Development server
npm run dev

# Production build
npm run build

# Preview production build
npm run preview
```

---

## 🧪 Comprehensive Verification & Audit Test Suites

ContentGuard Pro MAX is verified by **17 automated test suites comprising 172 deterministic assertions (100% passing)**:

```bash
# 1. Native Windows Comprehensive Forensic & Security Audit
npm run test:audit

# 2. Real-World Live Browser Automation Test (Chrome CDP)
npm run test:browser

# 3. Cryptographic Primitives Adversarial Suite (18 tests)
npm run test:crypto

# 4. Red-Team Remediation & Forensic Verification Suite (9 tests)
npm run test:redteam

# 5. Dual-Vault Protection & Extraction Suite (10 tests)
npm run test:protect

# 6. Reed-Solomon Error Correction Capacity Suite (10 tests)
npm run test:rs

# 7. MP4 Carrier Steganography Suite (10 tests)
npm run test:stego

# 8. Full Regression Suite
npm test
```

---

## 📜 Assurance & Compliance Dossier

Full cryptographic mathematical proofs, Landauer thermodynamic limits, forensic stego tables, and regulatory compliance mappings (FINRA 17a-4, HIPAA, GDPR Art. 32, NIST SP 800-88) are documented in [`COMMERCIAL_REGULATORY_SECURITY_DOSSIER.md`](./COMMERCIAL_REGULATORY_SECURITY_DOSSIER.md).

---

## ⚖️ License & Attribution

Internal Release v1.0.1 — Proprietary & Confidential.