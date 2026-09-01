import { expect } from "chai";
import hre from "hardhat";

import { Reverter } from "@test-helpers";

import type { SchnorrVerifier } from "@ethers-v6";

import { schnorr } from "@noble/curves/secp256k1.js";

type Bip340Vector = {
  index: number;
  secretKey?: string;
  auxRand?: string;
  publicKeyX: string;
  messageHash: string;
  signature: string;
};

const OFFICIAL_VECTOR_1: Bip340Vector = {
  index: 1,
  secretKey: "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
  auxRand: "0000000000000000000000000000000000000000000000000000000000000001",
  publicKeyX: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
  messageHash: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
  signature:
    "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
};

const OFFICIAL_VECTOR_3: Bip340Vector = {
  index: 3,
  secretKey: "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
  auxRand: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
  publicKeyX: "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
  messageHash: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
  signature:
    "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
};

const SECP256K1_SCALAR_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_FIELD_PRIME = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;

// This odd-key-branch signature was accepted by both verifier paths before parity
// hardening. It satisfies sG - eP_odd = R, but is outside BIP340 because x-only keys
// always select the even-y public key point.
const ODD_PUBLIC_KEY_BRANCH_VECTOR = {
  publicKeyX: 0xf9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9n,
  signatureScalar: 0x9f811eebb9ea784653b2b32c92059d4850781ebf42363e02972e9d62cacc95e9n,
  messageHash: "0x0000000000000000000000000000000000000000000000000000000000000000" as const,
  nonceX: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  nonceY: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
};

const { ethers, networkHelpers } = await hre.network.connect();

function withHexPrefix(value: string): `0x${string}` {
  return (value.startsWith("0x") ? value : `0x${value}`) as `0x${string}`;
}

function hexToBytes(value: string): Uint8Array {
  return ethers.getBytes(withHexPrefix(value));
}

function hexToBigInt(value: string): bigint {
  return BigInt(withHexPrefix(value));
}

function compactHex(value: Uint8Array): string {
  return ethers.hexlify(value).slice(2).toUpperCase();
}

function splitSignature(signature: string): { nonceX: bigint; signatureScalar: bigint } {
  const normalizedSignature = signature.startsWith("0x") ? signature.slice(2) : signature;

  return {
    nonceX: hexToBigInt(normalizedSignature.slice(0, 64)),
    signatureScalar: hexToBigInt(normalizedSignature.slice(64)),
  };
}

function toVerifierInput(vector: Bip340Vector): {
  publicKeyX: bigint;
  signatureScalar: bigint;
  messageHash: `0x${string}`;
  nonceX: bigint;
} {
  const { nonceX, signatureScalar } = splitSignature(vector.signature);

  return {
    publicKeyX: hexToBigInt(vector.publicKeyX),
    signatureScalar,
    messageHash: withHexPrefix(vector.messageHash),
    nonceX,
  };
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let poweredBase = base % modulus;

  while (exponent > 0n) {
    if (exponent & 1n) result = (result * poweredBase) % modulus;
    poweredBase = (poweredBase * poweredBase) % modulus;
    exponent >>= 1n;
  }

  return result;
}

function liftXToEvenY(pointX: bigint): bigint {
  const curveEquationValue = (pointX * pointX * pointX + 7n) % SECP256K1_FIELD_PRIME;
  const candidateY = modPow(curveEquationValue, (SECP256K1_FIELD_PRIME + 1n) / 4n, SECP256K1_FIELD_PRIME);

  expect((candidateY * candidateY) % SECP256K1_FIELD_PRIME).to.equal(curveEquationValue);
  return candidateY % 2n === 0n ? candidateY : SECP256K1_FIELD_PRIME - candidateY;
}

describe("SchnorrVerifier", () => {
  const reverter: Reverter = new Reverter(networkHelpers);

  let verifier: SchnorrVerifier;

  before("setup", async () => {
    verifier = await ethers.deployContract("SchnorrVerifier");

    await reverter.snapshot();
  });

  afterEach(reverter.revert);

  describe("verify", () => {
    it("accepts official BIP340 test vector #3", async () => {
      const vector = toVerifierInput(OFFICIAL_VECTOR_3);

      expect(vector.publicKeyX < SECP256K1_SCALAR_ORDER).to.equal(true);
      expect(await verifier.verify(...(Object.values(vector) as any))).to.equal(true);
    });

    it("reproduces official BIP340 test vector #3 with @noble/curves", async () => {
      const secretKey = hexToBytes(OFFICIAL_VECTOR_3.secretKey!);
      const messageHash = hexToBytes(OFFICIAL_VECTOR_3.messageHash);
      const auxRand = hexToBytes(OFFICIAL_VECTOR_3.auxRand!);

      const publicKeyX = compactHex(schnorr.getPublicKey(secretKey));
      const signature = compactHex(schnorr.sign(messageHash, secretKey, auxRand));

      expect(publicKeyX).to.equal(OFFICIAL_VECTOR_3.publicKeyX);
      expect(signature).to.equal(OFFICIAL_VECTOR_3.signature);
      expect(await verifier.verify(...(Object.values(toVerifierInput(OFFICIAL_VECTOR_3)) as any))).to.equal(true);
    });

    it("rejects a valid odd-key-branch signature that the previous implementation accepted", async () => {
      const vector = ODD_PUBLIC_KEY_BRANCH_VECTOR;

      expect(
        await verifier.verify(vector.publicKeyX, vector.signatureScalar, vector.messageHash, vector.nonceX),
      ).to.equal(false);
    });

    it("accepts valid BIP340 signatures with publicKeyX in the upper half of [1, n-1]", async () => {
      const vector = toVerifierInput(OFFICIAL_VECTOR_1);

      expect(vector.publicKeyX > SECP256K1_SCALAR_ORDER / 2n).to.equal(true);
      expect(vector.publicKeyX < SECP256K1_SCALAR_ORDER).to.equal(true);
      expect(
        schnorr.verify(
          hexToBytes(OFFICIAL_VECTOR_1.signature),
          hexToBytes(OFFICIAL_VECTOR_1.messageHash),
          hexToBytes(OFFICIAL_VECTOR_1.publicKeyX),
        ),
      ).to.equal(true);
      expect(await verifier.verify(...(Object.values(vector) as any))).to.equal(true);
    });

    it("rejects publicKeyX values that do not fit the ECDSA r slot", async () => {
      const vector = toVerifierInput(OFFICIAL_VECTOR_3);

      expect(
        await verifier.verify(SECP256K1_SCALAR_ORDER, vector.signatureScalar, vector.messageHash, vector.nonceX),
      ).to.equal(false);
    });

    it("treats s = 0 as in-range and rejects only after cryptographic verification", async () => {
      const vector = toVerifierInput(OFFICIAL_VECTOR_3);
      const zeroScalarInput = { ...vector, signatureScalar: 0n };
      const outOfRangeInput = { ...vector, signatureScalar: SECP256K1_SCALAR_ORDER };

      expect(await verifier.verify(...(Object.values(zeroScalarInput) as any))).to.equal(false);
      expect(await verifier.verify(...(Object.values(outOfRangeInput) as any))).to.equal(false);

      const zeroScalarGas = await verifier.verify.estimateGas(...(Object.values(zeroScalarInput) as any));
      const outOfRangeGas = await verifier.verify.estimateGas(...(Object.values(outOfRangeInput) as any));
      expect(zeroScalarGas).to.be.greaterThan(outOfRangeGas);
    });

    it("accepts zero-message signatures, matching BIP340", async () => {
      const secretKey = hexToBytes(OFFICIAL_VECTOR_3.secretKey!);
      const zeroMessageHash = ethers.ZeroHash;
      const zeroMessageSignature = schnorr.sign(
        ethers.getBytes(zeroMessageHash),
        secretKey,
        hexToBytes(OFFICIAL_VECTOR_3.auxRand!),
      );
      const publicKeyX = compactHex(schnorr.getPublicKey(secretKey));
      const signature = splitSignature(compactHex(zeroMessageSignature));

      expect(schnorr.verify(zeroMessageSignature, ethers.getBytes(zeroMessageHash), hexToBytes(publicKeyX))).to.equal(
        true,
      );
      expect(
        await verifier.verify(hexToBigInt(publicKeyX), signature.signatureScalar, zeroMessageHash, signature.nonceX),
      ).to.equal(true);
    });
  });

  describe("verifyWithNonceY", () => {
    it("accepts a valid signature with its even nonce witness", async () => {
      const vector = toVerifierInput(OFFICIAL_VECTOR_3);
      const nonceY = liftXToEvenY(vector.nonceX);

      expect(await verifier.verifyWithNonceY(...(Object.values({ ...vector, nonceY }) as any))).to.equal(true);
    });

    it("rejects a valid odd-key-branch signature that the previous implementation accepted", async () => {
      expect(await verifier.verifyWithNonceY(...(Object.values(ODD_PUBLIC_KEY_BRANCH_VECTOR) as any))).to.equal(false);
    });

    it("rejects invalid nonce witnesses", async () => {
      const vector = toVerifierInput(OFFICIAL_VECTOR_3);
      const nonceY = liftXToEvenY(vector.nonceX);
      const verify = (candidateY: bigint) =>
        verifier.verifyWithNonceY(...(Object.values({ ...vector, nonceY: candidateY }) as any));

      expect(await verify(SECP256K1_FIELD_PRIME - nonceY)).to.equal(false);
      expect(await verify(nonceY + 2n)).to.equal(false);
      expect(await verify(SECP256K1_FIELD_PRIME)).to.equal(false);
      expect(await verify(2n ** 256n - 1n)).to.equal(false);
    });

    it("uses the BIP340 scalar range [0, n-1] on the witness path", async () => {
      const vector = toVerifierInput(OFFICIAL_VECTOR_3);
      const nonceY = liftXToEvenY(vector.nonceX);
      const zeroScalarInput = { ...vector, signatureScalar: 0n, nonceY };
      const outOfRangeInput = { ...vector, signatureScalar: SECP256K1_SCALAR_ORDER, nonceY };

      expect(await verifier.verifyWithNonceY(...(Object.values(zeroScalarInput) as any))).to.equal(false);
      expect(await verifier.verifyWithNonceY(...(Object.values(outOfRangeInput) as any))).to.equal(false);

      const zeroScalarGas = await verifier.verifyWithNonceY.estimateGas(...(Object.values(zeroScalarInput) as any));
      const outOfRangeGas = await verifier.verifyWithNonceY.estimateGas(...(Object.values(outOfRangeInput) as any));
      expect(zeroScalarGas).to.be.greaterThan(outOfRangeGas);
    });

    it("uses less gas than recovering the nonce y-coordinate on-chain", async () => {
      const vector = toVerifierInput(OFFICIAL_VECTOR_3);
      const nonceY = liftXToEvenY(vector.nonceX);
      const originalGas = await verifier.verify.estimateGas(...(Object.values(vector) as any));
      const witnessGas = await verifier.verifyWithNonceY.estimateGas(...(Object.values({ ...vector, nonceY }) as any));

      expect(originalGas - witnessGas).to.be.greaterThanOrEqual(3_900n);
    });
  });
});
