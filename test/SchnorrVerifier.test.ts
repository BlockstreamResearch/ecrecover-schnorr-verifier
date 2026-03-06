import { expect } from "chai";
import hre from "hardhat";

import { Reverter } from "@test-helpers";

import type { SchnorrVerifier } from "@ethers-v6";

import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";

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

const SECP256K1_HALF_SCALAR_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;

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

function toVerifierInput(
  vector: Bip340Vector,
  publicKeyYParity = 0,
): {
  publicKeyX: bigint;
  publicKeyYParity: number;
  signatureScalar: bigint;
  messageHash: `0x${string}`;
  nonceX: bigint;
} {
  const { nonceX, signatureScalar } = splitSignature(vector.signature);

  return {
    publicKeyX: hexToBigInt(vector.publicKeyX),
    publicKeyYParity,
    signatureScalar,
    messageHash: withHexPrefix(vector.messageHash),
    nonceX,
  };
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

      expect(vector.publicKeyX <= SECP256K1_HALF_SCALAR_ORDER).to.equal(true);
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

    it("rejects the official signature when publicKeyYParity is odd", async () => {
      const vector = toVerifierInput(OFFICIAL_VECTOR_3, 1);
      const compressedPublicKeyPrefix = secp256k1.getPublicKey(hexToBytes(OFFICIAL_VECTOR_3.secretKey!), true)[0];

      expect(compressedPublicKeyPrefix).to.equal(0x03);
      expect(await verifier.verify(...(Object.values(vector) as any))).to.equal(false);
    });

    it("rejects valid BIP340 signatures outside the adapted low-x domain", async () => {
      const vector = toVerifierInput(OFFICIAL_VECTOR_1);

      expect(vector.publicKeyX > SECP256K1_HALF_SCALAR_ORDER).to.equal(true);
      expect(
        schnorr.verify(
          hexToBytes(OFFICIAL_VECTOR_1.signature),
          hexToBytes(OFFICIAL_VECTOR_1.messageHash),
          hexToBytes(OFFICIAL_VECTOR_1.publicKeyX),
        ),
      ).to.equal(true);
      expect(await verifier.verify(...(Object.values(vector) as any))).to.equal(false);
    });

    it("rejects zero-message signatures even when BIP340 verification succeeds off-chain", async () => {
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
        await verifier.verify(hexToBigInt(publicKeyX), 0, signature.signatureScalar, zeroMessageHash, signature.nonceX),
      ).to.equal(false);
    });
  });
});
