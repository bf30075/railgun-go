#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { brotliDecompressSync } from 'node:zlib';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

const RAILGUN_ENGINE_REPO = 'https://github.com/Railgun-Community/engine.git';
const RAILGUN_ENGINE_COMMIT = 'e2913b39e13f82f43556d23705fa20d2ece2e8ab';

const outArg = process.argv.indexOf('--out');
const outPath = outArg >= 0 ? resolve(process.argv[outArg + 1]) : undefined;
const artifactsOutArg = process.argv.indexOf('--artifacts-out');
const artifactsOutPath = artifactsOutArg >= 0 ? resolve(process.argv[artifactsOutArg + 1]) : undefined;

const workDir = mkdtempSync(join(tmpdir(), 'railgun-go-fixtures-'));
const engineDir = join(workDir, 'engine');

run('git', ['clone', '--depth', '1', RAILGUN_ENGINE_REPO, engineDir]);
run('git', ['fetch', '--depth', '1', 'origin', RAILGUN_ENGINE_COMMIT], engineDir);
run('git', ['checkout', RAILGUN_ENGINE_COMMIT], engineDir);
run('yarn', ['install', '--frozen-lockfile'], engineDir);

const exporterPath = join(engineDir, 'railgun-go-export-fixtures.ts');
writeFileSync(exporterPath, `
import TestVectorPOI from './src/test/test-vector-poi.json';
import crypto from 'crypto';
import { Interface } from 'ethers';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { ByteLength, ByteUtils } from './src/utils/bytes';
import { ZERO_ADDRESS } from './src/utils/constants';
import {
  ABIPoseidonMerkleAccumulator,
  ABIPoseidonMerkleVerifier,
  ABIRailgunSmartWallet,
  ABIRelayAdapt,
} from './src/abi/abi';
import { TokenType } from './src/models/formatted-types';
import { OutputType } from './src/models/formatted-types';
import { TXIDVersion } from './src/models/poi-types';
import { BlindedCommitment } from './src/poi/blinded-commitment';
import { POI } from './src/poi';
import { Prover } from './src/prover/prover';
import { ShieldNote } from './src/note/shield-note';
import { ShieldNoteERC20 } from './src/note/erc20/shield-note-erc20';
import { UnshieldNote } from './src/note/unshield-note';
import { UnshieldNoteERC20 } from './src/note/erc20/unshield-note-erc20';
import { UnshieldNoteNFT } from './src/note/nft/unshield-note-nft';
import { TransactNote } from './src/note/transact-note';
import { Memo } from './src/note/memo';
import { Transaction } from './src/transaction/transaction';
import { TransactionBatch } from './src/transaction/transaction-batch';
import { V2Events } from './src/contracts/railgun-smart-wallet/V2/V2-events';
import { V3Events } from './src/contracts/railgun-smart-wallet/V3/V3-events';
import { RelayAdaptV2Contract } from './src/contracts/relay-adapt/V2/relay-adapt-v2';
import { RelayAdaptHelper } from './src/contracts/relay-adapt/relay-adapt-helper';
import WalletInfo from './src/wallet/wallet-info';
import { findExactSolutionsOverTargetValue } from './src/solutions/simple-solutions';
import { createSpendingSolutionsForValue } from './src/solutions/complex-solutions';
import { calculateTotalSpend } from './src/solutions/utxos';
import {
  getNoteHash,
  getTokenDataERC20,
  getTokenDataHash,
  getTokenDataNFT,
  serializeTokenData,
} from './src/note/note-util';
import { deriveNodes, WalletNode } from './src/key-derivation/wallet-node';
import { decodeAddress, encodeAddress } from './src/key-derivation/bech32';
import { Mnemonic } from './src/key-derivation/bip39';
import {
  addChainSupportsV3,
  assertChainSupportsV3,
  getChainFullNetworkID,
  getChainSupportsV3,
} from './src/chain/chain';
import {
  getGlobalTreePosition,
  getGlobalTreePositionPreTransactionPOIProof,
} from './src/poi/global-tree-position';
import { poseidon } from './src/utils/poseidon';
import { createDummyMerkleProof, verifyMerkleProof } from './src/merkletree/merkle-proof';
import {
  calculateRailgunTransactionVerificationHash,
  getRailgunTransactionIDFromBigInts,
  getRailgunTransactionIDHex,
  getRailgunTxidLeafHash,
} from './src/transaction/railgun-txid';
import { hashBoundParamsV2, hashBoundParamsV3 } from './src/transaction/bound-params';
import {
  extractFirstNoteERC20AmountMapFromTransactionRequest,
  extractRailgunTransactionDataFromTransactionRequest,
} from './src/validation/extract-transaction-data';
import { POIValidation } from './src/validation/poi-validation';
import { AES } from './src/utils/encryption/aes';
import { XChaCha20 } from './src/utils/encryption/x-cha-cha-20';
import {
  getPublicSpendingKey,
  getPublicViewingKey,
  getPrivateScalarFromPrivateKey,
  getNoteBlindingKeys,
  getSharedSymmetricKey,
  signEDDSA,
  signED25519,
  verifyEDDSA,
  verifyED25519,
  unblindNoteKey,
} from './src/utils/keys-utils';
import {
  getSharedSymmetricKeyLegacy,
  getNoteBlindingKeysLegacy,
  unblindNoteKeyLegacy,
} from './src/utils/keys-utils-legacy';
const snarkjs = require('snarkjs');
const { getArtifactsPOI } = require('./src/test/test-artifacts-lite');
const railgunFixtures = [
  [1, 2],
  [1, 3],
  [2, 2],
  [2, 3],
  [8, 2],
].map(([inputs, outputs]) => {
  const publicInputs = {
    merkleRoot: 1n,
    boundParamsHash: 2n,
    nullifiers: Array.from({ length: inputs }, (_, i) => BigInt(i + 3)),
    commitmentsOut: Array.from({ length: outputs }, (_, i) => BigInt(i + 100)),
  };
  const privateInputs = {
    tokenAddress: 200n,
    publicKey: [201n, 202n],
    randomIn: Array.from({ length: inputs }, (_, i) => BigInt(i + 300)),
    valueIn: Array.from({ length: inputs }, (_, i) => BigInt(i + 400)),
    pathElements: Array.from({ length: inputs }, (_, i) => [BigInt(i + 500)]),
    leavesIndices: Array.from({ length: inputs }, (_, i) => BigInt(i)),
    nullifyingKey: 600n,
    npkOut: Array.from({ length: outputs }, (_, i) => BigInt(i + 700)),
    valueOut: Array.from({ length: outputs }, (_, i) => BigInt(i + 800)),
  };
  const raw = {
    publicInputs,
    privateInputs,
    signature: [900n, 901n, 902n],
  };
  const formatted = (Prover as any).formatRailgunInputs(raw);
  return {
    name: \`\${inputs}x\${outputs}\`,
    raw: JSON.parse(JSON.stringify(raw, bigintReplacer)),
    expected: JSON.parse(JSON.stringify(formatted, bigintReplacer)),
  };
});

const poi3x3 = {
  name: 'poi-3x3',
  raw: TestVectorPOI,
  formatted: JSON.parse(JSON.stringify((Prover as any).formatPOIInputs(TestVectorPOI, 3, 3), bigintReplacer)),
};
const poi13x13 = {
  name: 'poi-13x13',
  raw: TestVectorPOI,
  formatted: JSON.parse(JSON.stringify((Prover as any).formatPOIInputs(TestVectorPOI, 13, 13), bigintReplacer)),
};

async function main() {
  const transactNoteFixtures = await buildTransactNoteFixtures();
  const preTransactionPOIFixtures = buildPreTransactionPOIFixtures();
  const output = JSON.stringify({
    source: {
      repo: '${RAILGUN_ENGINE_REPO}',
      commit: '${RAILGUN_ENGINE_COMMIT}',
    },
    railgunFixtures,
    poiFixtures: [poi3x3, poi13x13],
    cryptoFixtures: await buildCryptoFixtures(),
    encryptionFixtures: buildEncryptionFixtures(),
    memoFixtures: buildMemoFixtures(),
    unshieldNoteFixtures: buildUnshieldNoteFixtures(),
    transactNoteFixtures,
    addressFixtures: buildAddressFixtures(),
    walletFixtures: await buildWalletFixtures(),
    chainFixtures: buildChainFixtures(),
    txidFixtures: buildTxidFixtures(),
    boundParamsFixtures: buildBoundParamsFixtures(),
    commitmentCiphertextFixtures: buildCommitmentCiphertextFixtures(transactNoteFixtures),
    spendingSolutionFixtures: buildSpendingSolutionFixtures(),
    transactionRequestFixtures: await buildTransactionRequestFixtures(),
    dummyBatchFixtures: await buildDummyBatchFixtures(),
    relayAdaptFixtures: await buildRelayAdaptFixtures(),
    preTransactionPOIFixtures,
    poiValidationFixtures: await buildPOIValidationFixtures(preTransactionPOIFixtures[0]),
    transactionStructFixtures: buildTransactionStructFixtures(),
    shieldFixtures: await buildShieldFixtures(),
    calldataFixtures: buildCalldataFixtures(),
    eventFixtures: await buildEventFixtures(),
    merkleFixtures: buildMerkleFixtures(),
    proofFixtures: await buildProofFixtures(),
    witnessFixtures: await buildWitnessFixtures(),
  }, bigintReplacer, 2);
  await new Promise<void>((resolve, reject) => {
    process.stdout.write(output + '\\n', (error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

async function buildCryptoFixtures() {
  const privateKeyHex = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  const privateKey = ByteUtils.hexStringToBytes(privateKeyHex);
  const poseidonMessage = poseidon([1n, 2n]);
  const spendingPublicKey = getPublicSpendingKey(privateKey);
  const poseidonSignature = signEDDSA(privateKey, poseidonMessage);
  const viewingPublicKey = await getPublicViewingKey(privateKey);
  const ed25519Message = Buffer.from('railgun', 'utf8');
  const ed25519Signature = await signED25519(ed25519Message, privateKey);
  const privateScalar = await getPrivateScalarFromPrivateKey(privateKey);
  const sharedSymmetricKey = await getSharedSymmetricKey(privateKey, viewingPublicKey);
  if (!sharedSymmetricKey) {
    throw new Error('Expected shared symmetric key fixture');
  }
  const receiverPrivateKeyHex = '1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100';
  const receiverPrivateKey = ByteUtils.hexStringToBytes(receiverPrivateKeyHex);
  const receiverViewingPublicKey = await getPublicViewingKey(receiverPrivateKey);
  const sharedRandom = '00112233445566778899aabbccddeeff';
  const senderRandom = '0102030405060708090a0b0c0d0e0f';
  const noteBlindingKeys = getNoteBlindingKeys(
    viewingPublicKey,
    receiverViewingPublicKey,
    sharedRandom,
    senderRandom,
  );
  const legacySharedSymmetricKey = await getSharedSymmetricKeyLegacy(privateKey, viewingPublicKey);
  if (!legacySharedSymmetricKey) {
    throw new Error('Expected legacy shared symmetric key fixture');
  }
  const legacyNoteBlindingKeys = getNoteBlindingKeysLegacy(
    viewingPublicKey,
    receiverViewingPublicKey,
    sharedRandom,
    senderRandom,
  );
  const unblindedSenderViewingKey = unblindNoteKey(
    noteBlindingKeys.blindedSenderViewingKey,
    sharedRandom,
    senderRandom,
  );
  if (!unblindedSenderViewingKey) {
    throw new Error('Expected unblinded sender viewing key fixture');
  }
  const legacyUnblindedSenderViewingKey = unblindNoteKeyLegacy(
    legacyNoteBlindingKeys[0],
    sharedRandom,
    senderRandom,
  );
  const legacyUnblindedReceiverViewingKey = unblindNoteKeyLegacy(
    legacyNoteBlindingKeys[1],
    sharedRandom,
    senderRandom,
  );
  if (!legacyUnblindedSenderViewingKey || !legacyUnblindedReceiverViewingKey) {
    throw new Error('Expected legacy unblinded viewing key fixtures');
  }

  const poiSpendingPublicKey: [bigint, bigint] = [
    BigInt(TestVectorPOI.spendingPublicKey[0]),
    BigInt(TestVectorPOI.spendingPublicKey[1]),
  ];
  const poiNullifyingKey = BigInt(TestVectorPOI.nullifyingKey);
  const poiNotePosition = TestVectorPOI.utxoPositionsIn[0];
  const poiMasterPublicKey = WalletNode.getMasterPublicKey(poiSpendingPublicKey, poiNullifyingKey);
  const poiNotePublicKey = ShieldNote.getNotePublicKey(poiMasterPublicKey, TestVectorPOI.randomsIn[0]);
  const poiShieldCommitment = ShieldNote.getShieldNoteHash(
    poiNotePublicKey,
    TestVectorPOI.token,
    BigInt(TestVectorPOI.valuesIn[0]),
  );
  const poiShieldCommitmentHex = ByteUtils.nToHex(poiShieldCommitment, ByteLength.UINT_256);
  const poiBlindedCommitment = BlindedCommitment.getForShieldOrTransact(
    poiShieldCommitmentHex,
    poiNotePublicKey,
    getGlobalTreePosition(0, poiNotePosition),
  );

  return {
    poseidonVectors: [
      { name: 'zero one', inputs: ['0', '1'], output: poseidon([0n, 1n]).toString() },
      { name: 'one two', inputs: ['1', '2'], output: poseidonMessage.toString() },
      { name: 'one two three four', inputs: ['1', '2', '3', '4'], output: poseidon([1n, 2n, 3n, 4n]).toString() },
    ],
    keyVector: {
      privateKey: privateKeyHex,
      poseidonMessage: poseidonMessage.toString(),
      spendingPublicKey: spendingPublicKey.map((value) => value.toString()),
      poseidonSignature: JSON.parse(JSON.stringify(poseidonSignature, bigintReplacer)),
      poseidonSignatureVerified: verifyEDDSA(poseidonMessage, poseidonSignature, spendingPublicKey),
      publicViewingKey: ByteUtils.fastBytesToHex(viewingPublicKey),
      privateScalar: privateScalar.toString(),
      sharedSymmetricKey: ByteUtils.fastBytesToHex(sharedSymmetricKey),
      ed25519Message: ByteUtils.fastBytesToHex(ed25519Message),
      ed25519Signature: ByteUtils.fastBytesToHex(ed25519Signature),
      ed25519SignatureVerified: await verifyED25519(ed25519Message, ed25519Signature, viewingPublicKey),
      noteBlinding: {
        receiverPrivateKey: receiverPrivateKeyHex,
        receiverViewingPublicKey: ByteUtils.fastBytesToHex(receiverViewingPublicKey),
        sharedRandom,
        senderRandom,
        blindedSenderViewingKey: ByteUtils.fastBytesToHex(noteBlindingKeys.blindedSenderViewingKey),
        blindedReceiverViewingKey: ByteUtils.fastBytesToHex(noteBlindingKeys.blindedReceiverViewingKey),
        unblindedSenderViewingKey: ByteUtils.fastBytesToHex(unblindedSenderViewingKey),
      },
      legacyNoteBlinding: {
        receiverPrivateKey: receiverPrivateKeyHex,
        receiverViewingPublicKey: ByteUtils.fastBytesToHex(receiverViewingPublicKey),
        sharedRandom,
        senderRandom,
        sharedSymmetricKey: ByteUtils.fastBytesToHex(legacySharedSymmetricKey),
        blindedSenderViewingKey: ByteUtils.fastBytesToHex(legacyNoteBlindingKeys[0]),
        blindedReceiverViewingKey: ByteUtils.fastBytesToHex(legacyNoteBlindingKeys[1]),
        unblindedSenderViewingKey: ByteUtils.fastBytesToHex(legacyUnblindedSenderViewingKey),
        unblindedReceiverViewingKey: ByteUtils.fastBytesToHex(legacyUnblindedReceiverViewingKey),
      },
    },
    tokenVectors: buildTokenVectors(),
    poiReference: {
      spendingPublicKey: poiSpendingPublicKey.map((value) => value.toString()),
      nullifyingKey: poiNullifyingKey.toString(),
      random: TestVectorPOI.randomsIn[0],
      token: TestVectorPOI.token,
      value: TestVectorPOI.valuesIn[0],
      notePosition: poiNotePosition,
      globalTreePosition: getGlobalTreePosition(0, poiNotePosition).toString(),
      masterPublicKey: poiMasterPublicKey.toString(),
      notePublicKey: poiNotePublicKey.toString(),
      shieldCommitment: poiShieldCommitment.toString(),
      shieldCommitmentHex: poiShieldCommitmentHex,
      blindedCommitment: poiBlindedCommitment,
      nullifier: TransactNote.getNullifier(poiNullifyingKey, poiNotePosition).toString(),
      nullifierHex: ByteUtils.nToHex(TransactNote.getNullifier(poiNullifyingKey, poiNotePosition), ByteLength.UINT_256),
      tokenDataHashERC20: TestVectorPOI.token,
    },
  };
}

function buildEncryptionFixtures() {
  const key = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  const gcmIV = '202122232425262728292a2b2c2d2e2f';
  const ctrIV = '303132333435363738393a3b3c3d3e3f';
  const xChaChaNonce = '404142434445464748494a4b4c4d4e4f';
  const xChaChaPoly1305Nonce = '505152535455565758595a5b5c5d5e5f';
  const gcmPlaintext = [
    '00112233445566778899aabbccddeeff',
    '0102030405060708090a0b0c0d0e0f00',
    'abcdef',
  ];
  const ctrPlaintext = [
    '11223344556677889900aabbccddeeff',
    'f0e0d0c0b0a090807060504030201000',
    '1234567890',
  ];
  const xChaChaPlaintext = '00112233445566778899aabbccddeeff0102030405060708';
  const xChaChaPoly1305Plaintext = 'abcdef0123456789ff00112233445566778899';
  const originalGetRandomIV = AES.getRandomIV;
  const originalGetRandomXChaChaIV = XChaCha20.getRandomIV;
  try {
    AES.getRandomIV = () => gcmIV;
    const gcmCiphertext = AES.encryptGCM(gcmPlaintext, key);
    AES.getRandomIV = () => ctrIV;
    const ctrCiphertext = AES.encryptCTR(ctrPlaintext, key);
    XChaCha20.getRandomIV = () => xChaChaNonce;
    const xChaChaCiphertext = XChaCha20.encryptChaCha20(
      xChaChaPlaintext,
      ByteUtils.fastHexToBytes(key),
    );
    XChaCha20.getRandomIV = () => xChaChaPoly1305Nonce;
    const xChaChaPoly1305Ciphertext = XChaCha20.encryptChaCha20Poly1305(
      xChaChaPoly1305Plaintext,
      ByteUtils.fastHexToBytes(key),
    );
    return {
      aesGCM: {
        key,
        iv: gcmIV,
        plaintext: gcmPlaintext,
        ciphertext: gcmCiphertext,
        decrypted: AES.decryptGCM(gcmCiphertext, key),
      },
      aesCTR: {
        key,
        iv: ctrIV,
        plaintext: ctrPlaintext,
        ciphertext: ctrCiphertext,
        decrypted: AES.decryptCTR(ctrCiphertext, key),
      },
      xChaCha20: {
        key,
        nonce: xChaChaNonce,
        plaintext: xChaChaPlaintext,
        ciphertext: xChaChaCiphertext,
        decrypted: XChaCha20.decryptChaCha20(xChaChaCiphertext, ByteUtils.fastHexToBytes(key)),
      },
      xChaCha20Poly1305: {
        key,
        nonce: xChaChaPoly1305Nonce,
        plaintext: xChaChaPoly1305Plaintext,
        ciphertext: xChaChaPoly1305Ciphertext,
        decrypted: XChaCha20.decryptChaCha20Poly1305(
          xChaChaPoly1305Ciphertext,
          ByteUtils.fastHexToBytes(key),
        ),
      },
    };
  } finally {
    AES.getRandomIV = originalGetRandomIV;
    XChaCha20.getRandomIV = originalGetRandomXChaChaIV;
  }
}

function buildMemoFixtures() {
  const viewingPrivateKey = '1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30';
  const walletSource = 'Memo Wallet';
  const senderRandom = '0102030405060708090a0b0c0d0e0f';
  const v2IV = '808182838485868788898a8b8c8d8e8f';
  const v3Nonce = '909192939495969798999a9b9c9d9e9f';
  const originalAESGetRandomIV = AES.getRandomIV;
  const originalXChaChaGetRandomIV = XChaCha20.getRandomIV;
  try {
    AES.getRandomIV = () => v2IV;
    XChaCha20.getRandomIV = () => v3Nonce;
    return {
      walletSource,
      encodedWalletSource: '0x' + WalletInfoEncoded(walletSource),
      senderRandom,
      viewingPrivateKey,
      v2IV,
      v2AnnotationData: Memo.createEncryptedNoteAnnotationDataV2(
        OutputType.BroadcasterFee,
        senderRandom,
        walletSource,
        ByteUtils.hexStringToBytes(viewingPrivateKey),
      ),
      v3Nonce,
      v3AnnotationData: Memo.createSenderAnnotationEncryptedV3(
        walletSource,
        [OutputType.Transfer, OutputType.Change],
        ByteUtils.hexStringToBytes(viewingPrivateKey),
      ),
      memoText: {
        input: 'hello railgun',
        encoded: Memo.encodeMemoText('hello railgun'),
      },
    };
  } finally {
    AES.getRandomIV = originalAESGetRandomIV;
    XChaCha20.getRandomIV = originalXChaChaGetRandomIV;
  }
}

async function buildTransactNoteFixtures() {
  const receiverMasterPublicKey = 123456789n;
  const senderMasterPublicKey = 987654321n;
  const receiverViewingPublicKey = ByteUtils.hexStringToBytes(
    '03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8',
  );
  const senderViewingPublicKey = ByteUtils.hexStringToBytes(
    '712651f450ba05b63898b99ef5f7ba45632e8e2527f7f715cd671ec4024cc51e',
  );
  const receiverAddressData = {
    masterPublicKey: receiverMasterPublicKey,
    viewingPublicKey: receiverViewingPublicKey,
  };
  const senderAddressData = {
    masterPublicKey: senderMasterPublicKey,
    viewingPublicKey: senderViewingPublicKey,
  };
  const tokenData = getTokenDataERC20(TestVectorPOI.token);
  const random = '101112131415161718191a1b1c1d1e1f';
  const value = 7654321n;
  const senderRandom = '0102030405060708090a0b0c0d0e0f';
  const sharedKey = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  const viewingPrivateKey = '1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30';
  const walletSource = 'tester';
  const outputType = OutputType.BroadcasterFee;
  const memoText = 'railgun memo';
  const noteCiphertextV2IV = 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf';
  const annotationV2IV = 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf';
  const noteCiphertextV3Nonce = 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf';
  const annotationV3Nonce = 'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf';
  const originalAESGetRandomIV = AES.getRandomIV;
  const originalXChaChaGetRandomIV = XChaCha20.getRandomIV;
  try {
    const note = new (TransactNote as any)(
      receiverAddressData,
      senderAddressData,
      random,
      value,
      tokenData,
      outputType,
      walletSource,
      senderRandom,
      memoText,
      undefined,
      undefined,
    );
    const aesIVs = [noteCiphertextV2IV, annotationV2IV];
    AES.getRandomIV = () => {
      const iv = aesIVs.shift();
      if (!iv) throw new Error('Missing deterministic transact V2 IV');
      return iv;
    };
    const v2 = note.encryptV2(
      TXIDVersion.V2_PoseidonMerkle,
      ByteUtils.hexStringToBytes(sharedKey),
      senderMasterPublicKey,
      senderRandom,
      ByteUtils.hexStringToBytes(viewingPrivateKey),
    );
    const xChaChaIVs = [noteCiphertextV3Nonce, annotationV3Nonce];
    XChaCha20.getRandomIV = () => {
      const iv = xChaChaIVs.shift();
      if (!iv) throw new Error('Missing deterministic transact V3 nonce');
      return iv;
    };
    const v3NoteCiphertext = note.encryptV3(
      TXIDVersion.V3_PoseidonMerkle,
      ByteUtils.hexStringToBytes(sharedKey),
      senderMasterPublicKey,
    );
    const orderedOutputTypes = [OutputType.BroadcasterFee, OutputType.Change];
    const v3AnnotationData = Memo.createSenderAnnotationEncryptedV3(
      walletSource,
      orderedOutputTypes,
      ByteUtils.hexStringToBytes(viewingPrivateKey),
    );
    const noteBlindingKeys = getNoteBlindingKeys(
      senderViewingPublicKey,
      receiverViewingPublicKey,
      random,
      senderRandom,
    );
    const sharedKeyBytes = ByteUtils.hexStringToBytes(sharedKey);
    const viewingPrivateKeyBytes = ByteUtils.hexStringToBytes(viewingPrivateKey);
    const chain = { type: 0, id: 1 };
    const expectedTokenHash = getTokenDataHash(tokenData);
    const tokenDataGetter = {
      getTokenDataFromHash: async (_txidVersion: unknown, _chain: unknown, tokenHash: string) => {
        const formattedTokenHash = ByteUtils.formatToByteLength(
          tokenHash,
          ByteLength.UINT_256,
          false,
        );
        if (formattedTokenHash !== expectedTokenHash) {
          throw new Error('Unexpected token hash ' + formattedTokenHash);
        }
        return tokenData;
      },
    };
    const snapshotNote = (decryptedNote: any) =>
      JSON.parse(JSON.stringify({
        receiverMasterPublicKey: decryptedNote.receiverAddressData.masterPublicKey.toString(),
        receiverViewingPublicKey: ByteUtils.fastBytesToHex(
          decryptedNote.receiverAddressData.viewingPublicKey,
        ),
        senderMasterPublicKey: decryptedNote.senderAddressData?.masterPublicKey.toString(),
        senderViewingPublicKey: decryptedNote.senderAddressData
          ? ByteUtils.fastBytesToHex(decryptedNote.senderAddressData.viewingPublicKey)
          : undefined,
        tokenHash: decryptedNote.tokenHash,
        tokenData: decryptedNote.tokenData,
        random: decryptedNote.random,
        value: decryptedNote.value.toString(),
        notePublicKey: decryptedNote.notePublicKey.toString(),
        hash: decryptedNote.hash.toString(),
        outputType: decryptedNote.outputType,
        walletSource: decryptedNote.walletSource,
        senderRandom: decryptedNote.senderRandom,
        memoText: decryptedNote.memoText,
        serialized: decryptedNote.serialize(false),
      }, bigintReplacer));
    const v2Sent = await TransactNote.decrypt(
      TXIDVersion.V2_PoseidonMerkle,
      chain,
      senderAddressData,
      v2.noteCiphertext,
      sharedKeyBytes,
      v2.noteMemo,
      v2.annotationData,
      viewingPrivateKeyBytes,
      noteBlindingKeys.blindedReceiverViewingKey,
      noteBlindingKeys.blindedSenderViewingKey,
      true,
      false,
      tokenDataGetter as any,
      undefined,
      undefined,
    );
    const v2Received = await TransactNote.decrypt(
      TXIDVersion.V2_PoseidonMerkle,
      chain,
      receiverAddressData,
      v2.noteCiphertext,
      sharedKeyBytes,
      v2.noteMemo,
      v2.annotationData,
      viewingPrivateKeyBytes,
      noteBlindingKeys.blindedReceiverViewingKey,
      noteBlindingKeys.blindedSenderViewingKey,
      false,
      false,
      tokenDataGetter as any,
      undefined,
      undefined,
    );
    const v3Sent = await TransactNote.decrypt(
      TXIDVersion.V3_PoseidonMerkle,
      chain,
      senderAddressData,
      v3NoteCiphertext,
      sharedKeyBytes,
      '',
      v3AnnotationData,
      viewingPrivateKeyBytes,
      noteBlindingKeys.blindedReceiverViewingKey,
      noteBlindingKeys.blindedSenderViewingKey,
      true,
      false,
      tokenDataGetter as any,
      undefined,
      0,
    );
    const v3Received = await TransactNote.decrypt(
      TXIDVersion.V3_PoseidonMerkle,
      chain,
      receiverAddressData,
      v3NoteCiphertext,
      sharedKeyBytes,
      '',
      v3AnnotationData,
      viewingPrivateKeyBytes,
      noteBlindingKeys.blindedReceiverViewingKey,
      noteBlindingKeys.blindedSenderViewingKey,
      false,
      false,
      tokenDataGetter as any,
      undefined,
      0,
    );
    return {
      inputs: {
        receiverMasterPublicKey: receiverMasterPublicKey.toString(),
        senderMasterPublicKey: senderMasterPublicKey.toString(),
        receiverViewingPublicKey: ByteUtils.fastBytesToHex(receiverViewingPublicKey),
        senderViewingPublicKey: ByteUtils.fastBytesToHex(senderViewingPublicKey),
        tokenData,
        random,
        value: value.toString(),
        senderRandom,
        sharedKey,
        viewingPrivateKey,
        outputType,
        walletSource,
        memoText,
        noteCiphertextV2IV,
        annotationV2IV,
        noteCiphertextV3Nonce,
        annotationV3Nonce,
        orderedOutputTypes,
      },
      v2: JSON.parse(JSON.stringify(v2, bigintReplacer)),
      v3: {
        noteCiphertext: v3NoteCiphertext,
        annotationData: v3AnnotationData,
      },
      noteBlinding: {
        blindedSenderViewingKey: ByteUtils.fastBytesToHex(noteBlindingKeys.blindedSenderViewingKey),
        blindedReceiverViewingKey: ByteUtils.fastBytesToHex(
          noteBlindingKeys.blindedReceiverViewingKey,
        ),
      },
      decrypted: {
        v2Sent: snapshotNote(v2Sent),
        v2Received: snapshotNote(v2Received),
        v3Sent: snapshotNote(v3Sent),
        v3Received: snapshotNote(v3Received),
      },
    };
  } finally {
    AES.getRandomIV = originalAESGetRandomIV;
    XChaCha20.getRandomIV = originalXChaChaGetRandomIV;
  }
}

function buildAddressFixtures() {
  const vectors = [
    {
      name: 'evm-mainnet-zero',
      pubkey: '00000000',
      chain: { type: 0, id: 1 },
    },
    {
      name: 'evm-bsc',
      pubkey: '01bfd5681c0479be9a8ef8dd8baadd97115899a9af30b3d2455843afb41b',
      chain: { type: 0, id: 56 },
    },
    {
      name: 'custom-chain-type',
      pubkey: '01bfd5681c0479be9a8ef8dd8baadd97115899a9af30b3d2455843afb41b',
      chain: { type: 1, id: 56 },
    },
    {
      name: 'all-chains',
      pubkey: 'ee6b4c702f8070c8ddea1cbb8b0f6a4a518b77fa8d3f9b68617b664550e75f64',
      chain: undefined,
    },
  ];
  return vectors.map((vector) => {
    const addressData = {
      masterPublicKey: ByteUtils.hexToBigInt(vector.pubkey),
      viewingPublicKey: ByteUtils.hexStringToBytes(
        ByteUtils.formatToByteLength(vector.pubkey, ByteLength.UINT_256, false),
      ),
      chain: vector.chain,
      version: 1,
    };
    const encoded = encodeAddress(addressData);
    const decoded = decodeAddress(encoded);
    return {
      name: vector.name,
      addressData: JSON.parse(JSON.stringify(addressData, bigintReplacer)),
      encoded,
      decoded: {
        masterPublicKey: decoded.masterPublicKey.toString(),
        viewingPublicKey: ByteUtils.fastBytesToHex(decoded.viewingPublicKey),
        chain: decoded.chain,
        version: decoded.version,
      },
    };
  });
}

async function buildWalletFixtures() {
  const mnemonicVectors = [
    {
      mnemonic:
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      entropy: '00000000000000000000000000000000',
      seed: '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4',
    },
    {
      mnemonic:
        'mammal step public march absorb critic visa rent miss color erase exhaust south lift ordinary ceiling stay physical',
      entropy: '86baaeb443e00c67bd2db28dc5b531a7bd0302e71127d4f4',
      seed: 'd8c228addf9a9cfe5b7934223737815e2f709b3ac12b0c1b2aaec921e5d3a2e8aeea1df817af8159f981798dacd5a930a1fcd8570ba4845078c1b1d09fa060cb',
    },
    {
      mnemonic:
        'culture flower sunny seat maximum begin design magnet side permit coin dial alter insect whisper series desk power cream afford regular strike poem ostrich',
      entropy: '358b3365e12896288ef42fc7f464b59e8076ea3ea6203bf528cb823b4dae29c4',
      seed: '243c1266228fc9ff370d567ba4f805dfacc516375aecf4657cf870a4b551020d92d9b45a8181154f531c1358f742f42078a1620fca6251b1c4ec5fa6e1cf5c3a',
    },
    {
      mnemonic:
        'culture flower sunny seat maximum begin design magnet side permit coin dial alter insect whisper series desk power cream afford regular strike poem ostrich',
      password: 'test',
      entropy: '358b3365e12896288ef42fc7f464b59e8076ea3ea6203bf528cb823b4dae29c4',
      seed: '87ec3e2ae9294cb5500698e6e6ee8357aa56222badae0e6b4150492c95ede7ddfca27c952afafb388453def93fac72f5d7e099debd79e85c2088f9b3e7a65df6',
    },
  ];
  const vectors = [
    {
      name: 'abandon-0',
      mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      path: "m/0'",
    },
    {
      name: 'abandon-0-1',
      mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      path: "m/0'/1'",
    },
    {
      name: 'culture-custom',
      mnemonic:
        'culture flower sunny seat maximum begin design magnet side permit coin dial alter insect whisper series desk power cream afford regular strike poem ostrich',
      path: "m/1984'/0'/1'/1'",
    },
  ];
  const derived = [];
  for (const vector of vectors) {
    const node = WalletNode.fromMnemonic(vector.mnemonic).derive(vector.path);
    const spending = node.getSpendingKeyPair();
    const viewing = await node.getViewingKeyPair();
    derived.push({
      name: vector.name,
      mnemonic: vector.mnemonic,
      path: vector.path,
      spendingKeyPair: {
        privateKey: ByteUtils.fastBytesToHex(spending.privateKey),
        pubkey: spending.pubkey.map((value) => value.toString()),
      },
      viewingKeyPair: {
        privateKey: ByteUtils.fastBytesToHex(viewing.privateKey),
        pubkey: ByteUtils.fastBytesToHex(viewing.pubkey),
      },
      nullifyingKey: (await node.getNullifyingKey()).toString(),
    });
  }

  const indexedNodes = deriveNodes(vectors[0].mnemonic, 0);
  const indexedSpending = indexedNodes.spending.getSpendingKeyPair();
  const indexedViewing = await indexedNodes.viewing.getViewingKeyPair();
  const indexedNullifyingKey = await indexedNodes.viewing.getNullifyingKey();
  const indexedMasterPublicKey = WalletNode.getMasterPublicKey(
    indexedSpending.pubkey,
    indexedNullifyingKey,
  );
  const indexedAddress = encodeAddress({
    masterPublicKey: indexedMasterPublicKey,
    viewingPublicKey: indexedViewing.pubkey,
  });

  return {
    mnemonic: {
      valid: mnemonicVectors.map((vector) => ({
        ...vector,
        entropyFromMnemonic: Mnemonic.toEntropy(vector.mnemonic),
        mnemonicFromEntropy: Mnemonic.fromEntropy(vector.entropy),
        seedFromMnemonic: Mnemonic.toSeed(vector.mnemonic, vector.password ?? ''),
        valid: Mnemonic.validate(vector.mnemonic),
      })),
      invalid: [
        "Why, sometimes I've believed as many as six impossible things before breakfast.",
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon',
        'chicken',
      ].map((mnemonic) => ({
        mnemonic,
        valid: Mnemonic.validate(mnemonic),
      })),
      evm: [
        { name: 'abandon-0', mnemonic: mnemonicVectors[0].mnemonic, index: 0 },
        { name: 'abandon-1', mnemonic: mnemonicVectors[0].mnemonic, index: 1 },
        { name: 'culture-0', mnemonic: mnemonicVectors[2].mnemonic, index: 0 },
      ].map((vector) => ({
        ...vector,
        privateKey: Mnemonic.to0xPrivateKey(vector.mnemonic, vector.index),
        address: Mnemonic.to0xAddress(vector.mnemonic, vector.index),
      })),
    },
    derived,
    indexed: {
      mnemonic: vectors[0].mnemonic,
      index: 0,
      spendingPublicKey: indexedSpending.pubkey.map((value) => value.toString()),
      viewingPublicKey: ByteUtils.fastBytesToHex(indexedViewing.pubkey),
      nullifyingKey: indexedNullifyingKey.toString(),
      masterPublicKey: indexedMasterPublicKey.toString(),
      address: indexedAddress,
    },
  };
}

function buildChainFixtures() {
  const chains = [
    { name: 'ethereum-mainnet', chain: { type: 0, id: 1 } },
    { name: 'polygon', chain: { type: 0, id: 137 } },
    { name: 'hardhat', chain: { type: 0, id: 31337 } },
    { name: 'non-evm-type', chain: { type: 7, id: 6500 } },
  ];
  const supported = { type: 0, id: 31337 };
  const unsupported = { type: 0, id: 1 };
  let assertUnsupportedError = '';
  try {
    assertChainSupportsV3(unsupported);
  } catch (err) {
    assertUnsupportedError = (err as Error).message;
  }
  const beforeAdd = getChainSupportsV3(supported);
  addChainSupportsV3(supported);
  return {
    fullNetworkIDs: chains.map((fixture) => ({
      ...fixture,
      fullNetworkID: getChainFullNetworkID(fixture.chain),
    })),
    supportsV3: {
      supported,
      unsupported,
      beforeAdd,
      afterAdd: getChainSupportsV3(supported),
      unsupportedAfterAdd: getChainSupportsV3(unsupported),
      assertUnsupportedError,
    },
  };
}

function WalletInfoEncoded(walletSource: string) {
  const charset = ' 0123456789abcdefghijklmnopqrstuvwxyz';
  const lower = walletSource.toLowerCase();
  let outputNumber = 0n;
  const base = BigInt(charset.length);
  for (let i = 0; i < lower.length; i += 1) {
    const charIndex = charset.indexOf(lower[i]);
    if (charIndex === -1) throw new Error('Invalid character for wallet source: ' + lower[i]);
    outputNumber += BigInt(charIndex) * base ** BigInt(lower.length - i - 1);
  }
  const outputHex = outputNumber.toString(16);
  return outputHex.length % 2 ? outputHex : '0' + outputHex;
}

function buildTokenVectors() {
  const erc20 = getTokenDataERC20(TestVectorPOI.token);
  const erc721 = getTokenDataNFT('0x1111111111111111111111111111111111111111', TokenType.ERC721, '12345');
  const erc1155 = getTokenDataNFT('0x2222222222222222222222222222222222222222', TokenType.ERC1155, '0xabcdef');
  const serializedERC1155 = serializeTokenData(
    '0x0000000000000000000000002222222222222222222222222222222222222222',
    TokenType.ERC1155,
    BigInt('0xabcdef'),
  );
  const notePublicKey = ByteUtils.nToHex(123456789n, ByteLength.UINT_256, true);
  const transferValue = 987654321n;

  return [
    {
      name: 'erc20',
      tokenData: erc20,
      tokenHash: getTokenDataHash(erc20),
      notePublicKey,
      value: transferValue.toString(),
      noteHash: getNoteHash(notePublicKey, erc20, transferValue).toString(),
    },
    {
      name: 'erc721',
      tokenData: erc721,
      tokenHash: getTokenDataHash(erc721),
      notePublicKey,
      value: '1',
      noteHash: getNoteHash(notePublicKey, erc721, 1n).toString(),
    },
    {
      name: 'erc1155',
      tokenData: erc1155,
      tokenHash: getTokenDataHash(erc1155),
      notePublicKey,
      value: transferValue.toString(),
      noteHash: getNoteHash(notePublicKey, erc1155, transferValue).toString(),
    },
    {
      name: 'serialized-erc1155',
      tokenData: serializedERC1155,
      tokenHash: getTokenDataHash(serializedERC1155),
      notePublicKey,
      value: transferValue.toString(),
      noteHash: getNoteHash(notePublicKey, serializedERC1155, transferValue).toString(),
    },
  ];
}

function buildUnshieldNoteFixtures() {
  const toAddress = '0x1111222233334444555566667777888899990000';
  const erc20 = new UnshieldNoteERC20(toAddress, 123456789n, TestVectorPOI.token, true);
  const erc721TokenData = getTokenDataNFT(
    '0x1111111111111111111111111111111111111111',
    TokenType.ERC721,
    '12345',
  );
  const erc721 = new UnshieldNoteNFT(toAddress, erc721TokenData, false);
  const erc1155TokenData = getTokenDataNFT(
    '0x2222222222222222222222222222222222222222',
    TokenType.ERC1155,
    '0xabcdef',
  );
  const erc1155 = new UnshieldNoteNFT(toAddress, erc1155TokenData, true);
  const empty = UnshieldNoteERC20.empty();
  const nativeUnshieldNote = (note: any) => ({
    toAddress: note.toAddress,
    value: note.value.toString(),
    tokenData: note.tokenData,
    hash: note.hash.toString(),
    hashHex: note.hashHex,
    allowOverride: note.allowOverride,
    npk: note.npk,
    notePublicKey: note.notePublicKey.toString(),
    unshieldData: {
      toAddress: note.unshieldData.toAddress,
      value: note.unshieldData.value.toString(),
      tokenData: note.unshieldData.tokenData,
      allowOverride: note.unshieldData.allowOverride,
    },
    serializeNoPrefix: note.serialize(false),
    serializePrefix: note.serialize(true),
    preImage: {
      npk: note.preImage.npk,
      token: note.preImage.token,
      value: note.preImage.value.toString(),
    },
  });
  return {
    notes: [
      { name: 'erc20', note: nativeUnshieldNote(erc20) },
      { name: 'erc721', note: nativeUnshieldNote(erc721) },
      { name: 'erc1155', note: nativeUnshieldNote(erc1155) },
      { name: 'empty-erc20', note: nativeUnshieldNote(empty) },
    ],
    amountFees: [
      { value: 1000000n, feeBasisPoints: 25n },
      { value: 999n, feeBasisPoints: 250n },
      { value: 1n, feeBasisPoints: 25n },
    ].map((input) => ({
      value: input.value.toString(),
      feeBasisPoints: input.feeBasisPoints.toString(),
      output: UnshieldNote.getAmountFeeFromValue(input.value, input.feeBasisPoints),
    })),
  };
}

function buildTxidFixtures() {
  const railgunTxid = getRailgunTransactionIDHex({
    nullifiers: TestVectorPOI.nullifiers,
    commitments: TestVectorPOI.commitmentsOut,
    boundParamsHash: TestVectorPOI.boundParamsHash,
  });
  const utxoTreeIn = BigInt(TestVectorPOI.utxoTreeIn);
  const utxoTreeOut = 0;
  const utxoBatchStartPositionOut = Number(TestVectorPOI.utxoBatchGlobalStartPositionOut);
  const globalTreePosition = getGlobalTreePosition(utxoTreeOut, utxoBatchStartPositionOut);
  const leafHash = getRailgunTxidLeafHash(ByteUtils.hexToBigInt(railgunTxid), utxoTreeIn, globalTreePosition);

  return {
    poiTransaction: {
      nullifiers: TestVectorPOI.nullifiers,
      commitments: TestVectorPOI.commitmentsOut,
      boundParamsHash: TestVectorPOI.boundParamsHash,
      railgunTxid,
      railgunTxidDecimal: BigInt(TestVectorPOI.railgunTxidIfHasUnshield).toString(),
      utxoTreeIn: TestVectorPOI.utxoTreeIn,
      utxoTreeOut,
      utxoBatchStartPositionOut,
      globalTreePosition: globalTreePosition.toString(),
      leafHash,
    },
    globalTreePositions: [
      { tree: 0, index: 0, output: getGlobalTreePosition(0, 0).toString() },
      { tree: 1, index: 0, output: getGlobalTreePosition(1, 0).toString() },
      { tree: 14, index: 6500, output: getGlobalTreePosition(14, 6500).toString() },
    ],
    verificationHash: {
      previousVerificationHash: '',
      firstNullifier: TestVectorPOI.nullifiers[0],
      output: calculateRailgunTransactionVerificationHash(undefined, TestVectorPOI.nullifiers[0]),
    },
  };
}

function buildPreTransactionPOIFixtures() {
  const nullifiers = TestVectorPOI.nullifiers.map((value) => ByteUtils.hexToBigInt(value));
  const commitmentsOut = TestVectorPOI.commitmentsOut.map((value) => ByteUtils.hexToBigInt(value));
  const boundParamsHash = ByteUtils.hexToBigInt(TestVectorPOI.boundParamsHash);
  const publicInputs = {
    merkleRoot: 0n,
    boundParamsHash,
    nullifiers,
    commitmentsOut,
  };
  const privateInputs = {
    npkOut: TestVectorPOI.npksOut.map((value) => BigInt(value)),
    valueOut: TestVectorPOI.valuesOut.map((value) => BigInt(value)),
  };
  const globalTreePosition = getGlobalTreePositionPreTransactionPOIProof();
  const railgunTxidBigInt = getRailgunTransactionIDFromBigInts(
    nullifiers,
    commitmentsOut,
    boundParamsHash,
  );
  const txidLeafHash = getRailgunTxidLeafHash(
    railgunTxidBigInt,
    BigInt(TestVectorPOI.utxoTreeIn),
    globalTreePosition,
  );
  const txidMerkleProof = createDummyMerkleProof(txidLeafHash);
  const poiMerkleProofs = TestVectorPOI.blindedCommitmentsIn.map((blindedCommitment) =>
    createDummyMerkleProof(blindedCommitment),
  );
  const railgunTxidHex = ByteUtils.nToHex(railgunTxidBigInt, ByteLength.UINT_256);
  const railgunTxidIfHasUnshield = BlindedCommitment.getForUnshield(railgunTxidHex);
  const blindedCommitmentsOut: string[] = [];
  const proofInputs = {
    anyRailgunTxidMerklerootAfterTransaction: txidMerkleProof.root,
    boundParamsHash: ByteUtils.nToHex(boundParamsHash, ByteLength.UINT_256, true),
    nullifiers: nullifiers.map((value) => ByteUtils.nToHex(value, ByteLength.UINT_256, true)),
    commitmentsOut: commitmentsOut.map((value) => ByteUtils.nToHex(value, ByteLength.UINT_256, true)),
    spendingPublicKey: TestVectorPOI.spendingPublicKey.map((value) => BigInt(value)),
    nullifyingKey: BigInt(TestVectorPOI.nullifyingKey),
    token: TestVectorPOI.token,
    randomsIn: TestVectorPOI.randomsIn,
    valuesIn: TestVectorPOI.valuesIn.map((value) => BigInt(value)),
    utxoPositionsIn: TestVectorPOI.utxoPositionsIn,
    utxoTreeIn: TestVectorPOI.utxoTreeIn,
    npksOut: privateInputs.npkOut,
    valuesOut: privateInputs.valueOut,
    utxoBatchGlobalStartPositionOut: globalTreePosition,
    railgunTxidIfHasUnshield,
    railgunTxidMerkleProofIndices: txidMerkleProof.indices,
    railgunTxidMerkleProofPathElements: txidMerkleProof.elements,
    poiMerkleroots: poiMerkleProofs.map((merkleProof) => merkleProof.root),
    poiInMerkleProofIndices: poiMerkleProofs.map((merkleProof) => merkleProof.indices),
    poiInMerkleProofPathElements: poiMerkleProofs.map((merkleProof) => merkleProof.elements),
  };
  return [
    {
      name: 'test-vector-has-unshield',
      input: {
        publicInputs: nativePublicInputsRailgun(publicInputs),
        privateInputs: {
          npkOut: privateInputs.npkOut.map((value) => value.toString()),
          valueOut: privateInputs.valueOut.map((value) => value.toString()),
        },
        spendingPublicKey: TestVectorPOI.spendingPublicKey,
        nullifyingKey: TestVectorPOI.nullifyingKey,
        utxos: TestVectorPOI.blindedCommitmentsIn.map((blindedCommitment, index) => ({
          tree: String(TestVectorPOI.utxoTreeIn),
          position: String(TestVectorPOI.utxoPositionsIn[index]),
          tokenHash: TestVectorPOI.token,
          random: TestVectorPOI.randomsIn[index],
          value: String(TestVectorPOI.valuesIn[index]),
          blindedCommitment,
        })),
        poiMerkleProofs,
        treeNumber: String(TestVectorPOI.utxoTreeIn),
        hasUnshield: true,
      },
      prepared: {
        railgunTxid: ByteUtils.prefix0x(railgunTxidHex),
        txidLeafHash,
        txidMerkleRoot: txidMerkleProof.root,
        poiMerkleroots: poiMerkleProofs.map((merkleProof) => merkleProof.root),
        blindedCommitmentsIn: TestVectorPOI.blindedCommitmentsIn,
        blindedCommitmentsOut,
        railgunTxidIfHasUnshield,
        proofInputs,
        formatted: JSON.parse(JSON.stringify((Prover as any).formatPOIInputs(proofInputs, 3, 3), bigintReplacer)),
        txidMerkleProof,
        txidMerkleProofVerified: verifyMerkleProof(txidMerkleProof),
        poiMerkleProofsVerified: poiMerkleProofs.map((merkleProof) => verifyMerkleProof(merkleProof)),
      },
    },
  ];
}

async function buildPOIValidationFixtures(preTransactionPOIFixture: any) {
  const listKey = 'test_list';
  const chain = { type: 0, id: 31337 };
  const txidVersion = TXIDVersion.V2_PoseidonMerkle;
  const prepared = preTransactionPOIFixture.prepared;
  const snarkProof = buildSampleProof();
  const publicInputProver = new Prover({
    assertArtifactExists: () => undefined,
  } as any);
  const validProver = {
    getPublicInputsPOI: publicInputProver.getPublicInputsPOI.bind(publicInputProver),
    verifyPOIProof: async () => true,
  };
  const invalidProver = {
    getPublicInputsPOI: publicInputProver.getPublicInputsPOI.bind(publicInputProver),
    verifyPOIProof: async () => false,
  };
  const makePOIs = (overrides: any = {}) => ({
    [listKey]: {
      [prepared.txidLeafHash]: {
        snarkProof,
        txidMerkleroot: prepared.txidMerkleRoot,
        poiMerkleroots: prepared.poiMerkleroots,
        blindedCommitmentsOut: prepared.blindedCommitmentsOut,
        railgunTxidIfHasUnshield: prepared.railgunTxidIfHasUnshield,
        ...overrides,
      },
    },
  });
  const railgunTxids = [prepared.railgunTxid];
  const utxoTreesIn = [BigInt(preTransactionPOIFixture.input.treeNumber)];
  const originalValidator = (POIValidation as any).validatePOIMerkleroots;
  const captureError = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      return '';
    } catch (cause) {
      if (!(cause instanceof Error)) {
        throw cause;
      }
      return cause.message;
    }
  };

  try {
    (POIValidation as any).validatePOIMerkleroots = async () => true;
    const validResult = await POIValidation.assertIsValidSpendableTXID(
      txidVersion,
      listKey,
      chain,
      validProver as any,
      makePOIs(),
      railgunTxids,
      utxoTreesIn,
    );
    const missingList = await captureError(() =>
      POIValidation.assertIsValidSpendableTXID(
        txidVersion,
        listKey,
        chain,
        validProver as any,
        {},
        railgunTxids,
        utxoTreesIn,
      ),
    );
    const missingTxid = await captureError(() =>
      POIValidation.assertIsValidSpendableTXID(
        txidVersion,
        listKey,
        chain,
        validProver as any,
        { [listKey]: {} },
        railgunTxids,
        utxoTreesIn,
      ),
    );
    const invalidTxidMerkleProof = await captureError(() =>
      POIValidation.assertIsValidSpendableTXID(
        txidVersion,
        listKey,
        chain,
        validProver as any,
        makePOIs({ txidMerkleroot: ByteUtils.nToHex(0n, ByteLength.UINT_256) }),
        railgunTxids,
        utxoTreesIn,
      ),
    );
    (POIValidation as any).validatePOIMerkleroots = async () => false;
    const invalidPOIMerkleRoots = await captureError(() =>
      POIValidation.assertIsValidSpendableTXID(
        txidVersion,
        listKey,
        chain,
        validProver as any,
        makePOIs(),
        railgunTxids,
        utxoTreesIn,
      ),
    );
    (POIValidation as any).validatePOIMerkleroots = async () => true;
    const invalidProof = await captureError(() =>
      POIValidation.assertIsValidSpendableTXID(
        txidVersion,
        listKey,
        chain,
        invalidProver as any,
        makePOIs(),
        railgunTxids,
        utxoTreesIn,
      ),
    );

    return {
      listKey,
      railgunTxids,
      utxoTreesIn: utxoTreesIn.map((value) => value.toString()),
      preTransactionPOIs: makePOIs(),
      validResult,
      errors: {
        missingList,
        missingTxid,
        invalidTxidMerkleProof,
        invalidPOIMerkleRoots,
        invalidProof,
      },
    };
  } finally {
    (POIValidation as any).validatePOIMerkleroots = originalValidator;
  }
}

function buildBoundParamsFixtures() {
  const bytes32Zero = ByteUtils.formatToByteLength('00', ByteLength.UINT_256, true);
  const v2 = {
    treeNumber: 0n,
    minGasPrice: 3000n,
    unshield: 0n,
    chainID: 31337n,
    adaptContract: ByteUtils.formatToByteLength('00', ByteLength.Address, true),
    adaptParams: bytes32Zero,
    commitmentCiphertext: [
      {
        ciphertext: [bytes32Zero, bytes32Zero, bytes32Zero, bytes32Zero],
        blindedSenderViewingKey: bytes32Zero,
        blindedReceiverViewingKey: bytes32Zero,
        annotationData: ByteUtils.hexlify('00', true),
        memo: ByteUtils.hexlify('00', true),
      },
    ],
  };
  const v3 = {
    local: {
      treeNumber: 0n,
      commitmentCiphertext: [
        {
          ciphertext: \`0x\${[bytes32Zero, bytes32Zero, bytes32Zero, bytes32Zero].map(ByteUtils.strip0x).join('')}\`,
          blindedSenderViewingKey: bytes32Zero,
          blindedReceiverViewingKey: bytes32Zero,
        },
      ],
    },
    global: {
      minGasPrice: 1n,
      chainID: 31337n,
      senderCiphertext: '0x',
      to: ByteUtils.formatToByteLength('00', ByteLength.Address, true),
      data: '0x',
    },
  };

  return {
    v2: {
      boundParams: JSON.parse(JSON.stringify(v2, bigintReplacer)),
      hash: hashBoundParamsV2(v2).toString(),
      hashHex: ByteUtils.nToHex(hashBoundParamsV2(v2), ByteLength.UINT_256, true),
    },
    v3: {
      boundParams: JSON.parse(JSON.stringify(v3, bigintReplacer)),
      hash: hashBoundParamsV3(v3).toString(),
      hashHex: ByteUtils.nToHex(hashBoundParamsV3(v3), ByteLength.UINT_256, true),
    },
  };
}

function buildCommitmentCiphertextFixtures(transactNote: any) {
  const senderViewingPublicKey = ByteUtils.hexStringToBytes(
    '03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8',
  );
  const receiverViewingPublicKey = ByteUtils.hexStringToBytes(
    '712651f450ba05b63898b99ef5f7ba45632e8e2527f7f715cd671ec4024cc51e',
  );
  const sharedRandom = '00112233445566778899aabbccddeeff';
  const senderRandom = '0102030405060708090a0b0c0d0e0f';
  const noteBlindingKeys = getNoteBlindingKeys(
    senderViewingPublicKey,
    receiverViewingPublicKey,
    sharedRandom,
    senderRandom,
  );
  return {
    blinding: {
      senderViewingPublicKey: ByteUtils.fastBytesToHex(senderViewingPublicKey),
      receiverViewingPublicKey: ByteUtils.fastBytesToHex(receiverViewingPublicKey),
      sharedRandom,
      senderRandom,
      blindedSenderViewingKey: ByteUtils.fastBytesToHex(noteBlindingKeys.blindedSenderViewingKey),
      blindedReceiverViewingKey: ByteUtils.fastBytesToHex(noteBlindingKeys.blindedReceiverViewingKey),
    },
    v2: {
      ciphertext: [
        ByteUtils.hexlify(
          transactNote.v2.noteCiphertext.iv + transactNote.v2.noteCiphertext.tag,
          true,
        ),
        ...transactNote.v2.noteCiphertext.data.map((data) => ByteUtils.hexlify(data, true)),
      ],
      blindedSenderViewingKey: ByteUtils.hexlify(noteBlindingKeys.blindedSenderViewingKey, true),
      blindedReceiverViewingKey: ByteUtils.hexlify(noteBlindingKeys.blindedReceiverViewingKey, true),
      annotationData: ByteUtils.hexlify(transactNote.v2.annotationData, true),
      memo: ByteUtils.hexlify(transactNote.v2.noteMemo, true),
    },
    v3: {
      ciphertext: ByteUtils.prefix0x(
        transactNote.v3.noteCiphertext.nonce + transactNote.v3.noteCiphertext.bundle,
      ),
      blindedSenderViewingKey: ByteUtils.hexlify(noteBlindingKeys.blindedSenderViewingKey, true),
      blindedReceiverViewingKey: ByteUtils.hexlify(noteBlindingKeys.blindedReceiverViewingKey, true),
    },
  };
}

function buildSpendingSolutionFixtures() {
  const tokenData = getTokenDataERC20(TestVectorPOI.token);
  const walletAddressData = {
    masterPublicKey: 12345678901234567890n,
    viewingPublicKey: ByteUtils.hexStringToBytes(
      '03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8',
    ),
  };
  const makeNote = (value: bigint, random: string) =>
    new (TransactNote as any)(
      walletAddressData,
      undefined,
      random,
      value,
      tokenData,
      OutputType.Transfer,
      'tester',
      '000000000000000000000000000000',
      undefined,
      undefined,
      undefined,
    );
  const makeTXO = (id: string, value: bigint, position: number, random: string) => ({
    tree: 0,
    position,
    txid: ByteUtils.nToHex(BigInt(position + 100), ByteLength.UINT_256, true),
    timestamp: undefined,
    blockNumber: 1,
    spendtxid: false,
    nullifier: ByteUtils.nToHex(BigInt(position + 200), ByteLength.UINT_256, true),
    note: makeNote(value, random),
    poisPerList: undefined,
    blindedCommitment: undefined,
    commitmentType: 'TransactCommitmentV2',
    transactCreationRailgunTxid: undefined,
    id,
  });
  const simpleTXOs = [
    makeTXO('small', 25n, 1, '00000000000000000000000000000001'),
    makeTXO('exact', 65n, 2, '00000000000000000000000000000002'),
    makeTXO('large', 90n, 3, '00000000000000000000000000000003'),
  ];
  const simpleTreeBalance = {
    balance: calculateTotalSpend(simpleTXOs),
    utxos: simpleTXOs,
    tokenData,
  };
  const exact = findExactSolutionsOverTargetValue(simpleTreeBalance as any, 65n);
  const simpleGroup = (TransactionBatch as any).createSimpleSatisfyingUTXOGroup(
    [simpleTreeBalance],
    100n,
  );

  const complexTXOs = [
    makeTXO('a', 40n, 11, '00000000000000000000000000000011'),
    makeTXO('b', 50n, 12, '00000000000000000000000000000012'),
    makeTXO('c', 70n, 13, '00000000000000000000000000000013'),
  ];
  const complexTreeBalance = {
    balance: calculateTotalSpend(complexTXOs),
    utxos: complexTXOs,
    tokenData,
  };
  const originalGetNoteRandom = TransactNote.getNoteRandom;
  const originalWalletSource = WalletInfo.walletSource;
  try {
    const processingRandoms = [
      '11111111111111111111111111111111',
      '22222222222222222222222222222222',
    ];
    TransactNote.getNoteRandom = () => {
      const random = processingRandoms.shift();
      if (!random) throw new Error('Missing deterministic processing note random');
      return random;
    };
    const remainingOutputs = [
      makeNote(100n, '00000000000000000000000000000100'),
      makeNote(30n, '00000000000000000000000000000030'),
    ];
    const excluded: string[] = [];
    const complexGroups = createSpendingSolutionsForValue(
      [complexTreeBalance],
      remainingOutputs,
      excluded,
      false,
    );
    WalletInfo.setWalletSource('tester');
    TransactNote.getNoteRandom = () => '33333333333333333333333333333333';
    const changeOutput = TransactionBatch.getChangeOutput(
      { addressKeys: walletAddressData } as any,
      complexGroups[0],
    );
    return {
      inputs: {
        tokenData,
        walletAddressData: {
          masterPublicKey: walletAddressData.masterPublicKey.toString(),
          viewingPublicKey: ByteUtils.fastBytesToHex(walletAddressData.viewingPublicKey),
        },
        simpleTreeBalance: nativeTreeBalance(simpleTreeBalance),
        simpleRequired: '100',
        complexTreeBalance: nativeTreeBalance(complexTreeBalance),
        complexOutputs: [
          { id: 'primary', value: '100' },
          { id: 'secondary', value: '30' },
        ],
        changeRandom: '33333333333333333333333333333333',
        walletSource: 'tester',
      },
      exact: nativeTXOs(exact ?? []),
      simpleGroup: nativeSimpleUTXOGroup(simpleGroup),
      complexGroups: complexGroups.map(nativeSpendingSolutionGroup),
      complexExcluded: [...excluded],
      complexRemainingOutputs: remainingOutputs.map(nativeSolutionOutput),
      changeOutput: changeOutput ? nativeTransactNoteSummary(changeOutput) : undefined,
    };
  } finally {
    TransactNote.getNoteRandom = originalGetNoteRandom;
    WalletInfo.walletSource = originalWalletSource;
  }
}

function nativeTreeBalance(treeBalance: any) {
  return {
    balance: treeBalance.balance.toString(),
    utxos: nativeTXOs(treeBalance.utxos),
  };
}

function nativeSimpleUTXOGroup(group: any) {
  return {
    spendingTree: String(group.spendingTree),
    amount: group.amount.toString(),
    utxos: nativeTXOs(group.utxos),
  };
}

function nativeSpendingSolutionGroup(group: any) {
  return {
    spendingTree: String(group.spendingTree),
    utxos: nativeTXOs(group.utxos),
    tokenOutputs: group.tokenOutputs.map(nativeSolutionOutput),
    unshieldValue: group.unshieldValue.toString(),
    tokenData: group.tokenData,
  };
}

function nativeSolutionOutput(output: any) {
  return {
    value: output.value.toString(),
    tokenHash: output.tokenHash,
    random: output.random,
  };
}

function nativeTXOs(utxos: any[]) {
  return utxos.map((utxo) => ({
    id: utxo.id,
    txid: utxo.txid,
    tree: String(utxo.tree),
    position: String(utxo.position),
    value: utxo.note.value.toString(),
  }));
}

function nativeTransactNoteSummary(note: any) {
  return {
    random: note.random,
    value: note.value.toString(),
    tokenHash: note.tokenHash,
    notePublicKey: note.notePublicKey.toString(),
    hash: note.hash.toString(),
    outputType: note.outputType,
    walletSource: note.walletSource,
    senderRandom: note.senderRandom,
    recipientMasterPublicKey: note.receiverAddressData.masterPublicKey.toString(),
    recipientViewingPublicKey: ByteUtils.fastBytesToHex(note.receiverAddressData.viewingPublicKey),
  };
}

async function buildTransactionRequestFixtures() {
  const chain = { type: 0, id: 31337 };
  const spendingTree = 0;
  const tokenData = getTokenDataERC20(TestVectorPOI.token);
  const spendingPrivateKey = ByteUtils.hexStringToBytes(
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  );
  const spendingPublicKey = getPublicSpendingKey(spendingPrivateKey);
  const nullifyingKey = 1234567890123456789n;
  const senderMasterPublicKey = WalletNode.getMasterPublicKey(spendingPublicKey, nullifyingKey);
  const senderViewingPrivateKey = ByteUtils.hexStringToBytes(
    '1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30',
  );
  const senderViewingPublicKey = await getPublicViewingKey(senderViewingPrivateKey);
  const receiverViewingPrivateKey = ByteUtils.hexStringToBytes(
    '3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50',
  );
  const receiverViewingPublicKey = await getPublicViewingKey(receiverViewingPrivateKey);
  const receiverAddressData = {
    masterPublicKey: 9876543210123456789n,
    viewingPublicKey: receiverViewingPublicKey,
  };
  const senderAddressData = {
    masterPublicKey: senderMasterPublicKey,
    viewingPublicKey: senderViewingPublicKey,
  };
  const utxoNote = new (TransactNote as any)(
    senderAddressData,
    undefined,
    '00112233445566778899aabbccddeeff',
    123450000n,
    tokenData,
    OutputType.Transfer,
    'tester',
    '000000000000000000000000000000',
    undefined,
    undefined,
    undefined,
  );
  const outputNote = new (TransactNote as any)(
    receiverAddressData,
    senderAddressData,
    '102132435465768798a9babbdcddedef',
    100000000n,
    tokenData,
    OutputType.Transfer,
    'tester',
    '0102030405060708090a0b0c0d0e0f',
    'request memo',
    undefined,
    undefined,
  );
  const merkleRoot = ByteUtils.nToHex(555555555n, ByteLength.UINT_256, true);
  const merkleProofElements = [
    ByteUtils.nToHex(111n, ByteLength.UINT_256, true),
    ByteUtils.nToHex(222n, ByteLength.UINT_256, true),
  ];
  const utxo = {
    tree: spendingTree,
    position: 7,
    txid: '0x00',
    timestamp: undefined,
    blockNumber: 1,
    spendtxid: false,
    nullifier: '0x00',
    note: utxoNote,
    poisPerList: undefined,
    blindedCommitment: undefined,
    commitmentType: 'TransactCommitmentV2',
    transactCreationRailgunTxid: undefined,
  };
  const adaptID = {
    contract: ByteUtils.formatToByteLength('00', ByteLength.Address, true),
    parameters: ByteUtils.formatToByteLength('00', ByteLength.UINT_256, true),
  };
  const globalBoundParams = {
    minGasPrice: 3000n,
    chainID: 31337n,
    senderCiphertext: '0x',
    to: ByteUtils.formatToByteLength('00', ByteLength.Address, true),
    data: '0x',
  };
  const fakeMerkletree = {
    getRoot: async (_tree: number) => merkleRoot,
    getMerkleProof: async (_tree: number, _position: number) => ({
      elements: merkleProofElements,
      indices: '0',
      leaf: '0',
      root: merkleRoot,
    }),
  };
  const fakeWallet = {
    addressKeys: {
      masterPublicKey: senderMasterPublicKey,
    },
    viewingKeyPair: {
      privateKey: senderViewingPrivateKey,
      pubkey: senderViewingPublicKey,
    },
    getUTXOMerkletree: () => fakeMerkletree,
    getSpendingKeyPair: async (_encryptionKey: string) => ({
      privateKey: spendingPrivateKey,
      pubkey: spendingPublicKey,
    }),
    getNullifyingKey: () => nullifyingKey,
    getViewingKeyPair: () => ({
      privateKey: senderViewingPrivateKey,
      pubkey: senderViewingPublicKey,
    }),
  };
  const tx = new (Transaction as any)(
    chain,
    tokenData,
    spendingTree,
    [utxo],
    [outputNote],
    adaptID,
  );
  const v2NoteCiphertextIV = '202122232425262728292a2b2c2d2e2f';
  const v2AnnotationIV = '303132333435363738393a3b3c3d3e3f';
  const v3NoteCiphertextNonce = '404142434445464748494a4b4c4d4e4f';
  const originalAESGetRandomIV = AES.getRandomIV;
  const originalXChaChaGetRandomIV = XChaCha20.getRandomIV;
  try {
    const aesIVs = [v2NoteCiphertextIV, v2AnnotationIV];
    AES.getRandomIV = () => {
      const iv = aesIVs.shift();
      if (!iv) throw new Error('Missing deterministic request V2 IV');
      return iv;
    };
    const v2 = await tx.generateTransactionRequest(
      fakeWallet,
      TXIDVersion.V2_PoseidonMerkle,
      'unused',
      globalBoundParams,
    );
    XChaCha20.getRandomIV = () => v3NoteCiphertextNonce;
    const v3 = await tx.generateTransactionRequest(
      fakeWallet,
      TXIDVersion.V3_PoseidonMerkle,
      'unused',
      globalBoundParams,
    );
    return {
      inputs: {
        chain,
        spendingTree: spendingTree.toString(),
        merkleRoot,
        merkleProofElements,
        tokenData,
        spendingPrivateKey: ByteUtils.fastBytesToHex(spendingPrivateKey),
        spendingPublicKey: spendingPublicKey.map((value) => value.toString()),
        nullifyingKey: nullifyingKey.toString(),
        senderMasterPublicKey: senderMasterPublicKey.toString(),
        senderViewingPrivateKey: ByteUtils.fastBytesToHex(senderViewingPrivateKey),
        senderViewingPublicKey: ByteUtils.fastBytesToHex(senderViewingPublicKey),
        receiverMasterPublicKey: receiverAddressData.masterPublicKey.toString(),
        receiverViewingPublicKey: ByteUtils.fastBytesToHex(receiverViewingPublicKey),
        utxos: [
          {
            position: utxo.position.toString(),
            noteRandom: utxoNote.random,
            noteValue: utxoNote.value.toString(),
          },
        ],
        outputs: [
          {
            random: outputNote.random,
            value: outputNote.value.toString(),
            senderRandom: outputNote.senderRandom,
            outputType: outputNote.outputType,
            walletSource: outputNote.walletSource,
            memoText: outputNote.memoText,
          },
        ],
        adaptID,
        minGasPrice: globalBoundParams.minGasPrice.toString(),
        globalBoundParams: nativeGlobalBoundParamsV3(globalBoundParams),
        v2NoteCiphertextIV,
        v2AnnotationIV,
        v3NoteCiphertextNonce,
      },
      v2: nativeTransactionRequest(v2),
      v3: nativeTransactionRequest(v3),
      signatures: {
        v2: nativeRailgunSignature(spendingPrivateKey, v2.publicInputs),
        v3: nativeRailgunSignature(spendingPrivateKey, v3.publicInputs),
      },
      dummyV2: nativeTransactionStruct((Transaction as any).createTransactionStructV2(
        TXIDVersion.V2_PoseidonMerkle,
        zeroProof(),
        v2.publicInputs,
        v2.boundParams,
        emptyUnshieldPreimage(),
      )),
      dummyV3: nativeTransactionStruct((Transaction as any).createTransactionStructV3(
        TXIDVersion.V3_PoseidonMerkle,
        zeroProof(),
        v3.publicInputs,
        v3.boundParams,
        emptyUnshieldPreimage(),
      )),
    };
  } finally {
    AES.getRandomIV = originalAESGetRandomIV;
    XChaCha20.getRandomIV = originalXChaChaGetRandomIV;
  }
}

async function buildDummyBatchFixtures() {
  const chain = { type: 0, id: 31337 };
  const spendingTree = 0;
  const overallBatchMinGasPrice = 3000n;
  const tokenData = getTokenDataERC20(TestVectorPOI.token);
  const spendingPrivateKey = ByteUtils.hexStringToBytes(
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  );
  const spendingPublicKey = getPublicSpendingKey(spendingPrivateKey);
  const nullifyingKey = 1234567890123456789n;
  const senderMasterPublicKey = WalletNode.getMasterPublicKey(spendingPublicKey, nullifyingKey);
  const senderViewingPrivateKey = ByteUtils.hexStringToBytes(
    '1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30',
  );
  const senderViewingPublicKey = await getPublicViewingKey(senderViewingPrivateKey);
  const receiverViewingPrivateKey = ByteUtils.hexStringToBytes(
    '3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50',
  );
  const receiverViewingPublicKey = await getPublicViewingKey(receiverViewingPrivateKey);
  const senderAddressData = {
    masterPublicKey: senderMasterPublicKey,
    viewingPublicKey: senderViewingPublicKey,
  };
  const receiverAddressData = {
    masterPublicKey: 9876543210123456789n,
    viewingPublicKey: receiverViewingPublicKey,
  };
  const utxoNote = new (TransactNote as any)(
    senderAddressData,
    undefined,
    '00112233445566778899aabbccddeeff',
    123450000n,
    tokenData,
    OutputType.Transfer,
    'tester',
    '000000000000000000000000000000',
    undefined,
    undefined,
    undefined,
  );
  const outputNote = new (TransactNote as any)(
    receiverAddressData,
    senderAddressData,
    '102132435465768798a9babbdcddedef',
    100000000n,
    tokenData,
    OutputType.Transfer,
    'tester',
    '0102030405060708090a0b0c0d0e0f',
    'batch memo',
    undefined,
    undefined,
  );
  const merkleRoot = ByteUtils.nToHex(555555555n, ByteLength.UINT_256, true);
  const merkleProofElements = [
    ByteUtils.nToHex(111n, ByteLength.UINT_256, true),
    ByteUtils.nToHex(222n, ByteLength.UINT_256, true),
  ];
  const utxo = {
    tree: spendingTree,
    position: 7,
    txid: '0x00',
    timestamp: undefined,
    blockNumber: 1,
    spendtxid: false,
    nullifier: '0x00',
    note: utxoNote,
    poisPerList: undefined,
    blindedCommitment: undefined,
    commitmentType: 'TransactCommitmentV2',
    transactCreationRailgunTxid: undefined,
  };
  const treeBalance = {
    balance: utxoNote.value,
    tokenData,
    utxos: [utxo],
  };
  const adaptID = {
    contract: ByteUtils.formatToByteLength('00', ByteLength.Address, true),
    parameters: ByteUtils.formatToByteLength('00', ByteLength.UINT_256, true),
  };
  const globalBoundParams = {
    minGasPrice: overallBatchMinGasPrice,
    chainID: BigInt(chain.id),
    senderCiphertext: '0x',
    to: ByteUtils.formatToByteLength('00', ByteLength.Address, true),
    data: '0x',
  };
  const fakeMerkletree = {
    getRoot: async (_tree: number) => merkleRoot,
    getMerkleProof: async (_tree: number, _position: number) => ({
      elements: merkleProofElements,
      indices: '0',
      leaf: '0',
      root: merkleRoot,
    }),
  };
  const fakeWallet = {
    addressKeys: senderAddressData,
    viewingKeyPair: {
      privateKey: senderViewingPrivateKey,
      pubkey: senderViewingPublicKey,
    },
    getUTXOMerkletree: () => fakeMerkletree,
    getSpendingKeyPair: async (_encryptionKey: string) => ({
      privateKey: spendingPrivateKey,
      pubkey: spendingPublicKey,
    }),
    getNullifyingKey: () => nullifyingKey,
    getViewingKeyPair: () => ({
      privateKey: senderViewingPrivateKey,
      pubkey: senderViewingPublicKey,
    }),
    balancesByTreeForToken: async () => [treeBalance],
  };
  const batch = new TransactionBatch(chain, overallBatchMinGasPrice);
  batch.setAdaptID(adaptID);
  batch.addOutput(outputNote);
  const prover = new Prover({
    assertArtifactExists: (_inputs: number, _outputs: number) => undefined,
  } as any);
  const changeRandom = '33333333333333333333333333333333';
  const v2NoteCiphertextIVs = [
    '202122232425262728292a2b2c2d2e2f',
    '404142434445464748494a4b4c4d4e4f',
  ];
  const v2AnnotationIVs = [
    '303132333435363738393a3b3c3d3e3f',
    '505152535455565758595a5b5c5d5e5f',
  ];
  const v3NoteCiphertextNonces = [
    '606162636465666768696a6b6c6d6e6f',
    '707172737475767778797a7b7c7d7e7f',
  ];
  const originalAESGetRandomIV = AES.getRandomIV;
  const originalXChaChaGetRandomIV = XChaCha20.getRandomIV;
  const originalGetNoteRandom = TransactNote.getNoteRandom;
  const originalWalletSource = WalletInfo.walletSource;
  try {
    POI.init([], { isRequired: async () => false } as any);
    WalletInfo.setWalletSource('tester');
    TransactNote.getNoteRandom = () => changeRandom;
    const resetV2IVs = () => {
      const aesIVs = [
        v2NoteCiphertextIVs[0],
        v2AnnotationIVs[0],
        v2NoteCiphertextIVs[1],
        v2AnnotationIVs[1],
      ];
      AES.getRandomIV = () => {
        const iv = aesIVs.shift();
        if (!iv) throw new Error('Missing deterministic dummy batch V2 IV');
        return iv;
      };
    };
    const resetV3IVs = () => {
      const xChaChaIVs = [...v3NoteCiphertextNonces];
      XChaCha20.getRandomIV = () => {
        const iv = xChaChaIVs.shift();
        if (!iv) throw new Error('Missing deterministic dummy batch V3 nonce');
        return iv;
      };
    };
    const generateUnproved = async (txidVersion: TXIDVersion) => {
      const spendingSolutionGroups = await (batch as any).generateValidSpendingSolutionGroupsAllOutputs(
        fakeWallet as any,
        txidVersion,
      );
      const unproved = [];
      for (const spendingSolutionGroup of spendingSolutionGroups) {
        const changeOutput = TransactionBatch.getChangeOutput(
          fakeWallet as any,
          spendingSolutionGroup,
        );
        const transaction = batch.generateTransactionForSpendingSolutionGroup(
          spendingSolutionGroup,
          changeOutput,
        );
        const request = await transaction.generateTransactionRequest(
          fakeWallet as any,
          txidVersion,
          'unused',
          globalBoundParams,
        );
        const signature = nativeRailgunSignature(spendingPrivateKey, request.publicInputs);
        unproved.push({
          request: nativeTransactionRequest(request),
          signature: [
            signature.signature.R8[0],
            signature.signature.R8[1],
            signature.signature.S,
          ].map((value) => value.toString()),
        });
      }
      return unproved;
    };
    resetV2IVs();
    const unprovedV2 = await generateUnproved(TXIDVersion.V2_PoseidonMerkle);
    resetV2IVs();
    const v2 = await batch.generateDummyTransactions(
      prover,
      fakeWallet as any,
      TXIDVersion.V2_PoseidonMerkle,
      'unused',
    );
    resetV3IVs();
    const unprovedV3 = await generateUnproved(TXIDVersion.V3_PoseidonMerkle);
    resetV3IVs();
    const v3 = await batch.generateDummyTransactions(
      prover,
      fakeWallet as any,
      TXIDVersion.V3_PoseidonMerkle,
      'unused',
    );
    const bytes32Zero = ByteUtils.formatToByteLength('00', ByteLength.UINT_256, true);
    const zeroUnshieldChangeCiphertext = {
      encryptedBundle: [bytes32Zero, bytes32Zero, bytes32Zero],
      shieldKey: bytes32Zero,
    };
    const v2Calldata = new Interface(ABIRailgunSmartWallet).encodeFunctionData('transact', [v2]);
    const relayActionData = {
      random: ByteUtils.prefix0x('44'.repeat(31)),
      requireSuccess: false,
      minGasLimit: 0n,
      calls: [],
    };
    const v2RelayCalldata = new Interface(ABIRelayAdapt).encodeFunctionData('relay', [
      v2,
      relayActionData,
    ]);
    const v3Calldata = new Interface(ABIPoseidonMerkleVerifier).encodeFunctionData('execute', [
      v3.map((transaction) => ({
        proof: transaction.proof,
        merkleRoot: transaction.merkleRoot,
        nullifiers: transaction.nullifiers,
        commitments: transaction.commitments,
        boundParams: transaction.boundParams.local,
        unshieldPreimage: transaction.unshieldPreimage,
      })),
      [],
      globalBoundParams,
      zeroUnshieldChangeCiphertext,
    ]);
    const contractAddress = '0x1111111111111111111111111111111111111111';
    const tokenDataGetter = {
      getTokenDataFromHash: async (_txidVersion: TXIDVersion, _chain: any, tokenHash: string) =>
        getTokenDataERC20(tokenHash),
    };
    const v2TransactionRequest = { to: contractAddress, data: v2Calldata, value: 0n };
    const v3TransactionRequest = { to: contractAddress, data: v3Calldata, value: 0n };
    const extractedV2 = await extractRailgunTransactionDataFromTransactionRequest(
      TXIDVersion.V2_PoseidonMerkle,
      chain,
      v2TransactionRequest as any,
      false,
      contractAddress,
      receiverViewingPrivateKey,
      receiverAddressData,
      tokenDataGetter as any,
    );
    const extractedV3 = await extractRailgunTransactionDataFromTransactionRequest(
      TXIDVersion.V3_PoseidonMerkle,
      chain,
      v3TransactionRequest as any,
      false,
      contractAddress,
      receiverViewingPrivateKey,
      receiverAddressData,
      tokenDataGetter as any,
    );
    const extractedRelayV2 = await extractRailgunTransactionDataFromTransactionRequest(
      TXIDVersion.V2_PoseidonMerkle,
      chain,
      { to: contractAddress, data: v2RelayCalldata, value: 0n } as any,
      true,
      contractAddress,
      receiverViewingPrivateKey,
      receiverAddressData,
      tokenDataGetter as any,
    );
    const erc20AmountMapV2 = await extractFirstNoteERC20AmountMapFromTransactionRequest(
      TXIDVersion.V2_PoseidonMerkle,
      chain,
      v2TransactionRequest as any,
      false,
      contractAddress,
      receiverViewingPrivateKey,
      receiverAddressData,
      tokenDataGetter as any,
    );
    const erc20AmountMapV3 = await extractFirstNoteERC20AmountMapFromTransactionRequest(
      TXIDVersion.V3_PoseidonMerkle,
      chain,
      v3TransactionRequest as any,
      false,
      contractAddress,
      receiverViewingPrivateKey,
      receiverAddressData,
      tokenDataGetter as any,
    );
    const erc20AmountMapRelayV2 = await extractFirstNoteERC20AmountMapFromTransactionRequest(
      TXIDVersion.V2_PoseidonMerkle,
      chain,
      { to: contractAddress, data: v2RelayCalldata, value: 0n } as any,
      true,
      contractAddress,
      receiverViewingPrivateKey,
      receiverAddressData,
      tokenDataGetter as any,
    );
    return {
      inputs: {
        chain,
        overallBatchMinGasPrice: overallBatchMinGasPrice.toString(),
        spendingTree: spendingTree.toString(),
        merkleRoot,
        merkleProofElements,
        tokenData,
        spendingPrivateKey: ByteUtils.fastBytesToHex(spendingPrivateKey),
        spendingPublicKey: spendingPublicKey.map((value) => value.toString()),
        nullifyingKey: nullifyingKey.toString(),
        walletMasterPublicKey: senderMasterPublicKey.toString(),
        walletViewingPrivateKey: ByteUtils.fastBytesToHex(senderViewingPrivateKey),
        walletViewingPublicKey: ByteUtils.fastBytesToHex(senderViewingPublicKey),
        receiverMasterPublicKey: receiverAddressData.masterPublicKey.toString(),
        receiverViewingPrivateKey: ByteUtils.fastBytesToHex(receiverViewingPrivateKey),
        receiverViewingPublicKey: ByteUtils.fastBytesToHex(receiverViewingPublicKey),
        utxos: [
          {
            position: utxo.position.toString(),
            noteRandom: utxoNote.random,
            noteValue: utxoNote.value.toString(),
          },
        ],
        outputs: [
          {
            random: outputNote.random,
            value: outputNote.value.toString(),
            senderRandom: outputNote.senderRandom,
            outputType: outputNote.outputType,
            walletSource: outputNote.walletSource,
            memoText: outputNote.memoText,
          },
        ],
        adaptID,
        globalBoundParams: nativeGlobalBoundParamsV3(globalBoundParams),
        walletSource: 'tester',
        changeRandom,
        v2NoteCiphertextIVs,
        v2AnnotationIVs,
        v3NoteCiphertextNonces,
      },
      unprovedV2,
      unprovedV3,
      calldata: {
        contractAddress,
        v2: v2Calldata,
        relayV2: v2RelayCalldata,
        v3: v3Calldata,
      },
      validation: {
        extractedV2,
        extractedRelayV2,
        extractedV3,
        erc20AmountMapV2,
        erc20AmountMapRelayV2,
        erc20AmountMapV3,
      },
      v2: v2.map(nativeTransactionStruct),
      v3: v3.map(nativeTransactionStruct),
    };
  } finally {
    AES.getRandomIV = originalAESGetRandomIV;
    XChaCha20.getRandomIV = originalXChaChaGetRandomIV;
    TransactNote.getNoteRandom = originalGetNoteRandom;
    WalletInfo.walletSource = originalWalletSource;
  }
}

async function buildRelayAdaptFixtures() {
  const nullifiers = [
    [
      '0x8f127859e3fe7c0d81e27dfafaf0d9c2b7b488991d2c59c492b225fa9fc30700',
      '0x0000000000000000000000000000000000000000000000000000000000000000',
    ],
  ];
  const random = '86727859e3fe7c0d81e27dfafaf0d9c2b7b488991d2c59c492b225fa9fc307';
  const calls = [
    {
      to: '0x8f86403A4DE0BB5791fa46B8e795C547942fE4Cf',
      data:
        '0xd28c25d4000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000026869000000000000000000000000000000000000000000000000000000000000',
      value: 0n,
    },
  ];
  const minGasLimit = 10000000n;
  const relayAdaptParams = RelayAdaptHelper.getRelayAdaptParams(
    nullifiers.map((group) => ({ nullifiers: group })) as any,
    random,
    false,
    calls,
    minGasLimit,
  );
  const actionData = RelayAdaptHelper.getActionData(random, false, calls, minGasLimit);
  const relayShieldRandom = '00112233445566778899aabbccddeeff';
  const relayShieldRecipientPrivateKey = ByteUtils.hexStringToBytes(
    '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
  );
  const relayShieldRecipientViewingPublicKey = await getPublicViewingKey(
    relayShieldRecipientPrivateKey,
  );
  const relayShieldRecipientMasterPublicKey = 987654321n;
  const relayShieldRecipientAddress = encodeAddress({
    masterPublicKey: relayShieldRecipientMasterPublicKey,
    viewingPublicKey: relayShieldRecipientViewingPublicKey,
  });
  const relayShieldERC20Recipients = [
    {
      tokenAddress: TestVectorPOI.token,
      recipientAddress: relayShieldRecipientAddress,
    },
  ];
  const relayShieldNFTRecipients = [
    {
      nftTokenData: getTokenDataNFT(
        '0x1111111111111111111111111111111111111111',
        TokenType.ERC721,
        '12345',
      ),
      recipientAddress: relayShieldRecipientAddress,
    },
    {
      nftTokenData: getTokenDataNFT(
        '0x2222222222222222222222222222222222222222',
        TokenType.ERC1155,
        '0xabcdef',
      ),
      recipientAddress: relayShieldRecipientAddress,
    },
  ];
  const relayShieldRandomness = [
    {
      shieldPrivateKey: '303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f',
      randomGCMIV: '505152535455565758595a5b5c5d5e5f',
      receiverCTRIV: '606162636465666768696a6b6c6d6e6f',
    },
    {
      shieldPrivateKey: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
      randomGCMIV: '707172737475767778797a7b7c7d7e7f',
      receiverCTRIV: '808182838485868788898a8b8c8d8e8f',
    },
    {
      shieldPrivateKey: '505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f',
      randomGCMIV: '909192939495969798999a9b9c9d9e9f',
      receiverCTRIV: 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
    },
  ];
  const originalByteUtilsRandomHex = ByteUtils.randomHex;
  const originalAESGetRandomIV = AES.getRandomIV;
  let randomHexIndex = 0;
  const shieldIVs = relayShieldRandomness.flatMap((item) => [
    item.randomGCMIV,
    item.receiverCTRIV,
  ]);
  let relayShieldRequests: any[];
  try {
    (ByteUtils as any).randomHex = (length = 32) => {
      if (length !== 32) return originalByteUtilsRandomHex(length);
      const key = relayShieldRandomness[randomHexIndex]?.shieldPrivateKey;
      randomHexIndex += 1;
      if (!key) throw new Error('Missing deterministic relay shield private key');
      return key;
    };
    AES.getRandomIV = () => {
      const iv = shieldIVs.shift();
      if (!iv) throw new Error('Missing deterministic relay shield IV');
      return iv;
    };
    relayShieldRequests = await RelayAdaptHelper.generateRelayShieldRequests(
      relayShieldRandom,
      relayShieldERC20Recipients,
      relayShieldNFTRecipients,
    );
  } finally {
    (ByteUtils as any).randomHex = originalByteUtilsRandomHex;
    AES.getRandomIV = originalAESGetRandomIV;
  }
  const relayAdaptErrorData =
    '0x5c0dee5d00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000006408c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001564732d6d6174682d7375622d756e646572666c6f77000000000000000000000000000000000000000000000000000000000000000000000000000000';
  const stringErrorData =
    '0x08c379a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000205261696c67756e4c6f6769633a204e6f746520616c7265616479207370656e74';
  const relayAdaptPlainStringData =
    '0x5c0dee5d00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000002d52656c617941646170743a205265667573696e6720746f2063616c6c205261696c67756e20636f6e747261637400000000000000000000000000000000000000';
  const notRelayAdaptData = '0x1234';
  const relayAdaptInterface = new Interface(ABIRelayAdapt);
  const relayAdaptAddress = '0x3333333333333333333333333333333333333333';
  const unshieldAddress = '0x4444444444444444444444444444444444444444';
  const wrapBaseAmount = 13579n;
  const baseTokenTransfer = {
    token: getTokenDataERC20(ZERO_ADDRESS),
    to: unshieldAddress,
    value: 0n,
  };
  const baseShieldRequest = {
    preimage: {
      npk: ByteUtils.nToHex(1357911n, ByteLength.UINT_256, true),
      token: getTokenDataERC20(ZERO_ADDRESS),
      value: wrapBaseAmount,
    },
    ciphertext: {
      encryptedBundle: [
        ByteUtils.nToHex(31n, ByteLength.UINT_256, true),
        ByteUtils.nToHex(32n, ByteLength.UINT_256, true),
        ByteUtils.nToHex(33n, ByteLength.UINT_256, true),
      ],
      shieldKey: ByteUtils.nToHex(34n, ByteLength.UINT_256, true),
    },
  };
  const relayCalldata = relayAdaptInterface.encodeFunctionData('relay', [[], actionData]);
  const multicallCalldata = relayAdaptInterface.encodeFunctionData('multicall', [true, calls]);
  const shieldCalldata = relayAdaptInterface.encodeFunctionData('shield', [relayShieldRequests]);
  const shieldBaseCalldata = relayAdaptInterface.encodeFunctionData('shield', [[baseShieldRequest]]);
  const transferCalldata = relayAdaptInterface.encodeFunctionData('transfer', [[baseTokenTransfer]]);
  const wrapBaseCalldata = relayAdaptInterface.encodeFunctionData('wrapBase', [wrapBaseAmount]);
  const unwrapBaseCalldata = relayAdaptInterface.encodeFunctionData('unwrapBase', [0n]);
  const shieldBaseCalls = [
    { to: relayAdaptAddress, data: wrapBaseCalldata, value: 0n },
    { to: relayAdaptAddress, data: shieldBaseCalldata, value: 0n },
  ];
  const unshieldBaseCalls = [
    { to: relayAdaptAddress, data: unwrapBaseCalldata, value: 0n },
    { to: relayAdaptAddress, data: transferCalldata, value: 0n },
  ];
  const crossContractCallsWithShield = [
    ...calls,
    { to: relayAdaptAddress, data: shieldCalldata, value: 0n },
  ];
  const crossContractMinGasLimit = 3200000n;
  const crossContractMinGasLimitForContract =
    RelayAdaptV2Contract.getMinimumGasLimitForContract(crossContractMinGasLimit);
  const crossContractRequireSuccess = (RelayAdaptV2Contract as any)
    .shouldRequireSuccessForCrossContractCalls(false, true);
  const unshieldBaseParams = RelayAdaptHelper.getRelayAdaptParams(
    nullifiers.map((group) => ({ nullifiers: group })) as any,
    random,
    true,
    unshieldBaseCalls,
  );
  const crossContractParams = RelayAdaptHelper.getRelayAdaptParams(
    nullifiers.map((group) => ({ nullifiers: group })) as any,
    random,
    crossContractRequireSuccess,
    crossContractCallsWithShield,
    crossContractMinGasLimitForContract,
  );
  const shieldBaseMulticallCalldata = relayAdaptInterface.encodeFunctionData('multicall', [
    true,
    shieldBaseCalls,
  ]);
  const multicallWithShieldCalldata = relayAdaptInterface.encodeFunctionData('multicall', [
    true,
    crossContractCallsWithShield,
  ]);
  const unshieldBaseActionData = RelayAdaptHelper.getActionData(
    random,
    true,
    unshieldBaseCalls,
    0n,
  );
  const unshieldBaseRelayCalldata = relayAdaptInterface.encodeFunctionData('relay', [
    [],
    unshieldBaseActionData,
  ]);
  const crossContractActionData = RelayAdaptHelper.getActionData(
    random,
    crossContractRequireSuccess,
    crossContractCallsWithShield,
    crossContractMinGasLimitForContract,
  );
  const crossContractRelayCalldata = relayAdaptInterface.encodeFunctionData('relay', [
    [],
    crossContractActionData,
  ]);
  const callErrorEvent = relayAdaptInterface.getEvent('CallError');
  if (!callErrorEvent) throw new Error('Missing RelayAdapt CallError event');
  const callErrorStringLog = relayAdaptInterface.encodeEventLog(callErrorEvent, [
    5n,
    stringErrorData,
  ]);
  const callErrorPlainLog = relayAdaptInterface.encodeEventLog(callErrorEvent, [
    2n,
    '0x' + Buffer.from('plain relay error', 'utf8').toString('hex'),
  ]);
  const unrelatedLog = {
    topics: [ByteUtils.nToHex(1234n, ByteLength.UINT_256, true)],
    data: '0x',
  };
  const gasEstimateError =
    'execution reverted (unknown custom error) (action="estimateGas", data="' +
    relayAdaptErrorData +
    '", reason=null, transaction={ "data": "0x28223a77", "from": "0x000000000000000000000000000000000000dEaD", "to": "0x0355B7B8cb128fA5692729Ab3AAa199C1753f726" }, invocation=null, revert=null, code=CALL_EXCEPTION, version=6.4.0)';
  const nonParseableGasEstimateError = 'not a parseable error';
  const parse = (data: string) => {
    const parsed = RelayAdaptV2Contract.parseRelayAdaptReturnValue(data);
    return {
      callIndex: parsed?.callIndex?.toString(),
      error: parsed?.error,
    };
  };
  return {
    params: {
      nullifiers,
      random,
      requireSuccess: false,
      minGasLimit: minGasLimit.toString(),
      calls: calls.map((call) => ({
        to: call.to,
        data: call.data,
        value: call.value.toString(),
      })),
      actionData: {
        random: ByteUtils.fastBytesToHex(actionData.random as Uint8Array),
        requireSuccess: actionData.requireSuccess,
        minGasLimit: actionData.minGasLimit.toString(),
        calls: actionData.calls.map((call) => ({
          to: call.to,
          data: call.data,
          value: call.value.toString(),
        })),
      },
      relayAdaptParams,
    },
    shieldRequests: {
      random: relayShieldRandom,
      recipient: {
        masterPublicKey: relayShieldRecipientMasterPublicKey.toString(),
        viewingPrivateKey: ByteUtils.fastBytesToHex(relayShieldRecipientPrivateKey),
        viewingPublicKey: ByteUtils.fastBytesToHex(relayShieldRecipientViewingPublicKey),
        address: relayShieldRecipientAddress,
      },
      erc20Recipients: relayShieldERC20Recipients,
      nftRecipients: relayShieldNFTRecipients,
      randomness: relayShieldRandomness,
      requests: JSON.parse(JSON.stringify(relayShieldRequests, bigintReplacer)),
    },
    calldata: {
      relayAdaptAddress,
      unshieldAddress,
      relay: relayCalldata,
      multicall: multicallCalldata,
      shield: shieldCalldata,
      transfer: transferCalldata,
      wrapBaseAmount: wrapBaseAmount.toString(),
      wrapBase: wrapBaseCalldata,
      unwrapBaseAmount: '0',
      unwrapBase: unwrapBaseCalldata,
      unshieldBaseCalls: unshieldBaseCalls.map((call) => ({
        to: call.to,
        data: call.data,
        value: call.value.toString(),
      })),
      unshieldBaseParams,
      crossContractCallsWithShield: crossContractCallsWithShield.map((call) => ({
        to: call.to,
        data: call.data,
        value: call.value.toString(),
      })),
      crossContractMinGasLimit: crossContractMinGasLimit.toString(),
      crossContractMinGasLimitForContract: crossContractMinGasLimitForContract.toString(),
      crossContractRequireSuccess,
      crossContractParams,
      baseShieldRequest: JSON.parse(JSON.stringify(baseShieldRequest, bigintReplacer)),
      populatedShieldBaseToken: {
        to: relayAdaptAddress,
        data: shieldBaseMulticallCalldata,
        value: wrapBaseAmount.toString(),
      },
      populatedMulticall: {
        to: relayAdaptAddress,
        data: multicallWithShieldCalldata,
        value: '0',
      },
      populatedUnshieldBaseToken: {
        to: relayAdaptAddress,
        data: unshieldBaseRelayCalldata,
        value: '0',
      },
      populatedCrossContract: {
        to: relayAdaptAddress,
        data: crossContractRelayCalldata,
        value: '0',
        gasLimit: crossContractMinGasLimit.toString(),
      },
    },
    crossContractPolicy: {
      minimumGasLimit: '3200000',
      minGasLimitForContract: RelayAdaptV2Contract.getMinimumGasLimitForContract(3200000n).toString(),
      requireSuccess: [
        { isGasEstimate: true, isBroadcasterTransaction: true },
        { isGasEstimate: true, isBroadcasterTransaction: false },
        { isGasEstimate: false, isBroadcasterTransaction: true },
        { isGasEstimate: false, isBroadcasterTransaction: false },
      ].map((input) => ({
        ...input,
        output: (RelayAdaptV2Contract as any).shouldRequireSuccessForCrossContractCalls(
          input.isGasEstimate,
          input.isBroadcasterTransaction,
        ),
      })),
    },
    parseReturnValues: [
      {
        name: 'relay-adapt-error',
        data: relayAdaptErrorData,
        parsed: parse(relayAdaptErrorData),
      },
      {
        name: 'string-error',
        data: stringErrorData,
        parsed: parse(stringErrorData),
      },
      {
        name: 'relay-adapt-plain-string',
        data: relayAdaptPlainStringData,
        parsed: parse(relayAdaptPlainStringData),
      },
      {
        name: 'not-relay-adapt',
        data: notRelayAdaptData,
        parsed: parse(notRelayAdaptData),
      },
    ],
    gasEstimateErrors: [
      {
        name: 'parseable',
        input: gasEstimateError,
        parsed: RelayAdaptV2Contract.extractGasEstimateCallFailedIndexAndErrorText(gasEstimateError),
      },
      {
        name: 'non-parseable',
        input: nonParseableGasEstimateError,
        parsed:
          RelayAdaptV2Contract.extractGasEstimateCallFailedIndexAndErrorText(
            nonParseableGasEstimateError,
          ),
      },
    ],
    callErrorTopic: relayAdaptInterface.encodeFilterTopics('CallError', [])[0],
    callErrorLogs: [
      {
        name: 'string-error-log',
        logs: [
          {
            topics: callErrorStringLog.topics,
            data: callErrorStringLog.data,
          },
        ],
        parsed:
          RelayAdaptV2Contract.getRelayAdaptCallError([
            { topics: callErrorStringLog.topics, data: callErrorStringLog.data } as any,
          ]) ?? null,
      },
      {
        name: 'plain-error-log',
        logs: [
          {
            topics: callErrorPlainLog.topics,
            data: callErrorPlainLog.data,
          },
        ],
        parsed:
          RelayAdaptV2Contract.getRelayAdaptCallError([
            { topics: callErrorPlainLog.topics, data: callErrorPlainLog.data } as any,
          ]) ?? null,
      },
      {
        name: 'no-call-error-log',
        logs: [unrelatedLog],
        parsed: RelayAdaptV2Contract.getRelayAdaptCallError([unrelatedLog as any]) ?? null,
      },
      {
        name: 'second-log-matches',
        logs: [
          unrelatedLog,
          {
            topics: callErrorPlainLog.topics,
            data: callErrorPlainLog.data,
          },
        ],
        parsed:
          RelayAdaptV2Contract.getRelayAdaptCallError([
            unrelatedLog as any,
            { topics: callErrorPlainLog.topics, data: callErrorPlainLog.data } as any,
          ]) ?? null,
      },
    ],
  };
}

function nativeRailgunSignature(privateKey: Uint8Array, publicInputs: any) {
  const message = poseidon([
    publicInputs.merkleRoot,
    publicInputs.boundParamsHash,
    ...publicInputs.nullifiers,
    ...publicInputs.commitmentsOut,
  ]);
  const signature = signEDDSA(privateKey, message);
  return {
    message: message.toString(),
    signature: JSON.parse(JSON.stringify(signature, bigintReplacer)),
  };
}

function zeroProof() {
  return {
    pi_a: ['00', '00'],
    pi_b: [
      ['00', '00'],
      ['00', '00'],
    ],
    pi_c: ['00', '00'],
  };
}

function emptyUnshieldPreimage() {
  const zeroAddress = ByteUtils.formatToByteLength('00', ByteLength.Address, true);
  return {
    npk: zeroAddress,
    token: getTokenDataERC20(zeroAddress),
    value: 0n,
  };
}

function nativeTransactionRequest(request: any) {
  return {
    txidVersion: request.txidVersion,
    privateInputs: nativePrivateInputsRailgun(request.privateInputs),
    publicInputs: nativePublicInputsRailgun(request.publicInputs),
    boundParams:
      request.txidVersion === TXIDVersion.V2_PoseidonMerkle
        ? nativeBoundParamsV2(request.boundParams)
        : nativeBoundParamsV3(request.boundParams),
  };
}

function nativeTransactionStruct(transaction: any) {
  return {
    txidVersion: transaction.txidVersion,
    proof: JSON.parse(JSON.stringify(transaction.proof, bigintReplacer)),
    merkleRoot: transaction.merkleRoot,
    nullifiers: transaction.nullifiers,
    boundParams:
      transaction.txidVersion === TXIDVersion.V2_PoseidonMerkle
        ? nativeBoundParamsV2(transaction.boundParams)
        : nativeBoundParamsV3(transaction.boundParams),
    commitments: transaction.commitments,
    unshieldPreimage: {
      npk: transaction.unshieldPreimage.npk,
      token: transaction.unshieldPreimage.token,
      value: transaction.unshieldPreimage.value.toString(),
    },
  };
}

function nativePrivateInputsRailgun(privateInputs: any) {
  return {
    tokenAddress: privateInputs.tokenAddress.toString(),
    publicKey: privateInputs.publicKey.map((value: bigint) => value.toString()),
    randomIn: privateInputs.randomIn.map((value: bigint) => value.toString()),
    valueIn: privateInputs.valueIn.map((value: bigint) => value.toString()),
    pathElements: privateInputs.pathElements.map((row: bigint[]) =>
      row.map((value: bigint) => value.toString()),
    ),
    leavesIndices: privateInputs.leavesIndices.map((value: bigint) => value.toString()),
    nullifyingKey: privateInputs.nullifyingKey.toString(),
    npkOut: privateInputs.npkOut.map((value: bigint) => value.toString()),
    valueOut: privateInputs.valueOut.map((value: bigint) => value.toString()),
  };
}

function nativePublicInputsRailgun(publicInputs: any) {
  return {
    merkleRoot: publicInputs.merkleRoot.toString(),
    boundParamsHash: publicInputs.boundParamsHash.toString(),
    nullifiers: publicInputs.nullifiers.map((value: bigint) => value.toString()),
    commitmentsOut: publicInputs.commitmentsOut.map((value: bigint) => value.toString()),
  };
}

function nativeBoundParamsV2(boundParams: any) {
  return {
    treeNumber: String(boundParams.treeNumber),
    minGasPrice: boundParams.minGasPrice.toString(),
    unshield: boundParams.unshield.toString(),
    chainID: BigInt(boundParams.chainID).toString(),
    adaptContract: String(boundParams.adaptContract).toLowerCase(),
    adaptParams: String(boundParams.adaptParams).toLowerCase(),
    commitmentCiphertext: boundParams.commitmentCiphertext.map((ciphertext: any) => ({
      ciphertext: ciphertext.ciphertext.map((value: string) => ByteUtils.hexlify(value, true)),
      blindedSenderViewingKey: ByteUtils.hexlify(ciphertext.blindedSenderViewingKey, true),
      blindedReceiverViewingKey: ByteUtils.hexlify(ciphertext.blindedReceiverViewingKey, true),
      annotationData: ByteUtils.hexlify(ciphertext.annotationData, true),
      memo: ByteUtils.hexlify(ciphertext.memo, true),
    })),
  };
}

function nativeBoundParamsV3(boundParams: any) {
  return {
    local: {
      treeNumber: String(boundParams.local.treeNumber),
      commitmentCiphertext: boundParams.local.commitmentCiphertext.map((ciphertext: any) => ({
        ciphertext: ByteUtils.hexlify(ciphertext.ciphertext, true),
        blindedSenderViewingKey: ByteUtils.hexlify(ciphertext.blindedSenderViewingKey, true),
        blindedReceiverViewingKey: ByteUtils.hexlify(ciphertext.blindedReceiverViewingKey, true),
      })),
    },
    global: nativeGlobalBoundParamsV3(boundParams.global),
  };
}

function nativeGlobalBoundParamsV3(global: any) {
  return {
    minGasPrice: global.minGasPrice.toString(),
    chainID: global.chainID.toString(),
    senderCiphertext: ByteUtils.hexlify(global.senderCiphertext, true),
    to: String(global.to).toLowerCase(),
    data: ByteUtils.hexlify(global.data, true),
  };
}

function buildTransactionStructFixtures() {
  const boundParamsFixtures = buildBoundParamsFixtures();
  const sampleProof = buildSampleProof();
  const unshieldPreimage = {
    npk: ByteUtils.nToHex(123456789n, ByteLength.UINT_256, true),
    token: getTokenDataERC20(TestVectorPOI.token),
    value: 987654321n,
  };
  const publicInputsV2 = {
    merkleRoot: 1n,
    boundParamsHash: hashBoundParamsV2(boundParamsFixtures.v2.boundParams),
    nullifiers: [2n, 3n],
    commitmentsOut: [4n, 5n, 6n],
  };
  const publicInputsV3 = {
    merkleRoot: 11n,
    boundParamsHash: hashBoundParamsV3(boundParamsFixtures.v3.boundParams),
    nullifiers: [12n, 13n],
    commitmentsOut: [14n, 15n],
  };

  return {
    v2: (Transaction as any).createTransactionStructV2(
      TXIDVersion.V2_PoseidonMerkle,
      sampleProof,
      publicInputsV2,
      boundParamsFixtures.v2.boundParams,
      unshieldPreimage,
    ),
    v3: (Transaction as any).createTransactionStructV3(
      TXIDVersion.V3_PoseidonMerkle,
      sampleProof,
      publicInputsV3,
      boundParamsFixtures.v3.boundParams,
      unshieldPreimage,
    ),
  };
}

function buildCalldataFixtures() {
  const transactionStructFixtures = buildTransactionStructFixtures();
  const bytes32Zero = ByteUtils.formatToByteLength('00', ByteLength.UINT_256, true);
  const zeroUnshieldChangeCiphertext = {
    encryptedBundle: [bytes32Zero, bytes32Zero, bytes32Zero],
    shieldKey: bytes32Zero,
  };
  const v3TransactStruct = {
    proof: transactionStructFixtures.v3.proof,
    merkleRoot: transactionStructFixtures.v3.merkleRoot,
    nullifiers: transactionStructFixtures.v3.nullifiers,
    commitments: transactionStructFixtures.v3.commitments,
    boundParams: transactionStructFixtures.v3.boundParams.local,
    unshieldPreimage: transactionStructFixtures.v3.unshieldPreimage,
  };

  return {
    v2Transact: new Interface(ABIRailgunSmartWallet).encodeFunctionData('transact', [
      [transactionStructFixtures.v2],
    ]),
    v3ExecuteTransact: new Interface(ABIPoseidonMerkleVerifier).encodeFunctionData('execute', [
      [v3TransactStruct],
      [],
      transactionStructFixtures.v3.boundParams.global,
      zeroUnshieldChangeCiphertext,
    ]),
  };
}

async function buildEventFixtures() {
  const railgunInterface = new Interface(ABIRailgunSmartWallet);
  const transactionHash = ByteUtils.nToHex(0x1234567890abcdefn, ByteLength.UINT_256, true);
  const blockNumber = 7654321;
  const eventLogIndex = 9;
  const shieldArgs = {
    treeNumber: 3n,
    startPosition: 11n,
    commitments: [
      {
        npk: ByteUtils.nToHex(1111n, ByteLength.UINT_256, true),
        token: getTokenDataERC20(TestVectorPOI.token),
        value: 2222n,
      },
      {
        npk: ByteUtils.nToHex(3333n, ByteLength.UINT_256, true),
        token: getTokenDataNFT(
          '0x5555555555555555555555555555555555555555',
          TokenType.ERC721,
          '4444',
        ),
        value: 1n,
      },
    ],
    shieldCiphertext: [
      {
        encryptedBundle: [
          ByteUtils.nToHex(21n, ByteLength.UINT_256, true),
          ByteUtils.nToHex(22n, ByteLength.UINT_256, true),
          ByteUtils.nToHex(23n, ByteLength.UINT_256, true),
        ],
        shieldKey: ByteUtils.nToHex(24n, ByteLength.UINT_256, true),
      },
      {
        encryptedBundle: [
          ByteUtils.nToHex(31n, ByteLength.UINT_256, true),
          ByteUtils.nToHex(32n, ByteLength.UINT_256, true),
          ByteUtils.nToHex(33n, ByteLength.UINT_256, true),
        ],
        shieldKey: ByteUtils.nToHex(34n, ByteLength.UINT_256, true),
      },
    ],
    fees: [7n, 0n],
  };
  const transactArgs = {
    treeNumber: 4n,
    startPosition: 15n,
    hash: [
      ByteUtils.nToHex(1001n, ByteLength.UINT_256, true),
      ByteUtils.nToHex(1002n, ByteLength.UINT_256, true),
    ],
    ciphertext: [
      {
        ciphertext: [
          ByteUtils.nToHex(41n, ByteLength.UINT_256, true),
          ByteUtils.nToHex(42n, ByteLength.UINT_256, true),
          ByteUtils.nToHex(43n, ByteLength.UINT_256, true),
          ByteUtils.nToHex(44n, ByteLength.UINT_256, true),
        ],
        blindedSenderViewingKey: ByteUtils.nToHex(45n, ByteLength.UINT_256, true),
        blindedReceiverViewingKey: ByteUtils.nToHex(46n, ByteLength.UINT_256, true),
        annotationData: '0x1234',
        memo: '0xabcd',
      },
      {
        ciphertext: [
          ByteUtils.nToHex(51n, ByteLength.UINT_256, true),
          ByteUtils.nToHex(52n, ByteLength.UINT_256, true),
          ByteUtils.nToHex(53n, ByteLength.UINT_256, true),
          ByteUtils.nToHex(54n, ByteLength.UINT_256, true),
        ],
        blindedSenderViewingKey: ByteUtils.nToHex(55n, ByteLength.UINT_256, true),
        blindedReceiverViewingKey: ByteUtils.nToHex(56n, ByteLength.UINT_256, true),
        annotationData: '0x5678',
        memo: '0xef01',
      },
    ],
  };
  const unshieldArgs = {
    to: '0x7777777777777777777777777777777777777777',
    token: getTokenDataERC20(TestVectorPOI.token),
    amount: 987654321n,
    fee: 12345n,
  };
  const nullifiedArgs = {
    treeNumber: 6,
    nullifier: [
      ByteUtils.nToHex(2001n, ByteLength.UINT_256, true),
      ByteUtils.nToHex(2002n, ByteLength.UINT_256, true),
    ],
  };
  const logFor = (eventName: string, args: any[], index: number) => {
    const event = railgunInterface.getEvent(eventName);
    if (!event) throw new Error('Missing event ' + eventName);
    const encoded = railgunInterface.encodeEventLog(event, args);
    return {
      topics: encoded.topics,
      data: encoded.data,
      transactionHash,
      blockNumber,
      index,
    };
  };
  const accumulatorInterface = new Interface(ABIPoseidonMerkleAccumulator);
  const v3TokenData = getTokenDataERC20(TestVectorPOI.token);
  const v3TokenID = ByteUtils.formatToByteLength(getTokenDataHash(v3TokenData), ByteLength.UINT_256, true);
  const v3UnshieldPreimage = {
    npk: ByteUtils.formatToByteLength('0x8888888888888888888888888888888888888888', ByteLength.UINT_256, true),
    token: v3TokenData,
    value: 1000n,
  };
  const v3Update = {
    commitments: [
      ByteUtils.nToHex(5001n, ByteLength.UINT_256, true),
      ByteUtils.nToHex(5002n, ByteLength.UINT_256, true),
    ],
    transactions: [
      {
        nullifiers: [
          ByteUtils.nToHex(6001n, ByteLength.UINT_256, true),
          ByteUtils.nToHex(6002n, ByteLength.UINT_256, true),
        ],
        commitmentsCount: 2,
        spendAccumulatorNumber: 2,
        unshieldPreimage: v3UnshieldPreimage,
        boundParamsHash: ByteUtils.nToHex(7001n, ByteLength.UINT_256, true),
      },
    ],
    shields: [
      {
        from: '0x9999999999999999999999999999999999999999',
        preimage: {
          npk: ByteUtils.nToHex(8001n, ByteLength.UINT_256, true),
          token: v3TokenData,
          value: 3000n,
        },
        ciphertext: {
          encryptedBundle: [
            ByteUtils.nToHex(81n, ByteLength.UINT_256, true),
            ByteUtils.nToHex(82n, ByteLength.UINT_256, true),
            ByteUtils.nToHex(83n, ByteLength.UINT_256, true),
          ],
          shieldKey: ByteUtils.nToHex(84n, ByteLength.UINT_256, true),
        },
      },
    ],
    commitmentCiphertext: [
      {
        ciphertext: '0x' + '11'.repeat(16) + '12'.repeat(32),
        blindedSenderViewingKey: ByteUtils.nToHex(91n, ByteLength.UINT_256, true),
        blindedReceiverViewingKey: ByteUtils.nToHex(92n, ByteLength.UINT_256, true),
      },
      {
        ciphertext: '0x' + '21'.repeat(16) + '22'.repeat(32),
        blindedSenderViewingKey: ByteUtils.nToHex(93n, ByteLength.UINT_256, true),
        blindedReceiverViewingKey: ByteUtils.nToHex(94n, ByteLength.UINT_256, true),
      },
    ],
    treasuryFees: [
      {
        tokenID: v3TokenID,
        fee: 40n,
      },
    ],
    senderCiphertext: '0x' + '33'.repeat(48),
  };
  const accumulatorNumber = 7;
  const accumulatorStartPosition = 100n;
  const accumulatorEvent = accumulatorInterface.getEvent('AccumulatorStateUpdate');
  if (!accumulatorEvent) throw new Error('Missing event AccumulatorStateUpdate');
  const encodedAccumulatorLog = accumulatorInterface.encodeEventLog(accumulatorEvent, [
    v3Update,
    accumulatorNumber,
    accumulatorStartPosition,
  ]);
  const v3Processed = {
    commitmentEvents: [] as any[],
    nullifierEvents: [] as any[],
    unshieldEvents: [] as any[],
    railgunTransactionEvents: [] as any[],
  };
  await V3Events.processAccumulatorEvent(
    TXIDVersion.V3_PoseidonMerkle,
    {
      update: v3Update,
      accumulatorNumber,
      startPosition: accumulatorStartPosition,
    } as any,
    transactionHash,
    blockNumber,
    async (_txidVersion: any, events: any[]) => {
      v3Processed.commitmentEvents.push(...events);
    },
    async (_txidVersion: any, events: any[]) => {
      v3Processed.nullifierEvents.push(...events);
    },
    async (_txidVersion: any, events: any[]) => {
      v3Processed.unshieldEvents.push(...events);
    },
    async (_txidVersion: any, events: any[]) => {
      v3Processed.railgunTransactionEvents.push(...events);
    },
    async () => {},
  );
  const native = (value: any) => JSON.parse(JSON.stringify(value, bigintReplacer));
  return native({
    v2: {
      transactionHash,
      blockNumber,
      shield: {
        log: logFor('Shield', [
          shieldArgs.treeNumber,
          shieldArgs.startPosition,
          shieldArgs.commitments,
          shieldArgs.shieldCiphertext,
          shieldArgs.fees,
        ], 3),
        formatted: V2Events.formatShieldEvent(
          shieldArgs as any,
          transactionHash,
          blockNumber,
          shieldArgs.fees,
          undefined,
        ),
      },
      transact: {
        log: logFor('Transact', [
          transactArgs.treeNumber,
          transactArgs.startPosition,
          transactArgs.hash,
          transactArgs.ciphertext,
        ], 4),
        formatted: V2Events.formatTransactEvent(
          transactArgs as any,
          transactionHash,
          blockNumber,
          undefined,
        ),
      },
      unshield: {
        log: logFor('Unshield', [
          unshieldArgs.to,
          unshieldArgs.token,
          unshieldArgs.amount,
          unshieldArgs.fee,
        ], eventLogIndex),
        formatted: V2Events.formatUnshieldEvent(
          unshieldArgs as any,
          transactionHash,
          blockNumber,
          eventLogIndex,
          undefined,
        ),
      },
      nullified: {
        log: logFor('Nullified', [
          nullifiedArgs.treeNumber,
          nullifiedArgs.nullifier,
        ], 5),
        formatted: V2Events.formatNullifiedEvents(
          nullifiedArgs as any,
          transactionHash,
          blockNumber,
        ),
      },
      topics: {
        shield: railgunInterface.encodeFilterTopics('Shield', [])[0],
        transact: railgunInterface.encodeFilterTopics('Transact', [])[0],
        unshield: railgunInterface.encodeFilterTopics('Unshield', [])[0],
        nullified: railgunInterface.encodeFilterTopics('Nullified', [])[0],
      },
    },
    v3: {
      accumulator: {
        log: {
          topics: encodedAccumulatorLog.topics,
          data: encodedAccumulatorLog.data,
          transactionHash,
          blockNumber,
          index: 6,
        },
        processed: v3Processed,
      },
      topics: {
        accumulatorStateUpdate: accumulatorInterface.encodeFilterTopics('AccumulatorStateUpdate', [])[0],
      },
    },
  });
}

async function buildShieldFixtures() {
  const bytes32Zero = ByteUtils.formatToByteLength('00', ByteLength.UINT_256, true);
  const chainID = 31337n;
  const request = {
    preimage: {
      npk: ByteUtils.nToHex(246813579n, ByteLength.UINT_256, true),
      token: getTokenDataERC20(TestVectorPOI.token),
      value: 13579n,
    },
    ciphertext: {
      encryptedBundle: [
        ByteUtils.nToHex(21n, ByteLength.UINT_256, true),
        ByteUtils.nToHex(22n, ByteLength.UINT_256, true),
        ByteUtils.nToHex(23n, ByteLength.UINT_256, true),
      ],
      shieldKey: ByteUtils.nToHex(24n, ByteLength.UINT_256, true),
    },
  };
  const emptyGlobalBoundParams = {
    minGasPrice: 0n,
    chainID,
    senderCiphertext: '0x',
    to: ByteUtils.formatToByteLength('00', ByteLength.Address, true),
    data: '0x',
  };
  const zeroUnshieldChangeCiphertext = {
    encryptedBundle: [bytes32Zero, bytes32Zero, bytes32Zero],
    shieldKey: bytes32Zero,
  };

  const shieldNote = await buildShieldNoteFixture();

  return {
    chainID: chainID.toString(),
    request: JSON.parse(JSON.stringify(request, bigintReplacer)),
    shieldNote,
    v2ShieldCalldata: new Interface(ABIRailgunSmartWallet).encodeFunctionData('shield', [
      [request],
    ]),
    v3ExecuteShieldCalldata: new Interface(ABIPoseidonMerkleVerifier).encodeFunctionData(
      'execute',
      [[], [request], emptyGlobalBoundParams, zeroUnshieldChangeCiphertext],
    ),
  };
}

async function buildShieldNoteFixture() {
  const masterPublicKey = 123456789n;
  const random = '00112233445566778899aabbccddeeff';
  const value = 424242n;
  const tokenAddress = TestVectorPOI.token;
  const shieldPrivateKey = ByteUtils.hexStringToBytes(
    '1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30',
  );
  const receiverPrivateKey = ByteUtils.hexStringToBytes(
    '3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50',
  );
  const receiverViewingPublicKey = await getPublicViewingKey(receiverPrivateKey);
  const randomGCMIV = '606162636465666768696a6b6c6d6e6f';
  const receiverCTRIV = '707172737475767778797a7b7c7d7e7f';
  const originalGetRandomIV = AES.getRandomIV;
  try {
    const ivs = [randomGCMIV, receiverCTRIV];
    AES.getRandomIV = () => {
      const iv = ivs.shift();
      if (!iv) throw new Error('Missing deterministic shield IV');
      return iv;
    };
    const note = new ShieldNoteERC20(masterPublicKey, random, value, tokenAddress);
    const request = await note.serialize(shieldPrivateKey, receiverViewingPublicKey);
    return {
      masterPublicKey: masterPublicKey.toString(),
      random,
      value: value.toString(),
      tokenAddress,
      tokenData: getTokenDataERC20(tokenAddress),
      shieldPrivateKey: ByteUtils.fastBytesToHex(shieldPrivateKey),
      receiverPrivateKey: ByteUtils.fastBytesToHex(receiverPrivateKey),
      receiverViewingPublicKey: ByteUtils.fastBytesToHex(receiverViewingPublicKey),
      randomGCMIV,
      receiverCTRIV,
      request: JSON.parse(JSON.stringify(request, bigintReplacer)),
    };
  } finally {
    AES.getRandomIV = originalGetRandomIV;
  }
}

function buildMerkleFixtures() {
  const txid = buildTxidFixtures().poiTransaction;
  const poiTxidProof = {
    leaf: txid.leafHash,
    indices: TestVectorPOI.railgunTxidMerkleProofIndices,
    elements: TestVectorPOI.railgunTxidMerkleProofPathElements,
    root: TestVectorPOI.anyRailgunTxidMerklerootAfterTransaction,
  };
  return {
    singleStepProof: {
      leaf: ByteUtils.nToHex(0n, ByteLength.UINT_256),
      indices: ByteUtils.nToHex(0n, ByteLength.UINT_256),
      elements: [ByteUtils.nToHex(1n, ByteLength.UINT_256)],
      root: ByteUtils.nToHex(poseidon([0n, 1n]), ByteLength.UINT_256),
    },
    poiTxidProof,
    poiTxidProofVerified: verifyMerkleProof(poiTxidProof),
  };
}

async function buildProofFixtures() {
  const sampleProof = buildSampleProof();
  const railgunPublicInputs = {
    merkleRoot: '1',
    boundParamsHash: '2',
    nullifiers: ['3', '4'],
    commitmentsOut: ['5', '6', '7'],
  };
  const poiPublicInputs = {
    blindedCommitmentsOut: ['1', '2'],
    anyRailgunTxidMerklerootAfterTransaction: '3',
    railgunTxidIfHasUnshield: '4',
    poiMerkleroots: ['5', '6'],
  };

  return {
    sampleProof,
    formattedProof: (Prover as any).formatProof(sampleProof),
    poi3x3Proof: await buildPOI3x3ProofFixture(),
    railgunPublicSignals: {
      publicInputs: railgunPublicInputs,
      signals: [
        railgunPublicInputs.merkleRoot,
        railgunPublicInputs.boundParamsHash,
        ...railgunPublicInputs.nullifiers,
        ...railgunPublicInputs.commitmentsOut,
      ],
    },
    poiPublicSignals: {
      publicInputs: poiPublicInputs,
      signals: [
        ...poiPublicInputs.blindedCommitmentsOut,
        poiPublicInputs.anyRailgunTxidMerklerootAfterTransaction,
        poiPublicInputs.railgunTxidIfHasUnshield,
        ...poiPublicInputs.poiMerkleroots,
      ],
    },
  };
}

function buildSampleProof() {
  return {
    pi_a: ['1', '2'],
    pi_b: [['3', '4'], ['5', '6']],
    pi_c: ['7', '8'],
  };
}

async function buildPOI3x3ProofFixture() {
  return withDeterministicRandom(async () => {
    const formatted = (Prover as any).formatPOIInputs(TestVectorPOI, 3, 3);
    const artifacts = getArtifactsPOI(3, 3);
    const proofData = await snarkjs.groth16.fullProve(formatted, artifacts.wasm, artifacts.zkey, { debug() {} });
    const snarkProof = {
      pi_a: [proofData.proof.pi_a[0], proofData.proof.pi_a[1]],
      pi_b: [proofData.proof.pi_b[0], proofData.proof.pi_b[1]],
      pi_c: [proofData.proof.pi_c[0], proofData.proof.pi_c[1]],
    };
    return {
      proof: snarkProof,
      publicSignals: proofData.publicSignals,
      publicSignalsSHA256: crypto.createHash('sha256').update(JSON.stringify(proofData.publicSignals)).digest('hex'),
      proofSHA256: crypto.createHash('sha256').update(JSON.stringify(snarkProof)).digest('hex'),
      verified: await snarkjs.groth16.verify(artifacts.vkey, proofData.publicSignals, proofData.proof),
      vkey: artifacts.vkey,
    };
  });
}

async function withDeterministicRandom(fn: () => Promise<unknown>) {
  const originalRandomFillSync = crypto.randomFillSync;
  let seed = 0;
  crypto.randomFillSync = ((buffer: Uint8Array) => {
    for (let i = 0; i < buffer.length; i += 1) {
      buffer[i] = seed & 0xff;
      seed += 1;
    }
    return buffer;
  }) as typeof crypto.randomFillSync;
  try {
    return await fn();
  } finally {
    crypto.randomFillSync = originalRandomFillSync;
  }
}

async function buildWitnessFixtures() {
  const formatted = (Prover as any).formatPOIInputs(TestVectorPOI, 3, 3);
  const artifacts = getArtifactsPOI(3, 3);
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'railgun-go-witness-'));
  const wasmPath = path.join(workDir, 'poi-3x3.wasm');
  const wtnsPath = path.join(workDir, 'poi-3x3.wtns');
  fs.writeFileSync(wasmPath, Buffer.from(artifacts.wasm));
  await snarkjs.wtns.calculate(JSON.parse(JSON.stringify(formatted, bigintReplacer)), wasmPath, wtnsPath);
  const wtnsBytes = fs.readFileSync(wtnsPath);
  return {
    poi3x3: {
      artifactPath: 'artifacts/poi_3x3.wasm',
      inputFixtureName: 'poi-3x3',
      wtnsSHA256: crypto.createHash('sha256').update(wtnsBytes).digest('hex'),
      wtnsSize: wtnsBytes.length,
    },
  };
}

main().then(() => {
  process.exit(0);
}).catch((error) => {
  console.error(error);
  process.exit(1);
});

function bigintReplacer(_key: string, value: unknown) {
  return typeof value === 'bigint' ? value.toString() : value;
}
`);

const tsNodePath = join(engineDir, 'node_modules', '.bin', process.platform === 'win32' ? 'ts-node.cmd' : 'ts-node');
const exported = execFileSync(tsNodePath, ['--transpile-only', exporterPath], {
  cwd: engineDir,
  encoding: 'utf8',
});

if (outPath) {
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, exported);
} else {
  process.stdout.write(exported);
}

if (artifactsOutPath) {
  mkdirSync(artifactsOutPath, { recursive: true });
  const poi3x3Wasm = brotliDecompressSync(readFileSync(join(engineDir, 'src/test/test-artifacts-lite/poi/3x3/wasm.br')));
  writeFileSync(join(artifactsOutPath, 'poi_3x3.wasm'), poi3x3Wasm);
}

function run(command, args, cwd = process.cwd()) {
  execFileSync(command, args, { cwd, stdio: 'inherit' });
}
