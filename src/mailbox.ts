import EthCrypto from 'eth-crypto';
import { KeyPair } from './types';

export class Mailbox {
  /**
   * Generates a secp256k1 keypair for mailbox communications.
   */
  static generateKeys(): KeyPair {
    const identity = EthCrypto.createIdentity();

    return {
      privateKey: identity.privateKey,
      publicKey: `0x${identity.publicKey}`,
      compressedPublicKey: `0x${EthCrypto.publicKey.compress(identity.publicKey)}`,
    };
  }

  /**
   * Encrypts a payload for a receiver's public key.
   * Accepts compressed or uncompressed secp256k1 public keys.
   */
  static async encryptPayload(receiverPubKeyHex: string, payload: string | object): Promise<string> {
    const payloadStr = typeof payload === 'string' ? payload : JSON.stringify(payload);
    const normalizedPubKey = Mailbox.normalizePublicKey(receiverPubKeyHex);

    const encrypted = await EthCrypto.encryptWithPublicKey(normalizedPubKey, payloadStr);
    return EthCrypto.cipher.stringify(encrypted);
  }

  /**
   * Decrypts a stringified envelope with the receiver's private key.
   */
  static async decryptPayload(privateKeyHex: string, encryptedPayloadString: string): Promise<string> {
    const encryptedObject = EthCrypto.cipher.parse(encryptedPayloadString);
    return EthCrypto.decryptWithPrivateKey(privateKeyHex, encryptedObject);
  }

  private static normalizePublicKey(pubKeyHex: string): string {
    const cleanKey = pubKeyHex.startsWith('0x') ? pubKeyHex.slice(2) : pubKeyHex;

    // 33-byte compressed secp256k1 key (66 hex chars)
    if (cleanKey.length === 66) {
      return EthCrypto.publicKey.decompress(cleanKey);
    }

    // 64-byte uncompressed key without 0x04 prefix (128 hex chars)
    if (cleanKey.length === 128) {
      return cleanKey;
    }

    // 65-byte uncompressed key with 0x04 prefix (130 hex chars)
    if (cleanKey.length === 130 && cleanKey.startsWith('04')) {
      return cleanKey.slice(2);
    }

    throw new Error('Invalid public key format. Expected compressed or uncompressed secp256k1 public key.');
  }
}
