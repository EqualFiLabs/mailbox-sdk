import EthCrypto from 'eth-crypto';
import { EncryptedEnvelope, KeyPair } from './types';

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
   *
   * Returns an eth-crypto stringified cipher payload.
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
    const encryptedObject = Mailbox.parseEnvelope(encryptedPayloadString);
    return EthCrypto.decryptWithPrivateKey(privateKeyHex, encryptedObject);
  }

  /**
   * Parses and validates a stringified envelope.
   */
  static parseEnvelope(encryptedPayloadString: string): EncryptedEnvelope {
    try {
      const parsed = EthCrypto.cipher.parse(encryptedPayloadString) as EncryptedEnvelope;

      if (!parsed.iv || !parsed.ephemPublicKey || !parsed.ciphertext || !parsed.mac) {
        throw new Error('Missing required envelope fields.');
      }

      return parsed;
    } catch {
      throw new Error('Invalid encrypted payload format. Expected eth-crypto stringified envelope.');
    }
  }

  /**
   * Converts an encrypted payload string into 0x-prefixed hex bytes for on-chain mailbox transport.
   *
   * Convention: UTF-8 encoding of the stringified envelope.
   */
  static envelopeToBytes(encryptedPayloadString: string): string {
    // Validate shape before serializing to bytes.
    Mailbox.parseEnvelope(encryptedPayloadString);

    const hex = Buffer.from(encryptedPayloadString, 'utf8').toString('hex');
    return `0x${hex}`;
  }

  /**
   * Converts 0x-prefixed hex bytes from on-chain mailbox events back into
   * the stringified envelope format expected by decryptPayload().
   */
  static envelopeFromBytes(envelopeBytesHex: string): string {
    const cleanBytes = envelopeBytesHex.startsWith('0x') ? envelopeBytesHex.slice(2) : envelopeBytesHex;

    if (!/^[a-fA-F0-9]*$/.test(cleanBytes) || cleanBytes.length % 2 !== 0) {
      throw new Error('Invalid envelope bytes. Expected 0x-prefixed hex string.');
    }

    const envelopeString = Buffer.from(cleanBytes, 'hex').toString('utf8');
    // Validate shape after decoding bytes.
    Mailbox.parseEnvelope(envelopeString);

    return envelopeString;
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
