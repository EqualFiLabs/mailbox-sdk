import { describe, it, expect } from 'vitest';
import { Mailbox } from '../src/mailbox';

const deterministicVector = {
  privateKey: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  compressedPublicKey: '0x026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3',
  encryptedPayload:
    '2bd4b79cf5828c2a9eab719d78af499303e4e5702dfaf24b33c9e54ab8e2fdb85d0574d04fb68fa7f624972022892c55136e282ead8777633cb924c486698cdbfe2d02253726f1af72cc9cb76a866cae6cad578914330d1ce76cc9141b954fcd303fb4cbeae4363bbca0151e9a9b6f5bb7',
  plaintext: JSON.stringify({ hello: 'world', n: 42 }),
};

describe('Mailbox SDK', () => {
  it('should generate valid secp256k1 keys', () => {
    const keys = Mailbox.generateKeys();
    expect(keys.privateKey).toMatch(/^0x[a-fA-F0-9]{64}$/);
    expect(keys.publicKey).toMatch(/^0x[a-fA-F0-9]{128}$/);
    expect(keys.compressedPublicKey).toMatch(/^0x(02|03)[a-fA-F0-9]{64}$/);
  });

  it('should decrypt deterministic test vector payload', async () => {
    const decrypted = await Mailbox.decryptPayload(deterministicVector.privateKey, deterministicVector.encryptedPayload);
    expect(decrypted).toBe(deterministicVector.plaintext);
  });

  it('should encrypt and decrypt a string payload using compressed public keys', async () => {
    const bob = Mailbox.generateKeys();
    const payload = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...';

    // Alice encrypts for Bob using Bob's COMPRESSED public key (as stored in registry)
    const encrypted = await Mailbox.encryptPayload(bob.compressedPublicKey, payload);

    // The envelope should be a stringified payload from eth-crypto
    expect(typeof encrypted).toBe('string');
    expect(encrypted.length).toBeGreaterThan(100);

    // Bob decrypts using his private key
    const decrypted = await Mailbox.decryptPayload(bob.privateKey, encrypted);
    expect(decrypted).toBe(payload);
  });

  it('should encrypt and decrypt a JSON object payload', async () => {
    const bob = Mailbox.generateKeys();
    const payload = { ip: '192.168.1.100', user: 'ubuntu' };

    const encrypted = await Mailbox.encryptPayload(bob.compressedPublicKey, payload);
    const decryptedStr = await Mailbox.decryptPayload(bob.privateKey, encrypted);

    const decryptedObj = JSON.parse(decryptedStr);
    expect(decryptedObj.ip).toBe(payload.ip);
    expect(decryptedObj.user).toBe(payload.user);
  });

  it('should convert deterministic vector envelope to on-chain bytes and back', async () => {
    const asBytes = Mailbox.envelopeToBytes(deterministicVector.encryptedPayload);
    const restoredEnvelope = Mailbox.envelopeFromBytes(asBytes);
    const decrypted = await Mailbox.decryptPayload(deterministicVector.privateKey, restoredEnvelope);

    expect(asBytes).toMatch(/^0x[a-fA-F0-9]+$/);
    expect(decrypted).toBe(deterministicVector.plaintext);
  });

  it('should reject invalid envelope bytes', () => {
    expect(() => Mailbox.envelopeFromBytes('0x123')).toThrow(/Invalid envelope bytes/);
  });

  it('should reject malformed encrypted payload strings', async () => {
    const bob = Mailbox.generateKeys();
    await expect(Mailbox.decryptPayload(bob.privateKey, 'not-an-envelope')).rejects.toThrow(
      /Invalid encrypted payload format/
    );
  });

  it('should reject malformed recipient public keys', async () => {
    await expect(Mailbox.encryptPayload('0x1234', 'hello')).rejects.toThrow(/Invalid public key format/);
    await expect(
      Mailbox.encryptPayload('0x056a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3', 'hello')
    ).rejects.toThrow(/Invalid public key format|could not be parsed/i);
  });

  it('should encrypt for deterministic compressed key and decrypt with deterministic private key', async () => {
    const encrypted = await Mailbox.encryptPayload(deterministicVector.compressedPublicKey, 'fixed-destination');
    const decrypted = await Mailbox.decryptPayload(deterministicVector.privateKey, encrypted);
    expect(decrypted).toBe('fixed-destination');
  });
});
