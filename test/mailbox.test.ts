import { describe, it, expect } from 'vitest';
import { Mailbox } from '../src/mailbox';

describe('Mailbox SDK', () => {
  it('should generate valid secp256k1 keys', () => {
    const keys = Mailbox.generateKeys();
    expect(keys.privateKey).toMatch(/^0x[a-fA-F0-9]{64}$/);
    expect(keys.publicKey).toMatch(/^0x[a-fA-F0-9]{128}$/);
    expect(keys.compressedPublicKey).toMatch(/^0x(02|03)[a-fA-F0-9]{64}$/);
  });

  it('should encrypt and decrypt a string payload using compressed public keys', async () => {
    const bob = Mailbox.generateKeys();
    const payload = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...";

    // Alice encrypts for Bob using Bob's COMPRESSED public key (as stored in registry)
    const encrypted = await Mailbox.encryptPayload(bob.compressedPublicKey, payload);
    
    // The envelope should be a stringified hex payload from eth-crypto
    expect(typeof encrypted).toBe('string');
    expect(encrypted.length).toBeGreaterThan(100);

    // Bob decrypts using his private key
    const decrypted = await Mailbox.decryptPayload(bob.privateKey, encrypted);
    expect(decrypted).toBe(payload);
  });

  it('should encrypt and decrypt a JSON object payload', async () => {
    const bob = Mailbox.generateKeys();
    const payload = { ip: "192.168.1.100", user: "ubuntu" };

    const encrypted = await Mailbox.encryptPayload(bob.compressedPublicKey, payload);
    const decryptedStr = await Mailbox.decryptPayload(bob.privateKey, encrypted);
    
    const decryptedObj = JSON.parse(decryptedStr);
    expect(decryptedObj.ip).toBe(payload.ip);
    expect(decryptedObj.user).toBe(payload.user);
  });
});