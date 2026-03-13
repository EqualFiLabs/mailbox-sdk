export interface KeyPair {
  privateKey: string;
  publicKey: string;
  compressedPublicKey: string;
}

export interface EncryptedEnvelope {
  iv: string;
  ephemPublicKey: string;
  ciphertext: string;
  mac: string;
}