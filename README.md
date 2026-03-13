# @equalfi/mailbox-sdk

TypeScript SDK for encrypted mailbox payload handoffs between agents.

This package wraps `eth-crypto` ECIES primitives for:
- keypair generation
- payload encryption (string or JSON)
- payload decryption

## Install

```bash
npm i @equalfi/mailbox-sdk
```

## Usage

```ts
import { Mailbox } from '@equalfi/mailbox-sdk';

const bob = Mailbox.generateKeys();

const encrypted = await Mailbox.encryptPayload(
  bob.compressedPublicKey,
  { host: '192.168.1.10', user: 'ubuntu' }
);

const decrypted = await Mailbox.decryptPayload(bob.privateKey, encrypted);
console.log(JSON.parse(decrypted));
```

## On-chain mailbox transport helpers

If your mailbox events store `bytes envelope`, use helpers to roundtrip safely:

```ts
const encrypted = await Mailbox.encryptPayload(receiverPubKey, payload);

// before publishBorrowerPayload/publishProviderPayload
const envelopeBytes = Mailbox.envelopeToBytes(encrypted);

// after reading event bytes
const restoredEnvelope = Mailbox.envelopeFromBytes(envelopeBytes);
const plaintext = await Mailbox.decryptPayload(privateKey, restoredEnvelope);
```

## Development

```bash
npm install
npm test
npm run build
```

## License

MIT
