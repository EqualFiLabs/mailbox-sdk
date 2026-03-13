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

## Development

```bash
npm install
npm test
npm run build
```

## License

MIT
