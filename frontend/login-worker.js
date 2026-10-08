'use strict';

const sshpk = require('sshpk');
const crypto = require('crypto');
const {Buffer} = require('buffer');
const {BigInteger} = require('jsbn');

let privateKey = null;
let keyId = null;

function discardKey() {
    if (privateKey) {
        for (const part of privateKey.parts) part.data.fill(0);
    }
    privateKey = null;
    keyId = null;
}

self.onmessage = async ({data}) => {
    try {
        if (data.type === 'load') {
            if (!data.file || data.file.size > 65536) throw new Error('invalid_key');
            const bytes = Buffer.from(await data.file.arrayBuffer());
            try {
                privateKey = sshpk.parsePrivateKey(bytes, 'auto', {passphrase: data.passphrase || ''});
            } finally {
                bytes.fill(0);
                data.passphrase = '';
            }
            if (!['rsa', 'ecdsa', 'ed25519'].includes(privateKey.type)) throw new Error('unsupported_key');
            // OpenSSH omits RSA CRT exponents. sshpk's fallback subtracts a JS
            // number instead of a BigInteger, so supply the correct exponents.
            if (privateKey.type === 'rsa') {
                const d = new BigInteger(privateKey.part.d.data);
                const one = new BigInteger('1', 10);
                for (const [name, prime] of [['dmodp', 'p'], ['dmodq', 'q']]) {
                    if (!privateKey.part[name]) {
                        const value = d.mod(new BigInteger(privateKey.part[prime].data).subtract(one));
                        const part = {name, data: Buffer.from(value.toByteArray())};
                        privateKey.part[name] = part;
                        privateKey.parts.push(part);
                    }
                }
            }
            const publicIdentity = privateKey.toPublic().toString('ssh').trim().split(/\s+/).slice(0, 2).join(' ');
            keyId = crypto.createHash('sha256').update(publicIdentity, 'utf8').digest('hex');
            self.postMessage({type: 'loaded', key_id: keyId});
        } else if (data.type === 'sign') {
            // Only sign this site's login protocol, never arbitrary server-provided data.
            const lines = String(data.message).split('\n');
            if (!privateKey || lines.length !== 7 || lines[0] !== 'gpu-monitor-login-v1' ||
                lines[1] !== self.location.origin || lines[3] !== keyId ||
                lines[4] !== data.challenge_id || !/^[a-z_][a-z0-9_-]*\$?$/.test(lines[2]) ||
                !/^[A-Za-z0-9_-]{43}$/.test(lines[4]) || !/^[A-Za-z0-9_-]{43}$/.test(lines[6]) ||
                !/^\d+$/.test(lines[5]) || Number(lines[5]) < Date.now() / 1000 ||
                Number(lines[5]) > Date.now() / 1000 + 65) throw new Error('invalid_challenge');
            const signer = privateKey.createSign(privateKey.type === 'ed25519' ? 'sha512' : 'sha256');
            signer.update(Buffer.from(data.message, 'utf8'));
            const signature = signer.sign().toString('asn1');
            discardKey();
            self.postMessage({type: 'signed', signature});
            self.close();
        } else {
            throw new Error('invalid_request');
        }
    } catch (_) {
        discardKey();
        self.postMessage({type: 'error', error: data.type === 'load' ? 'invalid_key' : 'invalid_challenge'});
        self.close();
    }
};
