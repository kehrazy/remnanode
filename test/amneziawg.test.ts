import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { AmneziaWgEndpointSchema, AmneziaWgParametersSchema, createAwgParameters, validAwgSignature } from '../src/modules/amneziawg/amneziawg.types';
import { AmneziaWgManager } from '../src/modules/amneziawg/amneziawg.manager';
import { amneziaWgRequest, parseAmneziaWgUsage } from '../src/modules/amneziawg/amneziawg.uapi';

test('obfuscation validation rejects padding and packet shapes known to fail in native cores', () => {
    const endpoint = AmneziaWgEndpointSchema.parse({
        uuid: randomUUID(), name: 'Test', address: '192.0.2.1', port: 5443,
        network: '10.95.0.0/24', dnsServers: ['1.1.1.1'],
    });
    const parameters = createAwgParameters(endpoint);
    assert.equal(AmneziaWgParametersSchema.safeParse({ ...parameters, S3: 0 }).success, false);
    assert.equal(AmneziaWgParametersSchema.safeParse({ ...parameters, H2: parameters.H1 }).success, false);
    assert.equal(AmneziaWgParametersSchema.safeParse({ ...parameters, S1: 12, S2: 13, RandomTrailers: true }).success, false);
    assert.equal(AmneziaWgParametersSchema.safeParse({ ...parameters, HeaderProtectionKey: Buffer.alloc(32).toString('base64') }).success, false);
    assert.equal(validAwgSignature('<r -1>'), false);
    assert.equal(validAwgSignature('<r 1281>'), false);
    assert.equal(validAwgSignature('<r 1000><r 1000>'), false);
    assert.equal(validAwgSignature('<b 0x123>'), false);
    assert.equal(validAwgSignature('<r 2><b 0x0100><rc 28>'), true);
});

test('UAPI handles fragmented replies, native errno and truncated responses without exposing keys', async (t) => {
    const root = await mkdtemp(join(tmpdir(), 'rwawg-uapi-'));
    const path = join(root, 'control.sock');
    const peer = randomBytes(32).toString('hex');
    let response = `private_key=${randomBytes(32).toString('hex')}\npublic_key=${peer}\nrx_bytes=100\ntx_bytes=200\nlast_handshake_time_sec=300\nerrno=0\n\n`;
    const server = createServer((socket) => socket.once('data', () => {
        const body = response;
        socket.write(body.slice(0, 11));
        setImmediate(() => socket.end(body.slice(11)));
    }));
    await new Promise<void>((resolve) => server.listen(path, resolve));
    t.after(async () => {
        await new Promise<void>((resolve) => server.close(() => resolve()));
        await rm(root, { recursive: true, force: true });
    });
    const result = await amneziaWgRequest(path, 'get=1');
    assert.deepEqual(parseAmneziaWgUsage(result).get(peer), { rx: 100, tx: 200, handshake: 300 });
    response = 'errno=-22\n\n';
    await assert.rejects(amneziaWgRequest(path, 'get=1'), /errno -22/);
    response = 'private_key=not-for-errors\n';
    await assert.rejects(amneziaWgRequest(path, 'get=1'), /was truncated/);
});

test('initialized AmneziaWG volumes fail closed when state disappears or becomes corrupt', async (t) => {
    const root = await mkdtemp(join(tmpdir(), 'rwawg-state-'));
    t.after(() => rm(root, { recursive: true, force: true }));
    const original = new AmneziaWgManager({ root });
    await original.onModuleInit();
    await original.onModuleDestroy();
    await rm(join(root, 'state.json'));
    const missing = new AmneziaWgManager({ root });
    await missing.onModuleInit();
    assert.match(missing.status().error!, /missing/);
    await assert.rejects(missing.sync({ generation: 1, users: [] }), /missing/);
    await writeFile(join(root, 'state.json'), '{');
    const corrupt = new AmneziaWgManager({ root });
    await corrupt.onModuleInit();
    assert.match(corrupt.status().error!, /unreadable/);
});
