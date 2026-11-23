import assert from 'node:assert/strict';
import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';

import { AmneziaWgManager } from '../src/modules/amneziawg/amneziawg.manager';
import { AmneziaWgEndpointSchema } from '../src/modules/amneziawg/amneziawg.types';

const execute = promisify(execFile);

async function eventually(check: () => Promise<boolean>, message: string): Promise<void> {
    for (let attempt = 0; attempt < 150; attempt++) {
        if (await check()) return;
        await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(message);
}

test('native AmneziaWG peers transfer real data through server and relay, persist and revoke', {
    skip: process.env.AMNEZIAWG_RUNTIME_TEST !== 'true', timeout: 240_000,
}, async (t) => {
    const root = await mkdtemp(join(tmpdir(), 'rwawg-'));
    const clientNamespace = 'awc' + process.pid;
    const destinationNamespace = 'awd' + process.pid;
    const clientInterface = 'awg-client';
    const binary = process.env.AMNEZIAWG_TEST_BINARY!;
    const tools = process.env.AMNEZIAWG_TEST_TOOLS!;
    let manager = new AmneziaWgManager({ root: join(root, 'state'), binary });
    const children = new Set<ChildProcess>();
    let client: ChildProcess | undefined;
    t.after(async () => {
        for (const child of children) child.kill('SIGTERM');
        await manager.onModuleDestroy();
        await execute('ip', ['netns', 'del', clientNamespace]).catch(() => undefined);
        await execute('ip', ['netns', 'del', destinationNamespace]).catch(() => undefined);
        await rm(root, { recursive: true, force: true });
    });
    await execute('sysctl', ['-w', 'net.ipv4.ip_forward=1']);
    for (const [namespace, host, peer, address] of [
        [clientNamespace, 'awc-host', 'awc-peer', '172.31.253'],
        [destinationNamespace, 'awd-host', 'awd-peer', '198.19.0'],
    ]) {
        await execute('ip', ['netns', 'add', namespace]);
        await execute('ip', ['link', 'add', host, 'type', 'veth', 'peer', 'name', peer]);
        await execute('ip', ['link', 'set', peer, 'netns', namespace]);
        await execute('ip', ['addr', 'add', `${address}.1/24`, 'dev', host]);
        await execute('ip', ['link', 'set', host, 'up']);
        await execute('ip', ['netns', 'exec', namespace, 'ip', 'addr', 'add', `${address}.2/24`, 'dev', peer]);
        await execute('ip', ['netns', 'exec', namespace, 'ip', 'link', 'set', peer, 'up']);
        await execute('ip', ['netns', 'exec', namespace, 'ip', 'link', 'set', 'lo', 'up']);
        await execute('ip', ['netns', 'exec', namespace, 'ip', 'route', 'add', 'default', 'via', `${address}.1`]);
    }
    const payload = Buffer.alloc(1_048_576, 0x61);
    await writeFile(join(root, 'payload'), payload);
    const http = spawn('ip', ['netns', 'exec', destinationNamespace, 'python3', '-c',
        'import http.server, socketserver, os, sys; os.chdir(sys.argv[1]); socketserver.TCPServer(("198.19.0.2", 18081), http.server.SimpleHTTPRequestHandler).serve_forever()', root,
    ], { stdio: 'ignore' });
    children.add(http);
    await eventually(async () => {
        try { await execute('curl', ['-fsSI', '--max-time', '1', 'http://198.19.0.2:18081/payload']); return true; }
        catch { return false; }
    }, 'HTTP fixture did not start');
    await manager.onModuleInit();
    let generation = 1;
    for (const version of ['3.1', '2.0']) {
        for (const preset of ['default', 'mobile']) {
            const endpoint = AmneziaWgEndpointSchema.parse({
                uuid: randomUUID(), name: 'Native integration', address: '172.31.253.1', port: 15443,
                generation: version, preset, network: '10.95.0.0/24', dnsServers: ['1.1.1.1'],
            });
            await manager.configure(endpoint);
            const relay = AmneziaWgEndpointSchema.parse({
                ...endpoint, uuid: randomUUID(), mode: 'relay', port: 15444,
                targetAddress: endpoint.address, targetPort: endpoint.port, network: '10.96.0.0/24',
            });
            await manager.configure(relay);
            const user = {
                id: '1', credentialId: randomUUID(), expiresAt: new Date(Date.now() + 120_000).toISOString(),
                endpointUuids: [endpoint.uuid], devices: [{ uuid: 'default', name: 'Default' }, { uuid: randomUUID(), name: 'Second device' }],
            };
            await manager.sync({ generation: generation++, users: [user] });
            const direct = await manager.download(endpoint.uuid, user.id);
            assert.equal(await manager.download(endpoint.uuid, user.id), direct);
            const second = await manager.download(endpoint.uuid, user.id, { deviceUuid: user.devices[1].uuid });
            assert.notEqual(/^PrivateKey = (.+)$/m.exec(direct)![1], /^PrivateKey = (.+)$/m.exec(second)![1]);
            assert.notEqual(/^Address = (.+)$/m.exec(direct)![1], /^Address = (.+)$/m.exec(second)![1]);
            const before = (await manager.usage()).users.find((entry) => entry.id === user.id)?.downlink ?? 0;
            for (const viaRelay of [false, true]) {
                const profile = await manager.download(endpoint.uuid, user.id, viaRelay ? { port: relay.port } : {});
                const address = /^Address = (.+)$/m.exec(profile)![1];
                const native = profile.split('\n').filter((line) => !/^(Address|DNS|MTU) =/.test(line)).join('\n');
                const config = join(root, 'client.conf');
                await writeFile(config, native, { mode: 0o600 });
                client = spawn('ip', ['netns', 'exec', clientNamespace, binary, '-f', clientInterface], {
                    env: { ...process.env, LOG_LEVEL: 'error', GOMAXPROCS: '1' }, stdio: ['ignore', 'ignore', 'pipe'],
                });
                client.stderr?.on('data', (chunk: Buffer) => console.error(chunk.toString()));
                children.add(client);
                await eventually(async () => {
                    try { await execute('ip', ['netns', 'exec', clientNamespace, tools, 'show', clientInterface]); return true; }
                    catch { return false; }
                }, 'Native client did not start');
                await execute('ip', ['netns', 'exec', clientNamespace, tools, 'setconf', clientInterface, config]);
                await execute('ip', ['netns', 'exec', clientNamespace, 'ip', 'addr', 'add', address, 'dev', clientInterface]);
                await execute('ip', ['netns', 'exec', clientNamespace, 'ip', 'link', 'set', clientInterface, 'mtu', '1280', 'up']);
                await execute('ip', ['netns', 'exec', clientNamespace, 'ip', 'route', 'replace', '198.19.0.2/32', 'dev', clientInterface]);
                try {
                    await execute('ip', ['netns', 'exec', clientNamespace, 'curl', '-fsS', '--max-time', '15', '--output', join(root, 'download'), 'http://198.19.0.2:18081/payload']);
                } catch (error) {
                    console.error('Failed route', version, preset, viaRelay);
                    console.error((await execute('ip', ['netns', 'exec', clientNamespace, tools, 'show', clientInterface, 'latest-handshakes'])).stdout);
                    console.error((await execute('ip', ['netns', 'exec', clientNamespace, tools, 'show', clientInterface, 'transfer'])).stdout);
                    console.error(manager.status());
                    throw error;
                }
                assert.deepEqual(await readFile(join(root, 'download')), payload);
                const route = (await execute('ip', ['netns', 'exec', clientNamespace, 'ip', 'route', 'get', '198.19.0.2'])).stdout;
                assert.match(route, /dev awg-client/);
                if (viaRelay) {
                    await manager.sync({ generation: generation++, users: [{ ...user, endpointUuids: [] }] });
                    await assert.rejects(manager.download(endpoint.uuid, user.id));
                    await assert.rejects(execute('ip', ['netns', 'exec', clientNamespace, 'curl', '-fsS', '--max-time', '2', 'http://198.19.0.2:18081/payload']));
                    await manager.sync({ generation: generation++, users: [user] });
                    assert.equal(await manager.download(endpoint.uuid, user.id), direct);
                    await execute('ip', ['netns', 'exec', clientNamespace, 'curl', '-fsS', '--max-time', '15', '--output', join(root, 'download'), 'http://198.19.0.2:18081/payload']);
                }
                client.kill('SIGTERM');
                await new Promise<void>((resolve) => client!.once('exit', () => resolve()));
                children.delete(client);
                client = undefined;
                console.log(`Native ${version}/${preset}/${viaRelay ? 'relay' : 'direct'}: verified 1 MiB through the managed interface`);
            }
            const usage = await manager.usage();
            assert.ok(usage.users.find((entry) => entry.id === user.id)!.downlink >= before + payload.length * 2);
            await manager.onModuleDestroy();
            manager = new AmneziaWgManager({ root: join(root, 'state'), binary });
            await manager.onModuleInit();
            assert.equal(await manager.download(endpoint.uuid, user.id), direct);
            assert.equal((await manager.usage()).epoch, usage.epoch);
            await manager.remove(relay.uuid);
            await manager.remove(endpoint.uuid);
        }
    }
});
