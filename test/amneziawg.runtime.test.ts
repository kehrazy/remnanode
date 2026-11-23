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
    const secondNamespace = 'aw2' + process.pid;
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
        await execute('ip', ['netns', 'del', secondNamespace]).catch(() => undefined);
        await rm(root, { recursive: true, force: true });
    });
    await execute('sysctl', ['-w', 'net.ipv4.ip_forward=1']);
    for (const [namespace, host, peer, address] of [
        [clientNamespace, 'awc-host', 'awc-peer', '172.31.253'],
        [destinationNamespace, 'awd-host', 'awd-peer', '198.19.0'],
        [secondNamespace, 'aw2-host', 'aw2-peer', '172.31.254'],
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
            let direct = await manager.download(endpoint.uuid, user.id);
            assert.equal(await manager.download(endpoint.uuid, user.id), direct);
            const second = await manager.download(endpoint.uuid, user.id, { deviceUuid: user.devices[1].uuid });
            assert.notEqual(/^PrivateKey = (.+)$/m.exec(direct)![1], /^PrivateKey = (.+)$/m.exec(second)![1]);
            assert.notEqual(/^Address = (.+)$/m.exec(direct)![1], /^Address = (.+)$/m.exec(second)![1]);
            const before = (await manager.usage()).users.find((entry) => entry.id === user.id)?.downlink ?? 0;
            for (const viaRelay of [false, true]) {
                const profile = await manager.download(endpoint.uuid, user.id, viaRelay ? { port: relay.port } : {});
                const [address, ipv6] = /^Address = (.+)$/m.exec(profile)![1].split(', ');
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
                await execute('ip', ['netns', 'exec', clientNamespace, 'ip', '-6', 'addr', 'add', ipv6, 'dev', clientInterface]);
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
                await execute('ip', ['netns', 'exec', clientNamespace, 'ip', '-6', 'route', 'replace', '::/0', 'dev', clientInterface]);
                assert.match((await execute('ip', ['netns', 'exec', clientNamespace, 'ip', '-6', 'route', 'get', '2001:db8::2'])).stdout, /dev awg-client/);
                await execute('ip6tables', ['-C', 'FORWARD', '-i', 'rwawg' + endpoint.uuid.replaceAll('-', '').slice(0, 8), '-m', 'comment', '--comment', 'RWAWG' + endpoint.uuid.replaceAll('-', '').slice(0, 10), '-j', 'DROP']);
                if (viaRelay) {
                    await manager.sync({ generation: generation++, users: [{ ...user, endpointUuids: [] }] });
                    await assert.rejects(manager.download(endpoint.uuid, user.id));
                    await assert.rejects(execute('ip', ['netns', 'exec', clientNamespace, 'curl', '-fsS', '--max-time', '2', 'http://198.19.0.2:18081/payload']));
                    await manager.sync({ generation: generation++, users: [user] });
                    assert.equal(await manager.download(endpoint.uuid, user.id), direct);
                    // Removing a peer destroys its session; an unchanged saved profile reconnects with a fresh handshake.
                    client.kill('SIGTERM');
                    await new Promise<void>((resolve) => client!.once('exit', () => resolve()));
                    children.delete(client);
                    client = spawn('ip', ['netns', 'exec', clientNamespace, binary, '-f', clientInterface], {
                        env: { ...process.env, LOG_LEVEL: 'error', GOMAXPROCS: '1' }, stdio: 'ignore',
                    });
                    children.add(client);
                    await eventually(async () => {
                        try { await execute('ip', ['netns', 'exec', clientNamespace, tools, 'show', clientInterface]); return true; }
                        catch { return false; }
                    }, 'Native client did not restart');
                    await execute('ip', ['netns', 'exec', clientNamespace, tools, 'setconf', clientInterface, config]);
                    await execute('ip', ['netns', 'exec', clientNamespace, 'ip', 'addr', 'add', address, 'dev', clientInterface]);
                await execute('ip', ['netns', 'exec', clientNamespace, 'ip', '-6', 'addr', 'add', ipv6, 'dev', clientInterface]);
                    await execute('ip', ['netns', 'exec', clientNamespace, 'ip', 'link', 'set', clientInterface, 'mtu', '1280', 'up']);
                    await execute('ip', ['netns', 'exec', clientNamespace, 'ip', 'route', 'replace', '198.19.0.2/32', 'dev', clientInterface]);
                    await execute('ip', ['netns', 'exec', clientNamespace, 'curl', '-fsS', '--max-time', '15', '--output', join(root, 'download'), 'http://198.19.0.2:18081/payload']);
                }
                client.kill('SIGTERM');
                await new Promise<void>((resolve) => client!.once('exit', () => resolve()));
                children.delete(client);
                client = undefined;
                console.log(`Native ${version}/${preset}/${viaRelay ? 'relay' : 'direct'}: verified 1 MiB through the managed interface`);
            }
            if (version === '3.1' && preset === 'default') {
                const running = new Map<string, ChildProcess>();
                async function connect(profile: string, namespace: string) {
                    const previous = running.get(namespace);
                    if (previous) {
                        previous.kill('SIGTERM');
                        await new Promise<void>((resolve) => previous.once('exit', () => resolve()));
                        children.delete(previous);
                    }
                    const config = join(root, namespace + '.conf');
                    await writeFile(config, profile.split('\n').filter((line) => !/^(Address|DNS|MTU) =/.test(line)).join('\n'), { mode: 0o600 });
                    const child = spawn('ip', ['netns', 'exec', namespace, binary, '-f', clientInterface], { env: { ...process.env, LOG_LEVEL: 'error', GOMAXPROCS: '1', WG_PROCESS_FOREGROUND: '1' }, stdio: 'ignore' });
                    children.add(child);
                    running.set(namespace, child);
                    await eventually(async () => {
                        try { await execute('ip', ['netns', 'exec', namespace, tools, 'show', clientInterface]); return true; }
                        catch { return false; }
                    }, 'Additional native client did not start');
                    await execute('ip', ['netns', 'exec', namespace, tools, 'setconf', clientInterface, config]);
                    const [ipv4, ipv6] = /^Address = (.+)$/m.exec(profile)![1].split(', ');
                    for (const [family, address] of [['-4', ipv4], ['-6', ipv6]])
                        await execute('ip', ['netns', 'exec', namespace, 'ip', family, 'addr', 'add', address, 'dev', clientInterface, ...(family === '-6' ? ['nodad'] : [])]);
                    await execute('ip', ['netns', 'exec', namespace, 'ip', 'link', 'set', clientInterface, 'mtu', '1280', 'up']);
                    await execute('ip', ['netns', 'exec', namespace, 'ip', 'route', 'replace', '198.19.0.2/32', 'dev', clientInterface]);
                    await execute('ip', ['netns', 'exec', namespace, 'ip', '-6', 'route', 'replace', '::/0', 'dev', clientInterface]);
                }
                async function transfer(namespace: string, timeout = '15') {
                    const output = join(root, namespace + '.download');
                    await execute('ip', ['netns', 'exec', namespace, 'curl', '-fsS', '--max-time', timeout, '--output', output, 'http://198.19.0.2:18081/payload']);
                    assert.deepEqual(await readFile(output), payload);
                }
                await execute('sysctl', ['-w', 'net.ipv6.conf.all.forwarding=1']);
                await execute('ip', ['-6', 'addr', 'add', '2001:db8:9500::1/64', 'dev', 'awd-host', 'nodad']);
                await execute('ip', ['netns', 'exec', destinationNamespace, 'ip', '-6', 'addr', 'add', '2001:db8:9500::2/64', 'dev', 'awd-peer', 'nodad']);
                await execute('ip', ['netns', 'exec', destinationNamespace, 'ip', '-6', 'route', 'add', 'default', 'via', '2001:db8:9500::1']);
                const ipv6Http = spawn('ip', ['netns', 'exec', destinationNamespace, 'python3', '-m', 'http.server', '18081', '--bind', '2001:db8:9500::2', '--directory', root], { stdio: ['ignore', 'ignore', 'pipe'] });
                ipv6Http.stderr?.on('data', (chunk: Buffer) => console.error(chunk.toString()));
                children.add(ipv6Http);
                await eventually(async () => {
                    try { await execute('curl', ['--noproxy', '*', '-gfsSI', '--max-time', '1', 'http://[2001:db8:9500::2]:18081/payload']); return true; }
                    catch { return false; }
                }, 'IPv6 destination fixture did not start');
                await connect(direct, clientNamespace);
                await connect(second, secondNamespace);
                await Promise.all([transfer(clientNamespace), transfer(secondNamespace)]);
                await assert.rejects(execute('ip', ['netns', 'exec', clientNamespace, 'curl', '--noproxy', '*', '-gfsS', '--max-time', '2', 'http://[2001:db8:9500::2]:18081/payload']));
                const ipv6Rules = (await execute('ip6tables-save', ['-c'])).stdout;
                const drop = ipv6Rules.split('\n').find((line) => line.includes('-A FORWARD -i rwawg' + endpoint.uuid.replaceAll('-', '').slice(0, 8)));
                assert.ok(drop && Number(/^\[(\d+):/.exec(drop)![1]) > 0, 'IPv6 packets did not reach the owned drop rule');
                user.credentialId = randomUUID();
                await manager.sync({ generation: generation++, users: [user] });
                await assert.rejects(transfer(clientNamespace, '2'));
                const rotated = await manager.download(endpoint.uuid, user.id);
                assert.notEqual(/^PrivateKey = (.+)$/m.exec(rotated)![1], /^PrivateKey = (.+)$/m.exec(direct)![1]);
                direct = rotated;
                await connect(direct, clientNamespace);
                await transfer(clientNamespace);
                await assert.rejects(transfer(secondNamespace, '2'));
                const removedDevice = user.devices[1].uuid;
                user.devices = [user.devices[0]];
                await manager.sync({ generation: generation++, users: [user] });
                await assert.rejects(manager.download(endpoint.uuid, user.id, { deviceUuid: removedDevice }));
                user.expiresAt = new Date(Date.now() + 50).toISOString();
                await manager.sync({ generation: generation++, users: [user] });
                await eventually(async () => manager.status().endpoints.find((entry) => entry.uuid === endpoint.uuid)!.peers === 0, 'Expired peers remained installed');
                await assert.rejects(transfer(clientNamespace, '2'));
                await assert.rejects(manager.download(endpoint.uuid, user.id));
                user.expiresAt = new Date(Date.now() + 120_000).toISOString();
                await manager.sync({ generation: generation++, users: [user] });
                assert.equal(await manager.download(endpoint.uuid, user.id), direct);
                await connect(direct, clientNamespace);
                await transfer(clientNamespace);
                for (const child of running.values()) {
                    child.kill('SIGTERM');
                    await new Promise<void>((resolve) => child.once('exit', () => resolve()));
                    children.delete(child);
                }
                console.log('Simultaneous devices, credential rotation and local expiry enforcement passed');
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
