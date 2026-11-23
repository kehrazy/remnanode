import assert from 'node:assert/strict';
import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';

import { OpenVpnManager } from '../src/modules/openvpn/openvpn.manager';

const execute = promisify(execFile);

async function eventually(check: () => Promise<boolean>, message: string): Promise<void> {
    for (let attempt = 0; attempt < 150; attempt++) {
        if (await check()) return;
        await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(message);
}

test(
    'real OpenVPN tunnels authenticate, carry traffic, persist and revoke',
    {
        skip: process.env.OPENVPN_RUNTIME_TEST !== 'true',
        timeout: 180_000,
    },
    async (t) => {
        const root = await mkdtemp(join(tmpdir(), 'rwovp-'));
        const clientNamespace = `ovc${process.pid}`;
        const destinationNamespace = `ovd${process.pid}`;
        let manager = new OpenVpnManager({ root });
        let client: ChildProcess | undefined;
        let http: ChildProcess | undefined;
        const children = new Set<ChildProcess>();
        t.after(async () => {
            for (const child of children) child.kill('SIGKILL');
            await manager.onModuleDestroy();
            await execute('ip', ['netns', 'del', clientNamespace]).catch(() => undefined);
            await execute('ip', ['netns', 'del', destinationNamespace]).catch(() => undefined);
            await rm(root, { recursive: true, force: true });
        });
        await execute('sysctl', ['-w', 'net.ipv4.ip_forward=1']);
        for (const [namespace, host, peer, address] of [
            [clientNamespace, 'ovc-host', 'ovc-peer', '172.31.254'],
            [destinationNamespace, 'ovd-host', 'ovd-peer', '198.18.0'],
        ]) {
            await execute('ip', ['netns', 'add', namespace]);
            await execute('ip', ['link', 'add', host, 'type', 'veth', 'peer', 'name', peer]);
            await execute('ip', ['link', 'set', peer, 'netns', namespace]);
            await execute('ip', ['addr', 'add', `${address}.1/24`, 'dev', host]);
            await execute('ip', ['link', 'set', host, 'up']);
            await execute('ip', [
                'netns',
                'exec',
                namespace,
                'ip',
                'addr',
                'add',
                `${address}.2/24`,
                'dev',
                peer,
            ]);
            await execute('ip', ['netns', 'exec', namespace, 'ip', 'link', 'set', peer, 'up']);
            await execute('ip', ['netns', 'exec', namespace, 'ip', 'link', 'set', 'lo', 'up']);
            await execute('ip', [
                'netns',
                'exec',
                namespace,
                'ip',
                'route',
                'add',
                'default',
                'via',
                `${address}.1`,
            ]);
        }
        const payload = Buffer.alloc(1_048_576, 0x61);
        await writeFile(join(root, 'payload'), payload);
        http = spawn(
            'ip',
            [
                'netns',
                'exec',
                destinationNamespace,
                'python3',
                '-m',
                'http.server',
                '18080',
                '--bind',
                '198.18.0.2',
                '--directory',
                root,
            ],
            { stdio: 'ignore' },
        );
        children.add(http);
        await manager.onModuleInit();
        for (const [index, protocol, controlChannel] of [
            [0, 'udp', 'tls-crypt-v2'],
            [1, 'udp', 'tls-crypt'],
            [2, 'udp', 'tls-auth'],
            [3, 'tcp', 'tls-crypt-v2'],
        ] as const) {
            await t.test(`${protocol} ${controlChannel}`, async (subtest) => {
                const endpoint = {
                    uuid: randomUUID(),
                    name: 'Integration endpoint',
                    address: '172.31.254.1',
                    port: 23450 + index,
                    protocol,
                    controlChannel,
                    network: `10.87.${index}.0/24`,
                    dnsServers: ['1.1.1.1'],
                };
                await manager.configure(endpoint);
                subtest.after(async () => {
                    client?.kill('SIGKILL');
                    await manager.remove(endpoint.uuid);
                });
                let generation = Date.now();
                const user = {
                    id: '23',
                    credentialId: randomUUID(),
                    expiresAt: new Date(Date.now() + 60_000).toISOString(),
                    endpointUuids: [endpoint.uuid],
                };
                await manager.sync({ generation: ++generation, users: [user] });
                const profile = await manager.download(endpoint.uuid, user.id);
                const profilePath = join(root, 'client.ovpn');
                const logPath = join(root, 'client.log');
                await writeFile(profilePath, profile, { mode: 0o600 });
                await writeFile(logPath, '');
                client = spawn(
                    'ip',
                    [
                        'netns',
                        'exec',
                        clientNamespace,
                        '/usr/sbin/openvpn',
                        '--config',
                        profilePath,
                        '--log',
                        logPath,
                    ],
                    { stdio: 'ignore' },
                );
                children.add(client);
                await eventually(
                    async () =>
                        (await readFile(logPath, 'utf8').catch(() => '')).includes(
                            'Initialization Sequence Completed',
                        ),
                    `Client did not establish ${protocol}/${controlChannel}: ${await readFile(logPath, 'utf8').catch(() => '')}`,
                );
                const route = await execute('ip', [
                    'netns',
                    'exec',
                    clientNamespace,
                    'ip',
                    'route',
                    'get',
                    '198.18.0.2',
                ]);
                assert.match(route.stdout, /dev tun/);
                await execute('ip', [
                    'netns',
                    'exec',
                    clientNamespace,
                    'curl',
                    '-fsS',
                    '--max-time',
                    '10',
                    '--output',
                    join(root, 'download'),
                    'http://198.18.0.2:18080/payload',
                ]);
                assert.deepEqual(await readFile(join(root, 'download')), payload);
                await manager.sync({ generation: ++generation, users: [] });
                await assert.rejects(manager.download(endpoint.uuid, user.id), /unavailable/);
                await eventually(
                    async () => !(await manager.usage()).users.some((entry) => entry.online),
                    'Revoked session remained online',
                );
                if (client.exitCode === null && client.signalCode === null) {
                    const exited = new Promise<void>((resolve) =>
                        client!.once('exit', () => resolve()),
                    );
                    client.kill('SIGTERM');
                    await exited;
                }
                client = undefined;
                const usage = await manager.usage();
                assert.ok(
                    usage.users.find((entry) => entry.id === user.id)!.downlink >= payload.length,
                );
                await manager.onModuleDestroy();
                manager = new OpenVpnManager({ root });
                await manager.onModuleInit();
                assert.deepEqual(await manager.usage(), usage);
                await manager.sync({ generation: ++generation, users: [user] });
                assert.equal(await manager.download(endpoint.uuid, user.id), profile);
                await manager.sync({
                    generation: ++generation,
                    users: [{ ...user, credentialId: randomUUID() }],
                });
                assert.notEqual(await manager.download(endpoint.uuid, user.id), profile);
                await manager.sync({
                    generation: ++generation,
                    users: [{ ...user, expiresAt: new Date(0).toISOString() }],
                });
                await assert.rejects(manager.download(endpoint.uuid, user.id), /unavailable/);
                await manager.remove(endpoint.uuid);
            });
        }
    },
);
