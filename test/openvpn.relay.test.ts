import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import dgram from 'node:dgram';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createConnection, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { OpenVpnManager } from '../src/modules/openvpn/openvpn.manager';

for (const protocol of ['udp', 'tcp'] as const) {
    test(
        `${protocol} relay transfers data, survives restart and closes on disable`,
        { timeout: 10_000 },
        async (t) => {
            const root = await mkdtemp(join(tmpdir(), 'remnanode-openvpn-'));
            let manager = new OpenVpnManager({
                root,
                manageFirewall: false,
                listenAddress: '127.0.0.1',
            });
            const clients: { destroy(): void }[] = [];
            t.after(async () => {
                for (const client of clients) client.destroy();
                await manager.onModuleDestroy();
                await rm(root, { recursive: true, force: true });
            });
            const echo =
                protocol === 'tcp'
                    ? createServer((socket) => socket.pipe(socket))
                    : dgram.createSocket('udp4');
            if (protocol === 'tcp')
                (echo as ReturnType<typeof createServer>).listen(0, '127.0.0.1');
            else {
                (echo as dgram.Socket).on('message', (packet, peer) =>
                    (echo as dgram.Socket).send(packet, peer.port, peer.address),
                );
                (echo as dgram.Socket).bind(0, '127.0.0.1');
            }
            await once(echo, 'listening');
            t.after(() => echo.close());
            const reservation = protocol === 'tcp' ? createServer() : dgram.createSocket('udp4');
            if (protocol === 'tcp')
                (reservation as ReturnType<typeof createServer>).listen(0, '127.0.0.1');
            else (reservation as dgram.Socket).bind(0, '127.0.0.1');
            await once(reservation, 'listening');
            const port = (reservation.address() as { port: number }).port;
            await new Promise<void>((resolve) => reservation.close(() => resolve()));
            const endpoint = {
                uuid: randomUUID(),
                name: 'Relay test',
                address: '127.0.0.1',
                port,
                protocol,
                controlChannel: 'tls-crypt-v2',
                network: '10.88.0.0/24',
                dnsServers: ['1.1.1.1'],
                mode: 'relay',
                targetAddress: '127.0.0.1',
                targetPort: (echo.address() as { port: number }).port,
            };
            await manager.onModuleInit();
            await manager.configure(endpoint);
            await assert.rejects(
                manager.configure({ ...endpoint, uuid: randomUUID() }),
                /already uses/,
            );
            for (let attempt = 0; attempt < 2; attempt++) {
                if (protocol === 'tcp') {
                    const client = createConnection(port, '127.0.0.1');
                    clients.push(client);
                    await once(client, 'connect');
                    const response = once(client, 'data');
                    client.write('real tcp traffic');
                    assert.equal((await response)[0].toString(), 'real tcp traffic');
                    await manager.configure({
                        ...endpoint,
                        name: 'Renamed route',
                        address: '192.0.2.100',
                        network: '10.89.0.0/24',
                        dnsServers: ['8.8.8.8'],
                    });
                    const afterRename = once(client, 'data');
                    client.write('same TCP connection');
                    assert.equal((await afterRename)[0].toString(), 'same TCP connection');
                    client.destroy();
                } else {
                    const client = dgram.createSocket('udp4');
                    try {
                        const replies: string[] = [];
                        const complete = new Promise<void>((resolve) =>
                            client.on('message', (packet) => {
                                replies.push(packet.toString());
                                if (replies.length === 4) resolve();
                            }),
                        );
                        for (let i = 0; i < 4; i++) client.send(`packet-${i}`, port, '127.0.0.1');
                        await complete;
                        assert.deepEqual(replies, ['packet-0', 'packet-1', 'packet-2', 'packet-3']);
                    } finally {
                        client.close();
                    }
                }
                if (attempt === 0) {
                    await manager.restart();
                    assert.equal(manager.status().endpoints[0].running, true);
                    await manager.onModuleDestroy();
                    manager = new OpenVpnManager({
                        root,
                        manageFirewall: false,
                        listenAddress: '127.0.0.1',
                    });
                    await manager.onModuleInit();
                    assert.equal(manager.status().endpoints[0].running, true);
                }
            }
            await manager.configure({ ...endpoint, isDisabled: true });
            assert.equal(manager.status().endpoints[0].running, false);
            const usage = await manager.usage();
            assert.equal(
                JSON.parse(await readFile(join(root, 'state.json'), 'utf8')).epoch,
                usage.epoch,
            );
            const configuring = manager.configure(endpoint);
            await manager.onModuleDestroy();
            await configuring;
            assert.equal(manager.status().endpoints[0].running, false);
            await assert.rejects(manager.configure(endpoint), /stopping/);
        },
    );
}

test('corrupt persistent state fails closed without replacing identity or keys', async () => {
    const root = await mkdtemp(join(tmpdir(), 'remnanode-openvpn-'));
    try {
        await writeFile(join(root, 'state.json'), '{}');
        const manager = new OpenVpnManager({
            root,
            manageFirewall: false,
            listenAddress: '127.0.0.1',
        });
        await manager.onModuleInit();
        assert.match(manager.status().error!, /restore its persistent volume/);
        await assert.rejects(manager.sync({ generation: 1, users: [] }), /unreadable/);
        assert.equal(await readFile(join(root, 'state.json'), 'utf8'), '{}');
    } finally {
        await rm(root, { recursive: true, force: true });
    }
});
