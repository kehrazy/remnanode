import type { Socket } from 'node:net';

import assert from 'node:assert/strict';
import { Duplex } from 'node:stream';
import { test } from 'node:test';

import { OpenVpnManagement } from '../src/modules/openvpn/openvpn.management';

test('management authenticates fragmented events and charges final counters once', () => {
    const commands: string[] = [];
    const socket = new Duplex({
        read() {},
        write(chunk, _encoding, callback) {
            commands.push(chunk.toString());
            callback();
        },
    });
    const charged: { userId: string; uplink: number; downlink: number }[] = [];
    const authorized = new Map([
        ['23-revision', '23'],
        ['24-revision', '24'],
    ]);
    const manager = new OpenVpnManagement(
        socket as Socket,
        (name) => authorized.get(name) ?? null,
        (userId, usage) => charged.push({ userId, ...usage }),
    );
    manager.start();
    manager.receive('>CLIENT:CONNECT,7,1\n>CLIENT:ENV,common_na');
    assert.deepEqual(manager.onlineUsers(), []);
    manager.receive('me=23-revision\n>CLIENT:ENV,END\n');
    assert.equal(commands.at(-1), 'client-auth-nt 7 1\n');
    manager.receive('>BYTECOUNT_CLI:7,100,200\n>BYTECOUNT_CLI:7,100,200\n');
    manager.receive(
        '>BYTECOUNT_CLI:7,-1,201\n>BYTECOUNT_CLI:7,NaN,201\n>BYTECOUNT_CLI:7,9007199254740992,201\n',
    );
    manager.receive('>CLIENT:REAUTH,7,2\n>CLIENT:ENV,common_name=24-revision\n>CLIENT:ENV,END\n');
    assert.match(commands.at(-1)!, /^client-deny 7 2/);
    authorized.delete('23-revision');
    manager.enforceAccounts();
    assert.equal(commands.at(-1), 'client-kill 7\n');
    manager.receive(
        '>CLIENT:DISCONNECT,7\n>CLIENT:ENV,bytes_received=130\n>CLIENT:ENV,bytes_sent=260\n>CLIENT:ENV,END\n',
    );
    manager.receive('>BYTECOUNT_CLI:7,130,260\n');
    assert.deepEqual(manager.onlineUsers(), []);
    assert.deepEqual(
        charged.filter((entry) => entry.uplink || entry.downlink),
        [
            { userId: '23', uplink: 100, downlink: 200 },
            { userId: '23', uplink: 30, downlink: 60 },
        ],
    );
    manager.receive('>CLIENT:CONNECT,8,0\n>CLIENT:ENV,common_name=unknown\n>CLIENT:ENV,END\n');
    assert.match(commands.at(-1)!, /^client-deny 8 0/);
    socket.destroy();
});
