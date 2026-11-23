import { createConnection } from 'node:net';

export async function amneziaWgRequest(path: string, request: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const socket = createConnection(path);
        let response = '';
        socket.setEncoding('utf8');
        socket.setTimeout(5000, () => socket.destroy(new Error('AmneziaWG control request timed out')));
        socket.once('error', reject);
        socket.once('connect', () => socket.write(request + '\n\n'));
        socket.on('data', (chunk: string) => {
            response += chunk;
            if (response.length > 1024 * 1024) {
                socket.destroy(new Error('AmneziaWG control response is too large'));
                return;
            }
            if (!response.endsWith('\n\n')) return;
            socket.destroy();
            const status = /(?:^|\n)errno=(-?\d+)\n\n$/.exec(response);
            if (!status || status[1] !== '0') {
                reject(new Error('AmneziaWG control request failed: errno ' + (status?.[1] ?? 'missing')));
            } else resolve(response);
        });
        socket.once('end', () => {
            if (!response.endsWith('\n\n')) reject(new Error('AmneziaWG control response was truncated'));
        });
    });
}

export function parseAmneziaWgUsage(response: string): Map<string, {
    rx: number; tx: number; handshake: number;
}> {
    const peers = new Map<string, { rx: number; tx: number; handshake: number }>();
    let peer: { rx: number; tx: number; handshake: number } | undefined;
    for (const line of response.split('\n')) {
        const separator = line.indexOf('=');
        const key = line.slice(0, separator);
        const value = line.slice(separator + 1);
        if (key === 'public_key') {
            if (!/^[a-f0-9]{64}$/.test(value)) throw new Error('Invalid AmneziaWG peer identifier');
            peer = { rx: 0, tx: 0, handshake: 0 };
            peers.set(value, peer);
        } else if (peer && ['rx_bytes', 'tx_bytes', 'last_handshake_time_sec'].includes(key)) {
            const count = Number(value);
            if (!Number.isSafeInteger(count) || count < 0) throw new Error('Invalid AmneziaWG peer counters');
            if (key === 'rx_bytes') peer.rx = count;
            else if (key === 'tx_bytes') peer.tx = count;
            else peer.handshake = count;
        }
    }
    return peers;
}
