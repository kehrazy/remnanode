import dgram from 'node:dgram';
import { createConnection, createServer, type Socket } from 'node:net';

export async function startVpnRelay(options: {
    protocol: 'tcp' | 'udp';
    port: number;
    listenAddress: string;
    targetAddress: string | null;
    targetPort: number | null;
    onError: (error: Error) => void;
}): Promise<() => void> {
    if (!options.targetAddress || !options.targetPort)
        throw new Error('Relay target is required');
    const targetAddress = options.targetAddress;
    const targetPort = options.targetPort;
    if (options.protocol === 'tcp') {
        const clients = new Set<Socket>();
        const server = createServer((client) => {
            if (clients.size >= 512) {
                client.destroy();
                return;
            }
            const upstream = createConnection(targetPort, targetAddress);
            clients.add(client);
            client.setTimeout(120_000, () => client.destroy());
            client.on('error', () => upstream.destroy());
            upstream.on('error', () => client.destroy());
            client.on('close', () => {
                clients.delete(client);
                upstream.destroy();
            });
            upstream.on('close', () => client.destroy());
            client.pipe(upstream).pipe(client);
        });
        await new Promise<void>((resolve, reject) => {
            server.once('error', reject);
            server.listen(options.port, options.listenAddress, () => {
                server.removeListener('error', reject);
                resolve();
            });
        });
        server.on('error', options.onError);
        return () => {
            for (const client of clients) client.destroy();
            server.close();
        };
    } else {
        const listener = dgram.createSocket('udp4');
        const peers = new Map<
            string,
            { socket: dgram.Socket; seen: number; ready: boolean; pending: Buffer[] }
        >();
        listener.on('message', (message, remote) => {
            const key = `${remote.address}:${remote.port}`;
            let peer = peers.get(key);
            if (!peer) {
                if (peers.size >= 256) return;
                const upstream = dgram.createSocket('udp4');
                peer = { socket: upstream, seen: Date.now(), ready: false, pending: [] };
                peers.set(key, peer);
                upstream.on('error', () => {
                    peers.delete(key);
                    upstream.close();
                });
                upstream.on('message', (reply) =>
                    listener.send(reply, remote.port, remote.address),
                );
                const connecting = peer;
                upstream.connect(targetPort, targetAddress, () => {
                    connecting.ready = true;
                    for (const packet of connecting.pending) upstream.send(packet);
                    connecting.pending.length = 0;
                });
            }
            if (peer.ready) peer.socket.send(message);
            else if (message.length <= 8192) {
                // The authenticated handshake can follow a burst of decoy datagrams.
                if (peer.pending.length === 16) peer.pending.shift();
                peer.pending.push(message);
            }
            peer.seen = Date.now();
        });
        await new Promise<void>((resolve, reject) => {
            listener.once('error', reject);
            listener.bind(options.port, options.listenAddress, () => {
                listener.removeListener('error', reject);
                resolve();
            });
        });
        listener.on('error', options.onError);
        const cleanup = setInterval(() => {
            for (const [key, peer] of peers) {
                if (Date.now() - peer.seen > 120_000) {
                    peers.delete(key);
                    peer.socket.close();
                }
            }
        }, 30_000);
        cleanup.unref();
        return () => {
            clearInterval(cleanup);
            for (const peer of peers.values()) peer.socket.close();
            listener.close();
        };
    }
}
