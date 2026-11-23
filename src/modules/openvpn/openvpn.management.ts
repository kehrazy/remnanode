import type { OpenVpnUsage } from './openvpn.types';

import { Socket } from 'node:net';

type Session = OpenVpnUsage & { commonName: string; userId: string };
type ClientEvent = { kind: string; cid: string; kid: string; env: Record<string, string> };

export class OpenVpnManagement {
    private buffer = '';
    private event: ClientEvent | null = null;
    private readonly sessions = new Map<string, Session>();

    constructor(
        private readonly socket: Socket,
        private readonly authorize: (commonName: string) => string | null,
        private readonly account: (userId: string, usage: OpenVpnUsage) => void,
    ) {
        socket.on('data', (data: Buffer) => this.receive(data.toString()));
    }

    start(): void {
        this.socket.write('state on\nbytecount 1\nhold release\n');
    }

    receive(data: string): void {
        this.buffer += data;
        if (this.buffer.length > 1_048_576) {
            this.socket.destroy(new Error('OpenVPN management response exceeds limit'));
            return;
        }
        let newline: number;
        while ((newline = this.buffer.indexOf('\n')) >= 0) {
            const line = this.buffer.slice(0, newline).trimEnd();
            this.buffer = this.buffer.slice(newline + 1);
            if (line.startsWith('>BYTECOUNT_CLI:')) {
                const [cid, uplink, downlink] = line.slice(15).split(',');
                this.updateUsage(cid, Number(uplink), Number(downlink));
            } else if (line.startsWith('>CLIENT:ENV,')) {
                if (!this.event) continue;
                const value = line.slice(12);
                if (value === 'END') {
                    this.finishEvent(this.event);
                    this.event = null;
                } else {
                    const separator = value.indexOf('=');
                    if (separator > 0) {
                        this.event.env[value.slice(0, separator)] = value.slice(separator + 1);
                    }
                }
            } else if (line.startsWith('>CLIENT:')) {
                const [kind, cid, kid = '0'] = line.slice(8).split(',');
                if (!/^\d+$/.test(cid ?? '') || !/^\d+$/.test(kid)) continue;
                this.event = { kind, cid, kid, env: {} };
            }
        }
    }

    private finishEvent(event: ClientEvent): void {
        const { kind, cid, kid, env } = event;
        if (kind === 'CONNECT' || kind === 'REAUTH') {
            const commonName = env.common_name ?? '';
            const userId = this.authorize(commonName);
            const existing = this.sessions.get(cid);
            if (!userId || (existing && existing.commonName !== commonName)) {
                this.socket.write(`client-deny ${cid} ${kid} "Account unavailable"\n`);
                return;
            }
            if (!this.sessions.has(cid)) {
                this.sessions.set(cid, { userId, commonName, uplink: 0, downlink: 0 });
            }
            this.socket.write(`client-auth-nt ${cid} ${kid}\n`);
        } else if (kind === 'DISCONNECT') {
            this.updateUsage(cid, Number(env.bytes_received), Number(env.bytes_sent));
            this.sessions.delete(cid);
        }
    }

    private updateUsage(cid: string, uplink: number, downlink: number): void {
        const session = this.sessions.get(cid);
        if (!session || !Number.isSafeInteger(uplink) || !Number.isSafeInteger(downlink)) return;
        if (uplink < session.uplink || downlink < session.downlink) return;
        this.account(session.userId, {
            uplink: uplink - session.uplink,
            downlink: downlink - session.downlink,
        });
        session.uplink = uplink;
        session.downlink = downlink;
    }

    enforceAccounts(): void {
        for (const [cid, session] of this.sessions) {
            if (this.authorize(session.commonName) !== session.userId) {
                this.socket.write(`client-kill ${cid}\n`);
            }
        }
    }

    onlineUsers(): string[] {
        return [...new Set([...this.sessions.values()].map((session) => session.userId))];
    }
}
