import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { createPrivateKey, createPublicKey, randomUUID, randomBytes } from 'node:crypto';
import { access, chmod, mkdir, readFile } from 'node:fs/promises';
import { isIPv4 } from 'node:net';
import { join } from 'node:path';
import { promisify } from 'node:util';

import { Logger } from '@nestjs/common';

import { setVpnFirewall } from '@common/vpn/firewall';
import { writePrivateFile } from '@common/vpn/private-file';
import { startVpnRelay } from '@common/vpn/relay';

import {
    AmneziaWgEndpointSchema,
    AmneziaWgStateSchema,
    AmneziaWgSyncSchema,
    createAwgKeyPair,
    createAwgParameters,
    type AmneziaWgEndpoint,
    type AmneziaWgState,
    type AmneziaWgUser,
} from './amneziawg.types';
import { amneziaWgRequest, parseAmneziaWgUsage } from './amneziawg.uapi';

const execute = promisify(execFile);
const PARAMETER_NAMES: Record<string, string> = {
    HeaderProtectionKey: 'header_protection_key',
    ContentPaddingAddition: 'content_padding_addition',
    RandomTrailers: 'random_trailers',
    DisableCookies: 'disable_cookies',
};

export class AmneziaWgManager {
    private readonly startedAt = new Map<string, number>();
    private version: string | null = null;
    private readonly logger = new Logger(AmneziaWgManager.name);
    private state: AmneziaWgState = {
        epoch: randomUUID(),
        generation: 0,
        endpoints: {},
        users: {},
        servers: {},
        usage: {},
    };
    private readonly processes = new Map<string, ChildProcess>();
    private readonly relays = new Map<string, () => void>();
    private readonly ready = new Set<string>();
    private readonly applied = new Map<string, Set<string>>();
    private readonly activeUsers = new Set<string>();
    private readonly errors = new Map<string, string>();
    private serial: Promise<unknown> = Promise.resolve();
    private timer: ReturnType<typeof setInterval> | undefined;
    private stopping = false;
    private initializationError: string | null = null;
    private readonly root: string;
    private readonly binary: string;
    private readonly enabled: boolean;
    private readonly manageFirewall: boolean;
    private readonly listenAddress: string | undefined;

    constructor(options: {
        root: string;
        binary?: string;
        enabled?: boolean;
        manageFirewall?: boolean;
        listenAddress?: string;
    }) {
        this.root = options.root;
        this.binary = options.binary ?? '/usr/local/bin/amneziawg-go';
        this.enabled = options.enabled ?? true;
        this.manageFirewall = options.manageFirewall ?? true;
        this.listenAddress = options.listenAddress || undefined;
    }

    async onModuleInit(): Promise<void> {
        if (!this.enabled) return;
        if (this.listenAddress && !isIPv4(this.listenAddress)) {
            this.initializationError = 'AmneziaWG bind address must be IPv4';
            return;
        }
        try {
            if (this.binary === '/usr/local/bin/amneziawg-go')
                this.version = JSON.parse(
                    await readFile('/usr/local/share/remnanode/amneziawg-build.json', 'utf8'),
                ).version as string;
        } catch {
            this.version = null;
        }
        await mkdir(this.root, { recursive: true, mode: 0o700 });
        await chmod(this.root, 0o700);
        try {
            this.state = AmneziaWgStateSchema.parse(
                JSON.parse(await readFile(join(this.root, 'state.json'), 'utf8')),
            );
            for (const [uuid, server] of Object.entries(this.state.servers)) {
                if (this.state.endpoints[uuid] && this.state.endpoints[uuid].mode !== 'server')
                    throw new Error('Unknown server identity');
                const addresses = new Set<number>();
                const keys = new Set<string>();
                for (const [id, peer] of Object.entries(server.peers)) {
                    if (
                        id !== `${peer.userId}:${peer.deviceUuid}` ||
                        addresses.has(peer.address) ||
                        keys.has(peer.publicKey)
                    ) {
                        throw new Error('Conflicting peer identities');
                    }
                    addresses.add(peer.address);
                    keys.add(peer.publicKey);
                }
                for (const pair of [server, ...Object.values(server.peers)]) {
                    const privateKey = createPrivateKey({
                        key: Buffer.concat([
                            Buffer.from('302e020100300506032b656e04220420', 'hex'),
                            Buffer.from(pair.privateKey, 'base64'),
                        ]),
                        format: 'der',
                        type: 'pkcs8',
                    });
                    const publicKey = createPublicKey(privateKey)
                        .export({ type: 'spki', format: 'der' })
                        .subarray(-32)
                        .toString('base64');
                    if (publicKey !== pair.publicKey) throw new Error('Key pair mismatch');
                }
            }
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
                this.initializationError =
                    'AmneziaWG state is unreadable; restore its persistent volume';
                return;
            }
            try {
                await access(join(this.root, 'identity.ready'));
                this.initializationError = 'AmneziaWG state is missing from an initialized volume';
                return;
            } catch (markerError) {
                if ((markerError as NodeJS.ErrnoException).code !== 'ENOENT') throw markerError;
            }
            await this.save();
        }
        await writePrivateFile(join(this.root, 'identity.ready'), 'managed-amneziawg\n');
        for (const endpoint of Object.values(this.state.endpoints)) {
            if (endpoint.isDisabled) continue;
            try {
                await this.start(endpoint);
            } catch (error) {
                await this.stop(endpoint).catch(() => undefined);
                this.errors.set(endpoint.uuid, String(error));
            }
        }
        this.timer = setInterval(() => {
            void this.exclusive(async () => {
                this.activeUsers.clear();
                for (const endpoint of Object.values(this.state.endpoints)) {
                    if (endpoint.mode !== 'server' || !this.isRunning(endpoint.uuid)) continue;
                    try {
                        await this.applyPeers(endpoint);
                    } catch (error) {
                        this.errors.set(endpoint.uuid, String(error));
                    }
                }
                await this.save();
            }).catch((error: unknown) => this.logger.error(String(error)));
        }, 5000);
        this.timer.unref();
    }

    async onModuleDestroy(): Promise<void> {
        if (!this.enabled || this.initializationError) return;
        this.stopping = true;
        clearInterval(this.timer);
        await this.serial;
        for (const endpoint of Object.values(this.state.endpoints)) await this.stop(endpoint);
        await this.save();
    }

    private exclusive<T>(operation: () => Promise<T>): Promise<T> {
        if (!this.enabled || this.initializationError || this.stopping) {
            return Promise.reject(
                new Error(
                    this.initializationError ??
                        (this.stopping ? 'AmneziaWG is stopping' : 'AmneziaWG is disabled'),
                ),
            );
        }
        const result = this.serial.then(operation);
        this.serial = result.then(
            () => undefined,
            () => undefined,
        );
        return result;
    }

    private async save(): Promise<void> {
        await writePrivateFile(join(this.root, 'state.json'), JSON.stringify(this.state));
    }

    private interfaceName(uuid: string): string {
        return 'rwawg' + uuid.replaceAll('-', '').slice(0, 8);
    }

    private ipv6Prefix(uuid: string): string {
        const id = uuid.replaceAll('-', '');
        return `fd00:${id.slice(0, 4)}:${id.slice(4, 8)}:${id.slice(8, 12)}::`;
    }

    private request(uuid: string, command: string): Promise<string> {
        return amneziaWgRequest(`/var/run/amneziawg/${this.interfaceName(uuid)}.sock`, command);
    }

    private allowed(endpoint: AmneziaWgEndpoint, user: AmneziaWgUser): boolean {
        return (
            !endpoint.isDisabled &&
            user.endpointUuids.includes(endpoint.uuid) &&
            Date.parse(user.expiresAt) > Date.now()
        );
    }

    private async sample(endpoint: AmneziaWgEndpoint): Promise<void> {
        const response = await this.request(endpoint.uuid, 'get=1');
        const port = /(?:^|\n)listen_port=(\d+)/.exec(response);
        if (Number(port?.[1]) !== endpoint.port)
            throw new Error('AmneziaWG UDP listener is unavailable');
        const peers = parseAmneziaWgUsage(response);
        for (const peer of Object.values(this.state.servers[endpoint.uuid].peers)) {
            const current = peers.get(Buffer.from(peer.publicKey, 'base64').toString('hex'));
            if (!current) continue;
            const usage = (this.state.usage[peer.userId] ??= { uplink: 0, downlink: 0 });
            usage.uplink += current.rx >= peer.rx ? current.rx - peer.rx : current.rx;
            usage.downlink += current.tx >= peer.tx ? current.tx - peer.tx : current.tx;
            peer.rx = current.rx;
            peer.tx = current.tx;
            if (current.handshake > Date.now() / 1000 - 180) this.activeUsers.add(peer.userId);
        }
    }

    private async applyPeers(endpoint: AmneziaWgEndpoint): Promise<void> {
        await this.sample(endpoint);
        const server = this.state.servers[endpoint.uuid];
        const alive = new Set(
            Object.values(this.state.users).flatMap((user) =>
                user.devices.map((device) => `${user.id}:${device.uuid}`),
            ),
        );
        for (const id of Object.keys(server.peers)) if (!alive.has(id)) delete server.peers[id];
        const desired = new Map<string, (typeof server.peers)[string]>();
        for (const user of Object.values(this.state.users)) {
            for (const device of user.devices) {
                const id = `${user.id}:${device.uuid}`;
                let peer = server.peers[id];
                if (!peer && !this.allowed(endpoint, user)) continue;
                if (!peer || peer.credentialId !== user.credentialId) {
                    const used = new Set(Object.values(server.peers).map((entry) => entry.address));
                    let address = peer?.address ?? 2;
                    if (!peer) while (used.has(address)) address++;
                    if (address > 254)
                        throw new Error('AmneziaWG subnet has no free device addresses');
                    peer = server.peers[id] = {
                        ...createAwgKeyPair(),
                        userId: user.id,
                        deviceUuid: device.uuid,
                        credentialId: user.credentialId,
                        address,
                        presharedKey: randomBytes(32).toString('base64'),
                        rx: 0,
                        tx: 0,
                    };
                }
                if (this.allowed(endpoint, user)) desired.set(peer.publicKey, peer);
            }
        }
        const previous = this.applied.get(endpoint.uuid) ?? new Set<string>();
        const changes: string[] = [];
        for (const key of previous) {
            if (!desired.has(key))
                changes.push(
                    `public_key=${Buffer.from(key, 'base64').toString('hex')}`,
                    'remove=true',
                );
        }
        const prefix = endpoint.network.split('/')[0].split('.').slice(0, 3).join('.');
        for (const [key, peer] of desired) {
            if (previous.has(key)) continue;
            peer.rx = peer.tx = 0;
            changes.push(
                `public_key=${Buffer.from(key, 'base64').toString('hex')}`,
                `preshared_key=${Buffer.from(peer.presharedKey, 'base64').toString('hex')}`,
                'replace_allowed_ips=true',
                `allowed_ip=${prefix}.${peer.address}/32`,
                `allowed_ip=${this.ipv6Prefix(endpoint.uuid)}${peer.address.toString(16)}/128`,
            );
        }
        if (changes.length) await this.request(endpoint.uuid, 'set=1\n' + changes.join('\n'));
        this.applied.set(endpoint.uuid, new Set(desired.keys()));
    }

    async configure(input: AmneziaWgEndpoint): Promise<void> {
        return this.exclusive(async () => {
            const endpoint = AmneziaWgEndpointSchema.parse(input);
            const previous = this.state.endpoints[endpoint.uuid];
            if (
                previous &&
                (previous.mode !== endpoint.mode ||
                    (endpoint.mode === 'server' &&
                        ['generation', 'preset', 'parameters', 'network'].some(
                            (key) =>
                                JSON.stringify(previous[key as keyof AmneziaWgEndpoint]) !==
                                JSON.stringify(endpoint[key as keyof AmneziaWgEndpoint]),
                        )))
            )
                throw new Error('Create another endpoint to change AmneziaWG keys or obfuscation');
            if (
                previous &&
                JSON.stringify(previous) === JSON.stringify(endpoint) &&
                (endpoint.isDisabled || this.isRunning(endpoint.uuid))
            )
                return;
            if (
                Object.values(this.state.endpoints).some(
                    (other) =>
                        other.uuid !== endpoint.uuid &&
                        !other.isDisabled &&
                        !endpoint.isDisabled &&
                        (other.port === endpoint.port ||
                            (other.mode === 'server' &&
                                endpoint.mode === 'server' &&
                                other.network === endpoint.network)),
                )
            ) {
                throw new Error('AmneziaWG port or subnet is already assigned');
            }
            if (
                previous?.mode === 'relay' &&
                endpoint.mode === 'relay' &&
                ['port', 'targetAddress', 'targetPort', 'isDisabled'].every(
                    (key) =>
                        previous[key as keyof typeof previous] ===
                        endpoint[key as keyof typeof endpoint],
                ) &&
                (endpoint.isDisabled || this.isRunning(endpoint.uuid))
            ) {
                this.state.endpoints[endpoint.uuid] = endpoint;
                await this.save();
                return;
            }
            if (
                previous &&
                JSON.stringify({ ...previous, name: undefined, address: undefined }) ===
                    JSON.stringify({ ...endpoint, name: undefined, address: undefined }) &&
                (endpoint.isDisabled || this.isRunning(endpoint.uuid))
            ) {
                this.state.endpoints[endpoint.uuid] = endpoint;
                await this.save();
                return;
            }
            if (previous) await this.stop(previous);
            this.state.endpoints[endpoint.uuid] = endpoint;
            try {
                if (endpoint.mode === 'server')
                    this.state.servers[endpoint.uuid] ??= {
                        ...createAwgKeyPair(),
                        parameters: createAwgParameters(endpoint),
                        peers: {},
                    };
                if (!endpoint.isDisabled) await this.start(endpoint);
                await this.save();
            } catch (error) {
                await this.stop(endpoint).catch(() => undefined);
                if (previous) {
                    this.state.endpoints[endpoint.uuid] = previous;
                    if (!previous.isDisabled) await this.start(previous);
                } else {
                    delete this.state.endpoints[endpoint.uuid];
                    delete this.state.servers[endpoint.uuid];
                }
                await this.save();
                throw error;
            }
        });
    }

    async remove(uuid: string): Promise<void> {
        return this.exclusive(async () => {
            const endpoint = this.state.endpoints[uuid];
            if (endpoint) await this.stop(endpoint);
            delete this.state.endpoints[uuid];
            await this.save();
        });
    }

    async sync(input: unknown): Promise<void> {
        return this.exclusive(async () => {
            const snapshot = AmneziaWgSyncSchema.parse(input);
            if (snapshot.generation < this.state.generation) return;
            for (const endpoint of Object.values(this.state.endpoints)) {
                if (endpoint.mode === 'server' && this.isRunning(endpoint.uuid))
                    await this.sample(endpoint);
            }
            this.state.users = Object.fromEntries(snapshot.users.map((user) => [user.id, user]));
            this.state.generation = snapshot.generation;
            this.activeUsers.clear();
            for (const endpoint of Object.values(this.state.endpoints)) {
                if (endpoint.mode === 'server' && this.isRunning(endpoint.uuid))
                    await this.applyPeers(endpoint);
            }
            await this.save();
        });
    }

    async download(
        uuid: string,
        userId: string,
        remote: { address?: string; port?: number; deviceUuid?: string } = {},
    ): Promise<string> {
        return this.exclusive(async () => {
            const endpoint = this.state.endpoints[uuid];
            const user = this.state.users[userId];
            const deviceUuid = remote.deviceUuid ?? 'default';
            if (
                !endpoint ||
                endpoint.mode !== 'server' ||
                !user ||
                !this.allowed(endpoint, user) ||
                !user.devices.some((device) => device.uuid === deviceUuid)
            )
                throw new Error('AmneziaWG profile unavailable');
            if (!this.isRunning(uuid)) throw new Error('AmneziaWG server is not running');
            await this.applyPeers(endpoint);
            await this.save();
            const server = this.state.servers[uuid];
            const peer = server.peers[`${userId}:${deviceUuid}`];
            const prefix = endpoint.network.split('/')[0].split('.').slice(0, 3).join('.');
            return [
                '[Interface]',
                `PrivateKey = ${peer.privateKey}`,
                `Address = ${prefix}.${peer.address}/32, ${this.ipv6Prefix(uuid)}${peer.address.toString(16)}/128`,
                `DNS = ${endpoint.dnsServers.join(', ')}`,
                'MTU = 1280',
                ...Object.entries(server.parameters).map(
                    ([key, value]) =>
                        `${key} = ${typeof value === 'boolean' ? (value ? 'on' : 'off') : value}`,
                ),
                '',
                '[Peer]',
                `PublicKey = ${server.publicKey}`,
                `PresharedKey = ${peer.presharedKey}`,
                `Endpoint = ${remote.address ?? endpoint.address}:${remote.port ?? endpoint.port}`,
                'AllowedIPs = 0.0.0.0/0, ::/0',
                'PersistentKeepalive = 25',
                '',
            ].join('\n');
        });
    }

    private async firewall(endpoint: AmneziaWgEndpoint, enable: boolean): Promise<void> {
        if (!this.manageFirewall || endpoint.mode !== 'server') return;
        const name = this.interfaceName(endpoint.uuid);
        for (const [chain, direction] of [
            ['INPUT', '-i'],
            ['FORWARD', '-i'],
            ['FORWARD', '-o'],
        ]) {
            const rule = [
                chain,
                direction,
                name,
                '-m',
                'comment',
                '--comment',
                'RWAWG' + endpoint.uuid.replaceAll('-', '').slice(0, 10),
                '-j',
                'DROP',
            ];
            await execute('ip6tables', ['-w', '-D', ...rule]).catch(() => undefined);
            if (enable) await execute('ip6tables', ['-w', '-I', ...rule]);
        }
        await setVpnFirewall(
            {
                chain: 'RWAWG' + endpoint.uuid.replaceAll('-', '').slice(0, 10),
                network: endpoint.network,
                egressAddress: endpoint.egressAddress,
            },
            enable,
        );
    }

    private async start(endpoint: AmneziaWgEndpoint): Promise<void> {
        this.errors.delete(endpoint.uuid);
        if (endpoint.mode === 'relay') {
            this.relays.set(
                endpoint.uuid,
                await startVpnRelay({
                    ...endpoint,
                    protocol: 'udp',
                    listenAddress: this.listenAddress ?? '0.0.0.0',
                    onError: (error) => this.errors.set(endpoint.uuid, error.message),
                }),
            );
            this.startedAt.set(endpoint.uuid, Date.now());
            return;
        }
        const server = this.state.servers[endpoint.uuid];
        if (!server)
            throw new Error('AmneziaWG server identity is missing; restore its persistent state');
        for (const peer of Object.values(server.peers)) peer.rx = peer.tx = 0;
        const name = this.interfaceName(endpoint.uuid);
        const child = spawn(this.binary, ['-f', name], {
            env: {
                ...process.env,
                LOG_LEVEL: 'error',
                GOMAXPROCS: '1',
                WG_BIND_ADDRESS: this.listenAddress ?? '',
            },
            stdio: ['ignore', 'ignore', 'pipe'],
        });
        this.processes.set(endpoint.uuid, child);
        child.stderr?.on('data', (chunk: Buffer) =>
            this.logger.error(
                `AmneziaWG ${endpoint.uuid}: ${chunk.toString('utf8').slice(0, 1000)}`,
            ),
        );
        child.once('error', (error) => this.errors.set(endpoint.uuid, error.message));
        child.once('exit', () => {
            if (this.processes.get(endpoint.uuid) !== child) return;
            this.ready.delete(endpoint.uuid);
            this.errors.set(endpoint.uuid, 'AmneziaWG process exited');
        });
        for (let attempt = 0; attempt < 100; attempt++) {
            if (child.exitCode !== null || child.signalCode !== null)
                throw new Error('AmneziaWG process did not start');
            try {
                await this.request(endpoint.uuid, 'get=1');
                break;
            } catch {
                if (attempt === 99)
                    throw new Error('AmneziaWG control socket did not become ready');
            }
            await new Promise((resolve) => setTimeout(resolve, 50));
        }
        const address = endpoint.network.split('/')[0].replace(/\.0$/, '.1');
        const routes = JSON.parse(
            (await execute('ip', ['-j', '-4', 'route', 'show', endpoint.network])).stdout,
        ) as { dev?: string }[];
        if (routes.some((route) => route.dev !== name))
            throw new Error('VPN subnet is already used by another interface');
        await execute('ip', ['address', 'replace', `${address}/24`, 'dev', name]);
        await execute('ip', [
            '-6',
            'address',
            'replace',
            `${this.ipv6Prefix(endpoint.uuid)}1/64`,
            'dev',
            name,
        ]);
        await execute('ip', ['link', 'set', 'dev', name, 'mtu', '1280', 'up']);
        const parameters = Object.entries(server.parameters)
            .filter(([key]) => !/^J|^I[1-5]$/.test(key))
            .map(([key, value]) => {
                const nativeName = PARAMETER_NAMES[key] ?? key.toLowerCase();
                const nativeValue =
                    key === 'HeaderProtectionKey'
                        ? Buffer.from(String(value), 'base64').toString('hex')
                        : value;
                return `${nativeName}=${nativeValue}`;
            });
        await this.request(
            endpoint.uuid,
            [
                'set=1',
                `private_key=${Buffer.from(server.privateKey, 'base64').toString('hex')}`,
                `listen_port=${endpoint.port}`,
                ...parameters,
            ].join('\n'),
        );
        for (let attempt = 0; attempt < 100; attempt++) {
            const sockets = (
                await execute('ss', ['-H', '-l', '-u', '-n', '-p', `sport = :${endpoint.port}`])
            ).stdout;
            if (sockets.includes(`pid=${child.pid},`)) break;
            if (attempt === 99) throw new Error('AmneziaWG UDP port could not be opened');
            await new Promise((resolve) => setTimeout(resolve, 50));
        }
        await this.firewall(endpoint, true);
        this.applied.set(endpoint.uuid, new Set());
        await this.applyPeers(endpoint);
        this.ready.add(endpoint.uuid);
        this.startedAt.set(endpoint.uuid, Date.now());
        await this.save();
    }

    private async stop(endpoint: AmneziaWgEndpoint): Promise<void> {
        this.startedAt.delete(endpoint.uuid);
        this.relays.get(endpoint.uuid)?.();
        this.relays.delete(endpoint.uuid);
        const child = this.processes.get(endpoint.uuid);
        if (child) {
            if (this.ready.has(endpoint.uuid)) await this.sample(endpoint).catch(() => undefined);
            this.processes.delete(endpoint.uuid);
            const exited = new Promise<void>((resolve) => child.once('exit', () => resolve()));
            child.kill('SIGTERM');
            await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 3000))]);
            if (child.exitCode === null && child.signalCode === null) {
                child.kill('SIGKILL');
                await exited;
            }
        }
        this.ready.delete(endpoint.uuid);
        this.applied.delete(endpoint.uuid);
        await this.firewall(endpoint, false);
    }

    private isRunning(uuid: string): boolean {
        if (this.relays.has(uuid)) return !this.errors.has(uuid);
        const child = this.processes.get(uuid);
        return (
            this.ready.has(uuid) &&
            child?.exitCode === null &&
            child.signalCode === null &&
            !this.errors.has(uuid)
        );
    }

    async restart(): Promise<void> {
        await this.exclusive(async () => {
            let failed = false;
            for (const endpoint of Object.values(this.state.endpoints)) {
                await this.stop(endpoint);
                if (endpoint.isDisabled) continue;
                try {
                    await this.start(endpoint);
                } catch (error) {
                    failed = true;
                    await this.stop(endpoint).catch(() => undefined);
                    this.errors.set(
                        endpoint.uuid,
                        error instanceof Error ? error.message : 'Restart failed',
                    );
                }
            }
            await this.save();
            if (failed) throw new Error('Some VPN listeners failed to restart');
        });
    }

    status() {
        return {
            enabled: this.enabled,
            version: this.version,
            error: this.initializationError,
            endpoints: Object.values(this.state.endpoints).map((endpoint) => ({
                uuid: endpoint.uuid,
                running: this.isRunning(endpoint.uuid),
                uptime: this.isRunning(endpoint.uuid)
                    ? Math.floor(
                          (Date.now() - (this.startedAt.get(endpoint.uuid) ?? Date.now())) / 1000,
                      )
                    : 0,
                error: this.errors.get(endpoint.uuid) ?? null,
                peers: this.applied.get(endpoint.uuid)?.size ?? 0,
            })),
        };
    }

    async usage(): Promise<{
        epoch: string;
        users: { id: string; uplink: number; downlink: number; online: boolean }[];
    }> {
        return this.exclusive(async () => {
            this.activeUsers.clear();
            for (const endpoint of Object.values(this.state.endpoints)) {
                if (endpoint.mode === 'server' && this.isRunning(endpoint.uuid))
                    await this.sample(endpoint);
            }
            await this.save();
            return {
                epoch: this.state.epoch,
                users: Object.entries(this.state.usage).map(([id, usage]) => ({
                    id,
                    ...usage,
                    online: this.activeUsers.has(id),
                })),
            };
        });
    }
}
