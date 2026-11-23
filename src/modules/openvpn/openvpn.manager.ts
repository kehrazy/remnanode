import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { createHash, randomBytes, randomInt, randomUUID } from 'node:crypto';
import dgram from 'node:dgram';
import { access, chmod, mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { createConnection, createServer, type Socket } from 'node:net';
import { join } from 'node:path';
import { promisify } from 'node:util';

import { Logger } from '@nestjs/common';

import { OpenVpnManagement } from './openvpn.management';
import {
    OpenVpnEndpointSchema,
    OpenVpnSyncSchema,
    OpenVpnStateSchema,
    type OpenVpnEndpoint,
    type OpenVpnState,
    type OpenVpnUsage,
    type OpenVpnUser,
} from './openvpn.types';

const execute = promisify(execFile);
const PRIVATE_NETWORKS = [
    '0.0.0.0/8',
    '10.0.0.0/8',
    '100.64.0.0/10',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '224.0.0.0/4',
    '240.0.0.0/4',
];

export class OpenVpnManager {
    private readonly logger = new Logger(OpenVpnManager.name);
    private readonly root: string;
    private readonly binary: string;
    private readonly manageFirewall: boolean;
    private readonly enabled: boolean;
    private state: OpenVpnState = {
        epoch: randomUUID(),
        generation: 0,
        endpoints: {},
        users: {},
        usage: {},
    };
    private readonly processes = new Map<string, ChildProcess>();
    private readonly management = new Map<string, OpenVpnManagement>();
    private readonly sockets = new Map<string, Socket>();
    private readonly relays = new Map<string, () => void>();
    private readonly errors = new Map<string, string>();
    private serial: Promise<unknown> = Promise.resolve();
    private timer: ReturnType<typeof setInterval> | undefined;
    private stopping = false;
    private dirty = false;
    private initializationError: string | null = null;

    constructor(options: {
        root: string;
        binary?: string;
        manageFirewall?: boolean;
        enabled?: boolean;
    }) {
        this.root = options.root;
        this.binary = options.binary ?? '/usr/sbin/openvpn';
        this.manageFirewall = options.manageFirewall ?? true;
        this.enabled = options.enabled ?? true;
    }

    async onModuleInit(): Promise<void> {
        if (!this.enabled) return;
        await mkdir(this.root, { recursive: true, mode: 0o700 });
        await chmod(this.root, 0o700);
        try {
            this.state = OpenVpnStateSchema.parse(
                JSON.parse(await readFile(join(this.root, 'state.json'), 'utf8')),
            );
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
                this.initializationError =
                    'OpenVPN state is unreadable; restore its persistent volume';
                return;
            }
            await this.save();
        }
        for (const endpoint of Object.values(this.state.endpoints)) {
            if (!endpoint.isDisabled) {
                try {
                    await this.start(endpoint);
                } catch (error) {
                    await this.stop(endpoint).catch(() => undefined);
                    this.errors.set(endpoint.uuid, this.errorMessage(error));
                }
            }
        }
        this.timer = setInterval(() => {
            for (const manager of this.management.values()) manager.enforceAccounts();
            if (this.dirty)
                void this.exclusive(() => this.save()).catch((error: unknown) => {
                    this.logger.error(
                        `OpenVPN accounting persistence failed: ${this.errorMessage(error)}`,
                    );
                });
        }, 5000);
        this.timer.unref();
    }

    async onModuleDestroy(): Promise<void> {
        if (!this.enabled || this.initializationError) return;
        this.stopping = true;
        clearInterval(this.timer);
        for (const endpoint of Object.values(this.state.endpoints)) await this.stop(endpoint);
        await this.exclusive(() => this.save());
    }

    private exclusive<T>(operation: () => Promise<T>): Promise<T> {
        if (!this.enabled || this.initializationError)
            return Promise.reject(
                new Error(this.initializationError ?? 'OpenVPN is disabled on this node'),
            );
        const result = this.serial.then(operation);
        this.serial = result.then(
            () => undefined,
            () => undefined,
        );
        return result;
    }

    private async write(path: string, contents: string): Promise<void> {
        const temporary = `${path}.${randomUUID()}.tmp`;
        await writeFile(temporary, contents, { mode: 0o600 });
        await rename(temporary, path);
    }

    private async save(): Promise<void> {
        this.dirty = false;
        try {
            await this.write(join(this.root, 'state.json'), JSON.stringify(this.state));
        } catch (error) {
            this.dirty = true;
            throw error;
        }
    }

    private errorMessage(error: unknown): string {
        return error instanceof Error ? error.message.slice(0, 1000) : 'OpenVPN operation failed';
    }

    async configure(input: unknown): Promise<void> {
        const endpoint = OpenVpnEndpointSchema.parse(input);
        if (
            endpoint.udpMask !== 'none' &&
            (endpoint.protocol !== 'udp' || endpoint.mode !== 'server')
        ) {
            throw new Error('UDP masking requires a UDP server endpoint');
        }
        await this.exclusive(async () => {
            const previous = this.state.endpoints[endpoint.uuid];
            for (const other of Object.values(this.state.endpoints)) {
                if (other.uuid === endpoint.uuid || other.isDisabled || endpoint.isDisabled)
                    continue;
                if (other.port === endpoint.port && other.protocol === endpoint.protocol) {
                    throw new Error('Another OpenVPN endpoint already uses this protocol and port');
                }
                if (
                    endpoint.mode === 'server' &&
                    other.mode === 'server' &&
                    other.network === endpoint.network
                ) {
                    throw new Error('OpenVPN server networks must be distinct');
                }
            }
            if (
                previous &&
                (previous.mode !== endpoint.mode ||
                    previous.controlChannel !== endpoint.controlChannel)
            ) {
                throw new Error('Create a new endpoint to change its mode or control-channel keys');
            }
            if (
                previous &&
                JSON.stringify(previous) === JSON.stringify(endpoint) &&
                (endpoint.isDisabled || this.isRunning(endpoint))
            )
                return;
            if (previous) await this.stop(previous);
            try {
                if (!endpoint.isDisabled) await this.start(endpoint);
                this.state.endpoints[endpoint.uuid] = endpoint;
                await this.save();
            } catch (error) {
                if (previous) this.state.endpoints[endpoint.uuid] = previous;
                else delete this.state.endpoints[endpoint.uuid];
                await this.stop(endpoint);
                if (previous && !previous.isDisabled) await this.start(previous);
                throw error;
            }
        });
    }

    async remove(uuid: string): Promise<void> {
        await this.exclusive(async () => {
            const endpoint = this.state.endpoints[uuid];
            if (!endpoint) return;
            await this.stop(endpoint);
            delete this.state.endpoints[uuid];
            await this.save();
        });
    }

    async sync(input: unknown): Promise<void> {
        const data = OpenVpnSyncSchema.parse(input);
        await this.exclusive(async () => {
            if (data.generation <= this.state.generation) return;
            this.state.users = Object.fromEntries(data.users.map((user) => [user.id, user]));
            this.state.generation = data.generation;
            for (const manager of this.management.values()) manager.enforceAccounts();
            await this.save();
        });
    }

    private commonName(user: OpenVpnUser): string {
        const revision = createHash('sha256').update(user.credentialId).digest('hex').slice(0, 16);
        return `${user.id}-${revision}`;
    }

    private authorize(uuid: string, commonName: string): string | null {
        const user = this.state.users[commonName.split('-')[0]];
        if (
            !user ||
            this.commonName(user) !== commonName ||
            Date.parse(user.expiresAt) <= Date.now()
        )
            return null;
        return user.endpointUuids.includes(uuid) ? user.id : null;
    }

    private async certificate(
        directory: string,
        basename: string,
        commonName: string,
        server: boolean,
    ): Promise<void> {
        try {
            await access(join(directory, `${basename}.crt`));
            await access(join(directory, `${basename}.key`));
            return;
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        }
        const path = (suffix: string) => join(directory, `${basename}.${suffix}`);
        await execute('openssl', [
            'req',
            '-new',
            '-newkey',
            'ec',
            '-pkeyopt',
            'ec_paramgen_curve:P-256',
            '-nodes',
            '-keyout',
            path('key'),
            '-out',
            path('csr'),
            '-subj',
            `/CN=${commonName}`,
        ]);
        await chmod(path('key'), 0o600);
        await this.write(
            path('ext'),
            [
                'basicConstraints=critical,CA:FALSE',
                'keyUsage=critical,digitalSignature',
                `extendedKeyUsage=${server ? 'serverAuth' : 'clientAuth'}`,
            ].join('\n'),
        );
        await execute('openssl', [
            'x509',
            '-req',
            '-in',
            path('csr'),
            '-CA',
            join(directory, 'ca.crt'),
            '-CAkey',
            join(directory, 'ca.key'),
            '-set_serial',
            `0x${randomBytes(16).toString('hex')}`,
            '-days',
            '3650',
            '-sha256',
            '-extfile',
            path('ext'),
            '-out',
            path('crt'),
        ]);
        await chmod(path('crt'), 0o600);
        await unlink(path('csr'));
        await unlink(path('ext'));
    }

    private async preparePki(endpoint: OpenVpnEndpoint): Promise<string> {
        const directory = join(this.root, endpoint.uuid);
        await mkdir(directory, { recursive: true, mode: 0o700 });
        const prepared = await access(join(directory, 'pki.ready')).then(
            () => true,
            (error: NodeJS.ErrnoException) => {
                if (error.code === 'ENOENT') return false;
                throw error;
            },
        );
        if (prepared) {
            for (const file of [
                'ca.crt',
                'ca.key',
                'server.crt',
                'server.key',
                ...(endpoint.controlChannel === 'none' ? [] : ['control.key']),
            ]) {
                await access(join(directory, file));
            }
            return directory;
        }
        const caFiles = await Promise.all(
            ['ca.crt', 'ca.key'].map(async (file) => {
                try {
                    await access(join(directory, file));
                    return true;
                } catch (error) {
                    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
                    throw error;
                }
            }),
        );
        if (caFiles[0] !== caFiles[1])
            throw new Error('OpenVPN CA is incomplete; restore the endpoint PKI');
        if (!caFiles[0]) {
            await execute('openssl', [
                'req',
                '-x509',
                '-newkey',
                'ec',
                '-pkeyopt',
                'ec_paramgen_curve:P-256',
                '-nodes',
                '-keyout',
                join(directory, 'ca.key'),
                '-out',
                join(directory, 'ca.crt'),
                '-days',
                '7300',
                '-sha256',
                '-subj',
                `/CN=OpenVPN-${endpoint.uuid}`,
                '-addext',
                'basicConstraints=critical,CA:TRUE',
                '-addext',
                'keyUsage=critical,keyCertSign,cRLSign',
            ]);
            await chmod(join(directory, 'ca.key'), 0o600);
        }
        await this.certificate(directory, 'server', `server-${endpoint.uuid}`, true);
        if (endpoint.controlChannel === 'none') {
            await this.write(join(directory, 'pki.ready'), '1\n');
            return directory;
        }
        try {
            await access(join(directory, 'control.key'));
        } catch {
            await execute(this.binary, [
                '--genkey',
                endpoint.controlChannel === 'tls-crypt-v2' ? 'tls-crypt-v2-server' : 'secret',
                join(directory, 'control.key'),
            ]);
            await chmod(join(directory, 'control.key'), 0o600);
        }
        await this.write(join(directory, 'pki.ready'), '1\n');
        return directory;
    }

    async download(
        uuid: string,
        userId: string,
        remote?: { address?: string; port?: number },
    ): Promise<string> {
        return this.exclusive(async () => {
            const endpoint = this.state.endpoints[uuid];
            const user = this.state.users[userId];
            if (
                !endpoint ||
                endpoint.isDisabled ||
                endpoint.mode !== 'server' ||
                !user ||
                !this.authorize(uuid, this.commonName(user))
            )
                throw new Error('OpenVPN profile unavailable');
            const directory = await this.preparePki(endpoint);
            const commonName = this.commonName(user);
            await this.certificate(directory, `client-${commonName}`, commonName, false);
            let control = join(directory, 'control.key');
            if (endpoint.controlChannel === 'tls-crypt-v2') {
                control = join(directory, `client-${commonName}.tls.key`);
                try {
                    await access(control);
                } catch {
                    await execute(this.binary, [
                        '--tls-crypt-v2',
                        join(directory, 'control.key'),
                        '--genkey',
                        'tls-crypt-v2-client',
                        control,
                    ]);
                    await chmod(control, 0o600);
                }
            }
            const inline = async (tag: string, file: string) =>
                `<${tag}>\n${(await readFile(file, 'utf8')).trim()}\n</${tag}>`;
            return [
                'client',
                'dev tun',
                `proto ${endpoint.protocol === 'tcp' ? 'tcp-client' : 'udp'}`,
                `remote ${remote?.address ?? endpoint.address} ${remote?.port ?? endpoint.port}`,
                'resolv-retry infinite',
                'nobind',
                'persist-key',
                'persist-tun',
                'remote-cert-tls server',
                `verify-x509-name server-${uuid} name`,
                'tls-version-min 1.2',
                'auth SHA256',
                'data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305',
                'auth-nocache',
                'allow-compression no',
                'tun-mtu 1400',
                'verb 3',
                ...(endpoint.protocol === 'udp' ? ['explicit-exit-notify 1', 'mssfix 1360'] : []),
                ...(endpoint.controlChannel === 'tls-auth' ? ['key-direction 1'] : []),
                await inline('ca', join(directory, 'ca.crt')),
                await inline('cert', join(directory, `client-${commonName}.crt`)),
                await inline('key', join(directory, `client-${commonName}.key`)),
                ...(endpoint.controlChannel === 'none'
                    ? []
                    : [await inline(endpoint.controlChannel, control)]),
                '',
            ].join('\n');
        });
    }

    private async firewall(endpoint: OpenVpnEndpoint, enable: boolean): Promise<void> {
        if (!this.manageFirewall || endpoint.mode !== 'server') return;
        const chain = `RWOVP${endpoint.uuid.replaceAll('-', '').slice(0, 10)}`;
        const run = async (args: string[], optional = false) => {
            try {
                await execute('iptables', ['-w', ...args]);
            } catch (error) {
                if (!optional) throw error;
            }
        };
        const remove = async () => {
            await run(
                [
                    '-D',
                    'FORWARD',
                    '-s',
                    endpoint.network,
                    '-m',
                    'comment',
                    '--comment',
                    chain,
                    '-j',
                    chain,
                ],
                true,
            );
            await run(
                [
                    '-D',
                    'FORWARD',
                    '-d',
                    endpoint.network,
                    '-m',
                    'conntrack',
                    '--ctstate',
                    'ESTABLISHED,RELATED',
                    '-m',
                    'comment',
                    '--comment',
                    chain,
                    '-j',
                    'ACCEPT',
                ],
                true,
            );
            await run(
                [
                    '-D',
                    'INPUT',
                    '-s',
                    endpoint.network,
                    '-m',
                    'comment',
                    '--comment',
                    chain,
                    '-j',
                    'DROP',
                ],
                true,
            );
            await run(
                [
                    '-t',
                    'nat',
                    '-D',
                    'POSTROUTING',
                    '-s',
                    endpoint.network,
                    '-m',
                    'comment',
                    '--comment',
                    chain,
                    '-j',
                    chain,
                ],
                true,
            );
            await run(['-F', chain], true);
            await run(['-X', chain], true);
            await run(['-t', 'nat', '-F', chain], true);
            await run(['-t', 'nat', '-X', chain], true);
        };
        await remove();
        if (!enable) return;
        if ((await readFile('/proc/sys/net/ipv4/ip_forward', 'utf8')).trim() !== '1') {
            throw new Error(
                'Enable net.ipv4.ip_forward=1 on the Docker host before starting OpenVPN',
            );
        }
        try {
            await run(['-N', chain]);
            for (const network of PRIVATE_NETWORKS)
                await run(['-A', chain, '-d', network, '-j', 'DROP']);
            await run(['-A', chain, '-j', 'ACCEPT']);
            await run([
                '-I',
                'FORWARD',
                '1',
                '-s',
                endpoint.network,
                '-m',
                'comment',
                '--comment',
                chain,
                '-j',
                chain,
            ]);
            await run([
                '-I',
                'FORWARD',
                '1',
                '-d',
                endpoint.network,
                '-m',
                'conntrack',
                '--ctstate',
                'ESTABLISHED,RELATED',
                '-m',
                'comment',
                '--comment',
                chain,
                '-j',
                'ACCEPT',
            ]);
            await run([
                '-I',
                'INPUT',
                '1',
                '-s',
                endpoint.network,
                '-m',
                'comment',
                '--comment',
                chain,
                '-j',
                'DROP',
            ]);
            await run(['-t', 'nat', '-N', chain]);
            await run([
                '-t',
                'nat',
                '-A',
                chain,
                '-j',
                ...(endpoint.egressAddress
                    ? ['SNAT', '--to-source', endpoint.egressAddress]
                    : ['MASQUERADE']),
            ]);
            await run([
                '-t',
                'nat',
                '-A',
                'POSTROUTING',
                '-s',
                endpoint.network,
                '-m',
                'comment',
                '--comment',
                chain,
                '-j',
                chain,
            ]);
        } catch (error) {
            await remove();
            throw error;
        }
    }

    private async start(endpoint: OpenVpnEndpoint): Promise<void> {
        this.errors.delete(endpoint.uuid);
        if (endpoint.mode === 'relay') return this.startRelay(endpoint);
        const directory = await this.preparePki(endpoint);
        const socketPath = join(directory, 'management.sock');
        let listenPort = endpoint.port;
        if (endpoint.udpMask !== 'none') {
            listenPort = await new Promise<number>((resolve, reject) => {
                const reservation = dgram.createSocket('udp4');
                reservation.once('error', reject);
                reservation.bind(0, '127.0.0.1', () => {
                    const port = reservation.address().port;
                    reservation.close(() => resolve(port));
                });
            });
        }
        await unlink(socketPath).catch(() => undefined);
        const configuration = [
            `port ${listenPort}`,
            ...(endpoint.udpMask !== 'none' ? ['local 127.0.0.1'] : []),
            `proto ${endpoint.protocol === 'tcp' ? 'tcp-server' : 'udp4'}`,
            `dev rwovp${endpoint.uuid.replaceAll('-', '').slice(0, 8)}`,
            'dev-type tun',
            'topology subnet',
            `server ${endpoint.network.split('/')[0]} 255.255.255.0`,
            `server-ipv6 fd42:${endpoint.uuid.slice(0, 4)}:${endpoint.uuid.slice(4, 8)}::/64`,
            'push "redirect-gateway def1 ipv6"',
            'push "block-ipv6"',
            ...endpoint.dnsServers.map((ip) => `push "dhcp-option DNS ${ip}"`),
            'keepalive 10 60',
            'persist-key',
            'persist-tun',
            'dh none',
            'duplicate-cn',
            'tls-version-min 1.2',
            'remote-cert-tls client',
            'auth SHA256',
            'data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305',
            `ca ${join(directory, 'ca.crt')}`,
            `cert ${join(directory, 'server.crt')}`,
            `key ${join(directory, 'server.key')}`,
            ...(endpoint.controlChannel === 'none'
                ? []
                : [
                      `${endpoint.controlChannel} ${join(directory, 'control.key')}${endpoint.controlChannel === 'tls-auth' ? ' 0' : ''}`,
                  ]),
            'allow-compression no',
            'tun-mtu 1400',
            `management ${socketPath} unix`,
            'management-client-auth',
            'auth-user-pass-optional',
            'management-hold',
            'disable-dco',
            'verb 3',
            ...(endpoint.protocol === 'udp' ? ['explicit-exit-notify 1', 'mssfix 1360'] : []),
            '',
        ].join('\n');
        await this.write(join(directory, 'server.conf'), configuration);
        await this.firewall(endpoint, true);
        const child = spawn(this.binary, ['--config', join(directory, 'server.conf')], {
            stdio: ['ignore', 'inherit', 'inherit'],
        });
        this.processes.set(endpoint.uuid, child);
        child.on('error', (error) => {
            this.errors.set(endpoint.uuid, this.errorMessage(error));
            if (this.processes.get(endpoint.uuid) === child) this.processes.delete(endpoint.uuid);
        });
        child.on('exit', (code) => {
            if (this.processes.get(endpoint.uuid) !== child) return;
            this.processes.delete(endpoint.uuid);
            this.relays.get(endpoint.uuid)?.();
            this.relays.delete(endpoint.uuid);
            this.sockets.get(endpoint.uuid)?.destroy();
            this.management.delete(endpoint.uuid);
            if (!this.stopping)
                this.errors.set(endpoint.uuid, `OpenVPN exited (${code ?? 'signal'})`);
        });
        let socket: Socket | undefined;
        for (let attempt = 0; attempt < 50; attempt++) {
            if (child.exitCode !== null) break;
            try {
                socket = await new Promise<Socket>((resolve, reject) => {
                    const connection = createConnection(socketPath);
                    connection.once('error', reject);
                    connection.once('connect', () => {
                        connection.removeListener('error', reject);
                        resolve(connection);
                    });
                });
                break;
            } catch {
                await new Promise((resolve) => setTimeout(resolve, 100));
            }
        }
        if (!socket)
            throw new Error('OpenVPN management socket did not become ready; inspect node logs');
        await chmod(socketPath, 0o600);
        this.sockets.set(endpoint.uuid, socket);
        const manager = new OpenVpnManagement(
            socket,
            (name) => this.authorize(endpoint.uuid, name),
            (id, usage) => {
                const total = (this.state.usage[id] ??= { uplink: 0, downlink: 0 });
                total.uplink += usage.uplink;
                total.downlink += usage.downlink;
                this.dirty = true;
            },
        );
        socket.on('error', (error) => this.errors.set(endpoint.uuid, this.errorMessage(error)));
        socket.on('close', () => {
            if (this.processes.get(endpoint.uuid) === child) child.kill('SIGTERM');
        });
        this.management.set(endpoint.uuid, manager);
        manager.start();
        await new Promise((resolve) => setTimeout(resolve, 300));
        if (child.exitCode !== null || this.errors.has(endpoint.uuid))
            throw new Error('OpenVPN failed to start');
        if (endpoint.udpMask !== 'none') {
            await this.startRelay({
                ...endpoint,
                targetAddress: '127.0.0.1',
                targetPort: listenPort,
            });
        }
    }

    private async startRelay(endpoint: OpenVpnEndpoint): Promise<void> {
        if (!endpoint.targetAddress || !endpoint.targetPort)
            throw new Error('Relay target is required');
        const targetAddress = endpoint.targetAddress;
        const targetPort = endpoint.targetPort;
        if (endpoint.protocol === 'tcp') {
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
                server.listen(endpoint.port, '0.0.0.0', () => {
                    server.removeListener('error', reject);
                    resolve();
                });
            });
            server.on('error', (error) => this.errors.set(endpoint.uuid, this.errorMessage(error)));
            this.relays.set(endpoint.uuid, () => {
                for (const client of clients) client.destroy();
                server.close();
            });
        } else {
            const listener = dgram.createSocket('udp4');
            let maskWindow = Date.now();
            let maskPackets = 0;
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
                    upstream.on('message', (reply) => {
                        const opcode = reply.length ? reply[0] >> 3 : -1;
                        if (Date.now() - maskWindow >= 1000) {
                            maskWindow = Date.now();
                            maskPackets = 0;
                        }
                        if (
                            endpoint.udpMask === 'none' ||
                            ![7, 8, 10].includes(opcode) ||
                            maskPackets >= 500 ||
                            reply.length > 65400
                        ) {
                            listener.send(reply, remote.port, remote.address);
                            return;
                        }
                        const errorFree =
                            endpoint.udpMask === 'error-free' ||
                            (endpoint.udpMask === 'random' && randomInt(2) === 1);
                        if (errorFree) listener.send(reply, remote.port, remote.address);
                        const count = Math.min(randomInt(150, 201), 500 - maskPackets);
                        maskPackets += count;
                        for (let index = 0; index < count; index++) {
                            const packet = randomBytes(reply.length + randomInt(1, 101));
                            if (errorFree) {
                                reply.copy(packet);
                                packet[0] = 40;
                            } else if (packet[0] >> 3 >= 1 && packet[0] >> 3 <= 11) packet[0] &= 7;
                            listener.send(packet, remote.port, remote.address);
                        }
                        if (!errorFree) listener.send(reply, remote.port, remote.address);
                    });
                    const connecting = peer;
                    upstream.connect(targetPort, targetAddress, () => {
                        connecting.ready = true;
                        for (const packet of connecting.pending) upstream.send(packet);
                        connecting.pending.length = 0;
                    });
                }
                if (peer.ready) peer.socket.send(message);
                else if (peer.pending.length < 4 && message.length <= 8192)
                    peer.pending.push(message);
                peer.seen = Date.now();
            });
            await new Promise<void>((resolve, reject) => {
                listener.once('error', reject);
                listener.bind(endpoint.port, '0.0.0.0', () => {
                    listener.removeListener('error', reject);
                    resolve();
                });
            });
            listener.on('error', (error) =>
                this.errors.set(endpoint.uuid, this.errorMessage(error)),
            );
            const cleanup = setInterval(() => {
                for (const [key, peer] of peers) {
                    if (Date.now() - peer.seen > 120_000) {
                        peers.delete(key);
                        peer.socket.close();
                    }
                }
            }, 30_000);
            cleanup.unref();
            this.relays.set(endpoint.uuid, () => {
                clearInterval(cleanup);
                for (const peer of peers.values()) peer.socket.close();
                listener.close();
            });
        }
    }

    private async stop(endpoint: OpenVpnEndpoint): Promise<void> {
        this.relays.get(endpoint.uuid)?.();
        this.relays.delete(endpoint.uuid);
        const child = this.processes.get(endpoint.uuid);
        if (child) {
            this.processes.delete(endpoint.uuid);
            const exited = new Promise<void>((resolve) => child.once('exit', () => resolve()));
            child.kill('SIGTERM');
            await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 3000))]);
            if (child.exitCode === null && child.signalCode === null) {
                child.kill('SIGKILL');
                await exited;
            }
        }
        this.processes.delete(endpoint.uuid);
        this.sockets.get(endpoint.uuid)?.destroy();
        this.sockets.delete(endpoint.uuid);
        this.management.delete(endpoint.uuid);
        await this.firewall(endpoint, false);
    }

    async usage(): Promise<{
        epoch: string;
        users: (OpenVpnUsage & { id: string; online: boolean })[];
    }> {
        return this.exclusive(async () => {
            const online = new Set(
                [...this.management.values()].flatMap((manager) => manager.onlineUsers()),
            );
            const snapshot = {
                epoch: this.state.epoch,
                users: Object.entries(this.state.usage).map(([id, usage]) => ({
                    id,
                    ...usage,
                    online: online.has(id),
                })),
            };
            await this.save();
            return snapshot;
        });
    }

    status(): {
        enabled: boolean;
        error: string | null;
        endpoints: (OpenVpnEndpoint & { running: boolean; error: string | null })[];
    } {
        return {
            enabled: this.enabled,
            error: this.initializationError,
            endpoints: Object.values(this.state.endpoints).map((endpoint) => ({
                ...endpoint,
                running: this.isRunning(endpoint),
                error: this.errors.get(endpoint.uuid) ?? null,
            })),
        };
    }

    private isRunning(endpoint: OpenVpnEndpoint): boolean {
        return endpoint.mode === 'relay'
            ? this.relays.has(endpoint.uuid)
            : this.processes.has(endpoint.uuid) &&
                  (endpoint.udpMask === 'none' || this.relays.has(endpoint.uuid));
    }
}
