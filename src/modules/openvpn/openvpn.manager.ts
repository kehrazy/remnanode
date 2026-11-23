import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { access, chmod, mkdir, readFile, unlink } from 'node:fs/promises';
import { createConnection, isIP, type Socket } from 'node:net';
import { join } from 'node:path';
import { promisify } from 'node:util';

import { Logger } from '@nestjs/common';

import { startVpnRelay } from '@common/vpn/relay';
import { writePrivateFile } from '@common/vpn/private-file';
import { setVpnFirewall } from '@common/vpn/firewall';

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


export class OpenVpnManager {
    private readonly logger = new Logger(OpenVpnManager.name);
    private readonly root: string;
    private readonly binary: string;
    private readonly manageFirewall: boolean;
    private readonly enabled: boolean;
    private readonly listenAddress: string;
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
        listenAddress?: string;
    }) {
        this.root = options.root;
        this.binary = options.binary ?? '/usr/local/sbin/openvpn';
        this.manageFirewall = options.manageFirewall ?? true;
        this.enabled = options.enabled ?? true;
        this.listenAddress = options.listenAddress ?? '0.0.0.0';
        if (isIP(this.listenAddress) !== 4) throw new Error('OpenVPN listen address must be IPv4');
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
        await this.serial;
        for (const endpoint of Object.values(this.state.endpoints)) await this.stop(endpoint);
        await this.save();
    }

    private exclusive<T>(operation: () => Promise<T>): Promise<T> {
        if (!this.enabled || this.initializationError || this.stopping)
            return Promise.reject(
                new Error(
                    this.initializationError ??
                        (this.stopping
                            ? 'OpenVPN is stopping'
                            : 'OpenVPN is disabled on this node'),
                ),
            );
        const result = this.serial.then(operation);
        this.serial = result.then(
            () => undefined,
            () => undefined,
        );
        return result;
    }

    private async save(): Promise<void> {
        this.dirty = false;
        try {
            await writePrivateFile(join(this.root, 'state.json'), JSON.stringify(this.state));
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
        await writePrivateFile(
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
            await writePrivateFile(join(directory, 'pki.ready'), '1\n');
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
        await writePrivateFile(join(directory, 'pki.ready'), '1\n');
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
        await setVpnFirewall({
            chain: `RWOVP${endpoint.uuid.replaceAll('-', '').slice(0, 10)}`,
            network: endpoint.network,
            egressAddress: endpoint.egressAddress,
        }, enable);
    }

    private async start(endpoint: OpenVpnEndpoint): Promise<void> {
        this.errors.delete(endpoint.uuid);
        if (endpoint.mode === 'relay') {
            this.relays.set(endpoint.uuid, await startVpnRelay({
                ...endpoint,
                listenAddress: this.listenAddress,
                onError: (error) => this.errors.set(endpoint.uuid, this.errorMessage(error)),
            }));
            return;
        }
        const directory = await this.preparePki(endpoint);
        const socketPath = join(directory, 'management.sock');
        await unlink(socketPath).catch(() => undefined);
        const configuration = [
            `port ${endpoint.port}`,
            `local ${this.listenAddress}`,
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
            ...(endpoint.protocol === 'udp'
                ? ['explicit-exit-notify 1', 'mssfix 1360', 'multihome']
                : []),
            '',
        ].join('\n');
        await writePrivateFile(join(directory, 'server.conf'), configuration);
        await this.firewall(endpoint, true);
        const child = spawn(this.binary, ['--config', join(directory, 'server.conf')], {
            stdio: ['ignore', 'inherit', 'inherit'],
            env: { ...process.env, RW_OPENVPN_UDP_MASK: endpoint.udpMask },
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
            : this.processes.has(endpoint.uuid);
    }
}
