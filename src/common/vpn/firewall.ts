import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { promisify } from 'node:util';

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

export async function setVpnFirewall(options: {
    chain: string;
    network: string;
    egressAddress: string | null;
}, enable: boolean): Promise<void> {
    const chain = options.chain;
    if (!/^RW(?:OVP|AWG)[0-9a-f]{10}$/.test(chain)) throw new Error('Invalid VPN firewall owner');
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
                options.network,
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
                options.network,
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
                options.network,
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
                options.network,
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
            'Enable net.ipv4.ip_forward=1 on the Docker host before starting a VPN',
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
            options.network,
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
            options.network,
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
            options.network,
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
            ...(options.egressAddress
                ? ['SNAT', '--to-source', options.egressAddress]
                : ['MASQUERADE']),
        ]);
        await run([
            '-t',
            'nat',
            '-A',
            'POSTROUTING',
            '-s',
            options.network,
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
