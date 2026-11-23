import { generateKeyPairSync, randomBytes, randomInt } from 'node:crypto';
import { z } from 'zod';

import { ManagedVpnEndpointSchema, ManagedVpnUserSchema } from '@common/vpn/types';

export function parseAwgRange(value: string): [number, number] {
    const parts = value.split('-').map(Number);
    return [parts[0], parts[1] ?? parts[0]];
}

const RangeSchema = z.string().regex(/^\d{1,10}(?:-\d{1,10})?$/).refine((value) => {
    const [low, high] = parseAwgRange(value);
    return low <= high && high <= 0xffffffff;
});
const KeySchema = z.string().regex(/^[A-Za-z0-9+/]{43}=$/)
    .refine((value) => !Buffer.from(value, 'base64').every((byte) => byte === 0));

export function validAwgSignature(value: string): boolean {
    let size = 0;
    let remaining = value;
    while (remaining.length) {
        const tag = /^(?:\s*)(<(?:b\s+0x[0-9a-fA-F]+|r[cd]?\s+\d{1,4}|t)>)(?:\s*)/.exec(remaining);
        if (!tag) return false;
        const body = tag[1].slice(1, -1).split(/\s+/);
        if (body[0] === 'b') {
            if ((body[1].length - 2) % 2) return false;
            size += (body[1].length - 2) / 2;
        } else size += body[0] === 't' ? 4 : Number(body[1]);
        if (size > 1280) return false;
        remaining = remaining.slice(tag[0].length);
    }
    return true;
}

const SignatureSchema = z.string().max(8192).refine(validAwgSignature);
const ParameterFieldsSchema = z.object({
    Jc: z.number().int().min(0).max(128),
    Jmin: z.number().int().min(1).max(1280),
    Jmax: z.number().int().min(1).max(1280),
    S1: z.number().int().min(0).max(1132),
    S2: z.number().int().min(0).max(1188),
    S3: z.number().int().min(0).max(64),
    S4: z.number().int().min(0).max(32),
    H1: RangeSchema,
    H2: RangeSchema,
    H3: RangeSchema,
    H4: RangeSchema,
    HeaderProtectionKey: KeySchema.optional(),
    ContentPaddingAddition: RangeSchema.optional(),
    RandomTrailers: z.boolean().optional(),
    DisableCookies: z.boolean().optional(),
    I1: SignatureSchema.optional(),
    I2: SignatureSchema.optional(),
    I3: SignatureSchema.optional(),
    I4: SignatureSchema.optional(),
    I5: SignatureSchema.optional(),
}).strict();
export const AmneziaWgParametersSchema = ParameterFieldsSchema.refine((parameters) => {
    if (parameters.Jmin > parameters.Jmax) return false;
    const ranges = [parameters.H1, parameters.H2, parameters.H3, parameters.H4].map(parseAwgRange);
    for (let i = 0; i < ranges.length; i++) {
        for (let j = i + 1; j < ranges.length; j++) {
            if (ranges[i][0] <= ranges[j][1] && ranges[j][0] <= ranges[i][1]) return false;
        }
    }
    const paddings = [parameters.S1, parameters.S2, parameters.S3, parameters.S4];
    if (parameters.HeaderProtectionKey && paddings.some((padding) => padding < 12)) return false;
    if (parameters.RandomTrailers && paddings.some((padding) => padding !== paddings[0])) return false;
    if (parameters.S1 + 56 === parameters.S2 || parameters.S3 === parameters.S2 + 28) return false;
    if (parameters.ContentPaddingAddition && parseAwgRange(parameters.ContentPaddingAddition)[1] > 128) return false;
    return true;
}, 'Incompatible AmneziaWG obfuscation parameters');

export const AmneziaWgEndpointSchema = ManagedVpnEndpointSchema.extend({
    generation: z.enum(['3.1', '2.0']).default('3.1'),
    preset: z.enum(['default', 'mobile']).default('default'),
    parameters: ParameterFieldsSchema.partial().default({}),
});

export const AmneziaWgDeviceIdSchema = z.union([z.literal('default'), z.uuid()]);
export const AmneziaWgUserSchema = ManagedVpnUserSchema.extend({
    devices: z.array(z.object({
        uuid: AmneziaWgDeviceIdSchema,
        name: z.string().min(1).max(64),
    })).min(1).max(5).refine((devices) => new Set(devices.map((device) => device.uuid)).size === devices.length),
});
export const AmneziaWgSyncSchema = z.object({
    generation: z.number().int().positive(),
    users: z.array(AmneziaWgUserSchema),
});
export const AmneziaWgDownloadSchema = z.object({
    userId: ManagedVpnUserSchema.shape.id,
    deviceUuid: AmneziaWgDeviceIdSchema.default('default'),
    address: ManagedVpnEndpointSchema.shape.address.optional(),
    port: ManagedVpnEndpointSchema.shape.port.optional(),
});

const KeyPairSchema = z.object({ privateKey: KeySchema, publicKey: KeySchema });
const PeerStateSchema = KeyPairSchema.extend({
    userId: ManagedVpnUserSchema.shape.id,
    deviceUuid: AmneziaWgDeviceIdSchema,
    credentialId: z.uuid(),
    address: z.number().int().min(2).max(254),
    presharedKey: KeySchema,
    rx: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    tx: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
});
export const AmneziaWgStateSchema = z.object({
    epoch: z.uuid(),
    generation: z.number().int().nonnegative(),
    endpoints: z.record(z.uuid(), AmneziaWgEndpointSchema),
    users: z.record(ManagedVpnUserSchema.shape.id, AmneziaWgUserSchema),
    servers: z.record(z.uuid(), KeyPairSchema.extend({
        parameters: AmneziaWgParametersSchema,
        peers: z.record(z.string(), PeerStateSchema),
    })),
    usage: z.record(ManagedVpnUserSchema.shape.id, z.object({
        uplink: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
        downlink: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    })),
}).refine((state) =>
    Object.entries(state.endpoints).every(([uuid, endpoint]) => uuid === endpoint.uuid) &&
    Object.entries(state.users).every(([id, user]) => id === user.id) &&
    Object.values(state.endpoints).every((endpoint) => endpoint.mode !== 'server' || Boolean(state.servers[endpoint.uuid])),
);

export type AmneziaWgEndpoint = z.infer<typeof AmneziaWgEndpointSchema>;
export type AmneziaWgUser = z.infer<typeof AmneziaWgUserSchema>;
export type AmneziaWgState = z.infer<typeof AmneziaWgStateSchema>;
export type AmneziaWgParameters = z.infer<typeof AmneziaWgParametersSchema>;

export function createAwgKeyPair(): z.infer<typeof KeyPairSchema> {
    const pair = generateKeyPairSync('x25519');
    return {
        privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('base64'),
        publicKey: pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64'),
    };
}

export function createAwgParameters(endpoint: AmneziaWgEndpoint): AmneziaWgParameters {
    const modern = endpoint.generation === '3.1';
    const jmin = endpoint.preset === 'mobile' ? randomInt(30, 51) : randomInt(40, 90);
    const s1 = randomInt(15, 151);
    let s2 = randomInt(15, 151);
    while (s1 + 56 === s2) s2 = randomInt(15, 151);
    let s3 = randomInt(modern ? 12 : 8, 56);
    while (s3 === s2 + 28) s3 = randomInt(modern ? 12 : 8, 56);
    let s4 = randomInt(modern ? 12 : 4, 21);
    while (s4 === 16 || [s1 + 4, s2 + 12, s3].some((size) => size % 16 === s4 % 16)) {
        s4 = randomInt(modern ? 12 : 4, 21);
    }
    const headers = [0, 1, 2, 3].map((index) => {
        if (modern) return String(index + 1);
        const low = index * 536870912 + randomInt(5, 486870911);
        return `${low}-${low + 50000000}`;
    });
    return AmneziaWgParametersSchema.parse({
        Jc: endpoint.preset === 'mobile' ? 3 : randomInt(3, 7),
        Jmin: jmin,
        Jmax: jmin + (endpoint.preset === 'mobile' ? randomInt(20, 81) : randomInt(50, 251)),
        S1: s1, S2: s2, S3: s3, S4: s4,
        H1: headers[0], H2: headers[1], H3: headers[2], H4: headers[3],
        ...(modern ? { HeaderProtectionKey: randomBytes(32).toString('base64'), ContentPaddingAddition: '32-128' } : {}),
        ...(endpoint.preset === 'mobile' ? { I1: '<r 2><b 0x858000010002000000001c><rc 28><b 0x0463646e730669636c6f756403636f6d0000010001c00c000100010000003c00043c263e6bc00c000100010000003c000475bb065f>' } : {}),
        ...endpoint.parameters,
    });
}
