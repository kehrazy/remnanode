import { isIP } from 'node:net';
import { z } from 'zod';

export const OpenVpnEndpointSchema = z.object({
    uuid: z.uuid(),
    name: z.string().min(1).max(128),
    address: z.string().regex(/^[a-zA-Z0-9.-]{1,253}$/),
    port: z.number().int().min(1).max(65535),
    protocol: z.enum(['udp', 'tcp']),
    controlChannel: z.enum(['none', 'tls-auth', 'tls-crypt', 'tls-crypt-v2']),
    udpMask: z.enum(['none', 'random', 'strong', 'error-free']).default('none'),
    network: z
        .string()
        .regex(/^10\.(\d{1,3})\.(\d{1,3})\.0\/24$/)
        .refine((value) => isIP(value.split('/')[0]) === 4),
    dnsServers: z
        .array(z.string().refine((value) => isIP(value) === 4))
        .min(1)
        .max(4),
    egressAddress: z
        .string()
        .refine((value) => isIP(value) === 4)
        .nullable()
        .default(null),
    mode: z.enum(['server', 'relay']).default('server'),
    targetAddress: z
        .string()
        .regex(/^[a-zA-Z0-9.-]{1,253}$/)
        .nullable()
        .default(null),
    targetPort: z.number().int().min(1).max(65535).nullable().default(null),
    isDisabled: z.boolean().default(false),
});

export const OpenVpnUserSchema = z.object({
    id: z.string().regex(/^[1-9][0-9]{0,19}$/),
    credentialId: z.uuid(),
    expiresAt: z.iso.datetime(),
    endpointUuids: z.array(z.uuid()),
});

export const OpenVpnSyncSchema = z.object({
    generation: z.number().int().positive(),
    users: z.array(OpenVpnUserSchema),
});

export const OpenVpnDownloadSchema = z.object({
    userId: OpenVpnUserSchema.shape.id,
    address: OpenVpnEndpointSchema.shape.address.optional(),
    port: OpenVpnEndpointSchema.shape.port.optional(),
});

export type OpenVpnEndpoint = z.infer<typeof OpenVpnEndpointSchema>;
export type OpenVpnUser = z.infer<typeof OpenVpnUserSchema>;
export type OpenVpnUsage = { uplink: number; downlink: number };

export const OpenVpnStateSchema = z
    .object({
        epoch: z.uuid(),
        generation: z.number().int().nonnegative(),
        endpoints: z.record(z.uuid(), OpenVpnEndpointSchema),
        users: z.record(OpenVpnUserSchema.shape.id, OpenVpnUserSchema),
        usage: z.record(
            OpenVpnUserSchema.shape.id,
            z.object({
                uplink: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
                downlink: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
            }),
        ),
    })
    .refine(
        (state) =>
            Object.entries(state.endpoints).every(([id, endpoint]) => id === endpoint.uuid) &&
            Object.entries(state.users).every(([id, user]) => id === user.id),
    );
export type OpenVpnState = z.infer<typeof OpenVpnStateSchema>;
