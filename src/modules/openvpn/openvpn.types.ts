import { z } from 'zod';
import { ManagedVpnEndpointSchema, ManagedVpnUserSchema } from '@common/vpn/types';

export const OpenVpnEndpointSchema = ManagedVpnEndpointSchema.extend({
    protocol: z.enum(['udp', 'tcp']),
    controlChannel: z.enum(['none', 'tls-auth', 'tls-crypt', 'tls-crypt-v2']),
    udpMask: z.enum(['none', 'random', 'strong', 'error-free']).default('none'),
});
export const OpenVpnUserSchema = ManagedVpnUserSchema;

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
