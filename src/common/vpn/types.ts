import { isIP } from 'node:net';
import { z } from 'zod';

export const ManagedVpnEndpointSchema = z.object({
    uuid: z.uuid(),
    name: z.string().min(1).max(128),
    address: z.string().regex(/^[a-zA-Z0-9.-]{1,253}$/),
    port: z.number().int().min(1).max(65535),
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

export const ManagedVpnUserSchema = z.object({
    id: z.string().regex(/^[1-9][0-9]{0,19}$/),
    credentialId: z.uuid(),
    expiresAt: z.iso.datetime(),
    endpointUuids: z.array(z.uuid()),
});

