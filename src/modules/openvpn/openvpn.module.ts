import { Module } from '@nestjs/common';

import { OpenVpnController } from './openvpn.controller';
import { OpenVpnManager } from './openvpn.manager';

@Module({
    controllers: [OpenVpnController],
    providers: [
        {
            provide: OpenVpnManager,
            useFactory: () =>
                new OpenVpnManager({
                    root: process.env.OPENVPN_STATE_PATH ?? '/var/lib/remnanode/openvpn',
                    binary: process.env.OPENVPN_BINARY ?? '/usr/local/sbin/openvpn',
                    manageFirewall: process.env.OPENVPN_MANAGE_FIREWALL !== 'false',
                    enabled: process.env.OPENVPN_ENABLED === 'true',
                }),
        },
    ],
})
export class OpenVpnModule {}
