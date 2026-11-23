import { Module } from '@nestjs/common';

import { AmneziaWgController } from './amneziawg.controller';
import { AmneziaWgManager } from './amneziawg.manager';

@Module({
    controllers: [AmneziaWgController],
    providers: [
        {
            provide: AmneziaWgManager,
            useFactory: () =>
                new AmneziaWgManager({
                    root: process.env.AMNEZIAWG_STATE_PATH ?? '/var/lib/remnanode/amneziawg',
                    binary: process.env.AMNEZIAWG_BINARY ?? '/usr/local/bin/amneziawg-go',
                    manageFirewall: process.env.AMNEZIAWG_MANAGE_FIREWALL !== 'false',
                    enabled: process.env.AMNEZIAWG_ENABLED === 'true',
                }),
        },
    ],
})
export class AmneziaWgModule {}
