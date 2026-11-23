import { Module } from '@nestjs/common';
import { CqrsModule } from '@nestjs/cqrs';

import { AmneziaWgModule } from '../amneziawg/amneziawg.module';
import { OpenVpnModule } from '../openvpn/openvpn.module';
import { XrayModule } from '../xray-core/xray.module';
import { RuntimeController } from './runtime.controller';

@Module({
    imports: [CqrsModule, OpenVpnModule, AmneziaWgModule, XrayModule],
    controllers: [RuntimeController],
})
export class RuntimeModule {}
