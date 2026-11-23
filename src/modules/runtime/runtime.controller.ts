import {
    BadRequestException,
    Controller,
    Get,
    Param,
    Post,
    UseGuards,
    UseFilters,
} from '@nestjs/common';
import { QueryBus } from '@nestjs/cqrs';

import { HttpExceptionFilter } from '@common/exception';
import { JwtDefaultGuard } from '@common/guards/jwt-guards';
import { getSystemInfo, getSystemStats } from '@common/utils/get-system-stats';

import { AmneziaWgManager } from '../amneziawg/amneziawg.manager';
import { GetInterfaceStatsQuery } from '../network-stats/queries/get-interface-stats/get-interface-stats.query';
import { OpenVpnManager } from '../openvpn/openvpn.manager';
import { XrayService } from '../xray-core/xray.service';

@UseFilters(HttpExceptionFilter)
@UseGuards(JwtDefaultGuard)
@Controller('runtime')
export class RuntimeController {
    constructor(
        private readonly openVpn: OpenVpnManager,
        private readonly amneziaWg: AmneziaWgManager,
        private readonly xray: XrayService,
        private readonly queries: QueryBus,
    ) {}

    @Get()
    async status() {
        const [health, network] = await Promise.all([
            this.xray.getNodeHealthCheck(),
            this.queries.execute(new GetInterfaceStatsQuery()),
        ]);
        return {
            response: {
                agent: { version: __RWNODE_VERSION__, uptime: Math.floor(process.uptime()) },
                system: {
                    info: getSystemInfo(),
                    stats: { ...getSystemStats(), interface: network },
                },
                xray: health.isOk ? health.response : null,
                engines: { openvpn: this.openVpn.status(), amneziawg: this.amneziaWg.status() },
            },
        };
    }

    @Post(':engine/restart')
    async restart(@Param('engine') engine: string) {
        if (engine === 'openvpn') await this.openVpn.restart();
        else if (engine === 'amneziawg') await this.amneziaWg.restart();
        else throw new BadRequestException('Unknown VPN engine');
        return this.status();
    }
}
