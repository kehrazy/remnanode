import { createZodDto } from 'nestjs-zod';

import {
    Body,
    Controller,
    Get,
    Param,
    ParseUUIDPipe,
    Post,
    UseFilters,
    UseGuards,
} from '@nestjs/common';

import { HttpExceptionFilter } from '@common/exception';
import { JwtDefaultGuard } from '@common/guards/jwt-guards';

import { OpenVpnManager } from './openvpn.manager';
import { OpenVpnDownloadSchema, OpenVpnEndpointSchema, OpenVpnSyncSchema } from './openvpn.types';

class EndpointDto extends createZodDto(OpenVpnEndpointSchema) {}
class SyncDto extends createZodDto(OpenVpnSyncSchema) {}
class DownloadDto extends createZodDto(OpenVpnDownloadSchema) {}

@UseFilters(HttpExceptionFilter)
@UseGuards(JwtDefaultGuard)
@Controller('openvpn')
export class OpenVpnController {
    constructor(private readonly manager: OpenVpnManager) {}

    @Get()
    status() {
        return { response: this.manager.status() };
    }

    @Post('endpoints')
    async configure(@Body() body: EndpointDto) {
        await this.manager.configure(body);
        return { response: this.manager.status() };
    }

    @Post('endpoints/:uuid/remove')
    async remove(@Param('uuid', ParseUUIDPipe) uuid: string) {
        await this.manager.remove(uuid);
        return { response: { success: true } };
    }

    @Post('users')
    async sync(@Body() body: SyncDto) {
        await this.manager.sync(body);
        return { response: { success: true } };
    }

    @Post('endpoints/:uuid/profile')
    async profile(@Param('uuid', ParseUUIDPipe) uuid: string, @Body() body: DownloadDto) {
        const profile = await this.manager.download(uuid, body.userId, body);
        return { response: { profile } };
    }

    @Get('usage')
    async usage() {
        return { response: await this.manager.usage() };
    }
}
