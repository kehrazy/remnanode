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

import { AmneziaWgManager } from './amneziawg.manager';
import { AmneziaWgDownloadSchema, AmneziaWgEndpointSchema, AmneziaWgSyncSchema } from './amneziawg.types';

class EndpointDto extends createZodDto(AmneziaWgEndpointSchema) {}
class SyncDto extends createZodDto(AmneziaWgSyncSchema) {}
class DownloadDto extends createZodDto(AmneziaWgDownloadSchema) {}

@UseFilters(HttpExceptionFilter)
@UseGuards(JwtDefaultGuard)
@Controller('amneziawg')
export class AmneziaWgController {
    constructor(private readonly manager: AmneziaWgManager) {}

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
