import { randomUUID } from 'node:crypto';
import { rename, writeFile } from 'node:fs/promises';

export async function writePrivateFile(path: string, contents: string): Promise<void> {
    const temporary = `${path}.${randomUUID()}.tmp`;
    await writeFile(temporary, contents, { mode: 0o600 });
    await rename(temporary, path);
}
