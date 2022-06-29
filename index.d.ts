import type {RequestHandler, Response, Request} from 'express'
import type {EventEmitter} from 'events'

export default function expressJailMiddleware(options?: Partial<ExpressJailMiddlewareOptions>) : EventEmitter & RequestHandler & {
    ban: (ip: string, context?: unknown) => Promise<void>;
    bans: () => Promise<Array<{
        ip: string;
        from: Date;
        time: number;
        to: Date;
    }>>;
    hasBan: (ip: string) => Promise<boolean>;
    on(event: 'ban', handler: (ip: string, req?: Request, res?: Response) => Promise<boolean>): void
    on(event: 'banned', handler: (ip: string, req?: Request, res?: Response) => void): void
    on(event: 'unban', handler: (ip: string) => Promise<boolean>): void
    on(event: 'unbanned', handler: (ip: string) => void): void
    setup: () => Promise<void>;
    unban: (ip: string, context?: unknown) => Promise<void>;
    version: () => Promise<string>;
};

interface ExpressJailMiddlewareOptions {
	clientBinary: string[],
	jail: string,
	jailPorts: string,
	minVersion: string,
	paths: string[],
	responseCode: number,
	setup: boolean,
}
