import type {RequestHandler, Response, Request} from 'express'

export default function expressJailMiddleware(options?: Partial<ExpressJailMiddlewareOptions>) : RequestHandler & {
    ban: (ip: string, context?: unknown) => Promise<void>;
    bans: () => Promise<Array<{
        ip: string;
        from: Date;
        time: number;
        to: Date;
    }>>;
    hasBan: (ip: string) => Promise<boolean>;
    on(event: 'ban', handler: (info: {ip: string, req?: Request, res?: Response}) => Promise<boolean>): void
    on(event: 'banned', handler: (info: {ip: string, req?: Request, res?: Response}) => void): void
    on(event: 'unban', handler: (info: {ip: string}) => Promise<boolean>): void
    on(event: 'unbanned', handler: (info: {ip: string}) => void): void
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
