declare module 'express' {
  export interface Request { body: any; params: any; query: any; headers: any; ip: string; socket: any; }
  export interface Response { json(body: any): void; status(code: number): Response; setHeader(name: string, value: string): void; }
  export interface NextFunction { (err?: any): void; }
  export interface Application { use(...args: any[]): void; get(path: string, ...handlers: any[]): void; listen(port: number, cb?: () => void): void; }
  export function Router(): any;
  function express(): Application;
  export namespace express { function json(opts?: any): any; }
  export default express;
}
declare module 'cors' { export default function(opts?: any): any; }
declare module 'helmet' { export default function(opts?: any): any; }
declare module 'better-sqlite3' {
  namespace Database { type Database = any; }
  class Database { constructor(path: string); prepare(sql: string): any; exec(sql: string): void; pragma(s: string): any; close(): void; }
  export = Database;
}
declare module 'sqlite-vec' { export function load(db: any): void; }
