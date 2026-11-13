import { createServer as createHttpServer, request as httpRequest } from "node:http";
import { connect, isIP } from "node:net";
import { requestAllowed } from "./index.js";

/** Gate each HTTP request and CONNECT hop because Chromium follows redirects outside Playwright route handlers. */
export async function createPinnedProxy(options: {
  allowedHosts: string[];
  allowedOrigins?: string[];
  authorizeRequest?: (url: string) => Promise<boolean>;
  pinnedAddresses: ReadonlyMap<string, readonly string[]>;
  onBlocked?: (url: string) => void;
}) {
  const allowed = async (value: string) => {
    try {
      const url = new URL(value);
      const address = options.pinnedAddresses.get(url.hostname.toLowerCase())?.[0];
      if (
        !url.username &&
        !url.password &&
        requestAllowed(value, options.allowedHosts, options.allowedOrigins) &&
        address &&
        isIP(address) &&
        (!options.authorizeRequest || (await options.authorizeRequest(value)))
      ) {
        return { url, address };
      }
    } catch {
      // A resolver or authorization failure must deny the request.
    }
    options.onBlocked?.(value);
    return undefined;
  };

  const server = createHttpServer(async (request, response) => {
    let parsed: URL;
    try {
      parsed = new URL(request.url ?? "");
    } catch {
      options.onBlocked?.(request.url ?? "");
      response.writeHead(400).end();
      return;
    }
    if (parsed.protocol !== "http:") {
      options.onBlocked?.(parsed.toString());
      response.writeHead(403).end();
      return;
    }
    const destination = await allowed(parsed.toString());
    if (!destination) {
      response.writeHead(403).end();
      return;
    }
    const headers = { ...request.headers };
    delete headers["proxy-authorization"];
    delete headers["proxy-connection"];
    headers.host = destination.url.host;
    headers.connection = "close";
    const upstream = httpRequest(
      {
        hostname: destination.address,
        port: Number(destination.url.port || 80),
        method: request.method,
        path: `${destination.url.pathname}${destination.url.search}`,
        headers,
      },
      (upstreamResponse) => {
        const responseHeaders = { ...upstreamResponse.headers };
        delete responseHeaders["proxy-authenticate"];
        response.writeHead(upstreamResponse.statusCode ?? 502, responseHeaders);
        upstreamResponse.pipe(response);
      },
    );
    upstream.on("error", () => {
      if (!response.headersSent) response.writeHead(502);
      response.end();
    });
    request.pipe(upstream);
  });

  server.on("connect", async (request, client, head) => {
    let destinationUrl: URL;
    try {
      destinationUrl = new URL(`https://${request.url ?? ""}/`);
    } catch {
      options.onBlocked?.(request.url ?? "");
      client.end("HTTP/1.1 400 Bad Request\r\n\r\n");
      return;
    }
    const destination = await allowed(destinationUrl.toString());
    if (!destination) {
      client.end("HTTP/1.1 403 Forbidden\r\n\r\n");
      return;
    }
    const upstream = connect(
      { host: destination.address, port: Number(destination.url.port || 443) },
      () => {
        client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (head.length) upstream.write(head);
        upstream.pipe(client);
        client.pipe(upstream);
      },
    );
    upstream.on("error", () => client.destroy());
    client.on("error", () => upstream.destroy());
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("pinned_proxy_port_unavailable");
  return {
    serverUrl: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}
