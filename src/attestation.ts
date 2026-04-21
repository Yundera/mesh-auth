import { Resolver } from "node:dns/promises";

export class AttestationError extends Error {}

export interface Attestor {
    resolveContainerName(sourceIp: string): Promise<string>;
}

export class DnsPtrAttestor implements Attestor {
    private readonly resolver: Resolver;

    constructor(dnsResolver: string) {
        this.resolver = new Resolver();
        this.resolver.setServers([dnsResolver]);
    }

    async resolveContainerName(sourceIp: string): Promise<string> {
        // Express gives "::ffff:172.20.0.7" for IPv4 peers on a dual-stack socket.
        // Strip the v4-mapped-v6 prefix so the PTR lookup uses the plain v4 address
        // — Docker's embedded DNS only answers PTR for the v4 arpa zone.
        const ip = sourceIp.replace(/^::ffff:/, "");

        let names: string[];
        try {
            names = await this.resolver.reverse(ip);
        } catch (err) {
            throw new AttestationError(
                `PTR lookup failed for ${ip}: ${(err as Error).message}`,
            );
        }
        if (names.length === 0) {
            throw new AttestationError(`no PTR record for ${ip}`);
        }

        // Docker embedded DNS returns names like "myapp.pcs." (container_name.network.).
        // The first label is the container name — that's the identity we want.
        const firstLabel = names[0]?.split(".")[0];
        if (!firstLabel) {
            throw new AttestationError(`invalid PTR result for ${ip}: ${names[0]}`);
        }
        return firstLabel;
    }
}
