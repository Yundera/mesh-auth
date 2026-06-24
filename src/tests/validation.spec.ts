import { expect } from "chai";
import { computeAppHosts, validateContainerName, validateRedirectUri, ValidationError } from "../validation.js";

const DEFAULT_TEMPLATES = ["{APP}-{DOMAIN}", "{APP}-{IP_DASH}.nip.io", "{APP}-{IP_DASH}.sslip.io"];

describe("validateContainerName", () => {
    it("accepts valid names", () => {
        expect(() => validateContainerName("myapp")).to.not.throw();
        expect(() => validateContainerName("myapp-alice")).to.not.throw();
        expect(() => validateContainerName("my-app_v2")).to.not.throw();
        expect(() => validateContainerName("a")).to.not.throw();
        expect(() => validateContainerName("123app")).to.not.throw();
    });

    it("rejects empty and malformed names", () => {
        expect(() => validateContainerName("")).to.throw(ValidationError);
        expect(() => validateContainerName("-myapp")).to.throw(ValidationError);
        expect(() => validateContainerName("_myapp")).to.throw(ValidationError);
        expect(() => validateContainerName("My-App")).to.throw(ValidationError);
        expect(() => validateContainerName("my app")).to.throw(ValidationError);
        expect(() => validateContainerName("my.app")).to.throw(ValidationError);
        expect(() => validateContainerName("../etc")).to.throw(ValidationError);
        expect(() => validateContainerName("myapp;rm")).to.throw(ValidationError);
    });

    it("rejects overly long names", () => {
        expect(() => validateContainerName("a".repeat(65))).to.throw(ValidationError);
    });
});

describe("computeAppHosts", () => {
    const params = { domain: "wisera.inojob.com", publicIpDash: "80-241-218-30", appHostTemplates: DEFAULT_TEMPLATES };

    it("computes the three canonical hosts from the attested client_id", () => {
        expect(computeAppHosts("appshield-demo", params)).to.deep.equal([
            "appshield-demo-wisera.inojob.com",
            "appshield-demo-80-241-218-30.nip.io",
            "appshield-demo-80-241-218-30.sslip.io",
        ]);
    });

    it("skips IP templates when PUBLIC_IP_DASH is empty", () => {
        expect(computeAppHosts("myapp", { ...params, publicIpDash: "" })).to.deep.equal(["myapp-wisera.inojob.com"]);
    });

    it("skips the domain template when DOMAIN is empty", () => {
        expect(computeAppHosts("myapp", { ...params, domain: "" })).to.deep.equal([
            "myapp-80-241-218-30.nip.io",
            "myapp-80-241-218-30.sslip.io",
        ]);
    });

    it("lowercases the result and honours a custom template array", () => {
        expect(computeAppHosts("MyApp", { domain: "Alice.NSL.sh", publicIpDash: "", appHostTemplates: ["{APP}.{DOMAIN}"] })).to.deep.equal([
            "myapp.alice.nsl.sh",
        ]);
    });
});

describe("validateRedirectUri", () => {
    // The allowlist is recomputed from the PTR-attested client_id — exactly what
    // server.ts passes to the validator.
    const allowedHosts = new Set(
        computeAppHosts("appshield-demo", {
            domain: "wisera.inojob.com",
            publicIpDash: "80-241-218-30",
            appHostTemplates: DEFAULT_TEMPLATES,
        }),
    );
    const opts = { clientId: "appshield-demo", allowedHosts };

    it("accepts each canonical host (any callback path)", () => {
        expect(() => validateRedirectUri("https://appshield-demo-wisera.inojob.com/nhl-auth/oidc/callback", opts)).to.not.throw();
        expect(() => validateRedirectUri("https://appshield-demo-80-241-218-30.nip.io/nhl-auth/oidc/callback", opts)).to.not.throw();
        expect(() => validateRedirectUri("https://appshield-demo-80-241-218-30.sslip.io/nhl-auth/oidc/callback", opts)).to.not.throw();
    });

    it("does not constrain path / query / fragment (host is the boundary)", () => {
        expect(() => validateRedirectUri("https://appshield-demo-wisera.inojob.com/any/other/path?x=1#f", opts)).to.not.throw();
    });

    it("rejects another app's host (impersonation defense)", () => {
        // "appshield" is a different (shorter) app — a naive startsWith would have let it slip.
        expect(() => validateRedirectUri("https://appshield-wisera.inojob.com/cb", opts)).to.throw(ValidationError);
        expect(() => validateRedirectUri("https://otherapp-wisera.inojob.com/cb", opts)).to.throw(ValidationError);
    });

    it("rejects typosquat / suffixed app names (exact match only)", () => {
        expect(() => validateRedirectUri("https://appshield-demo2-wisera.inojob.com/cb", opts)).to.throw(ValidationError);
        expect(() => validateRedirectUri("https://appshield-demox-wisera.inojob.com/cb", opts)).to.throw(ValidationError);
    });

    it("rejects a foreign domain even with the right app prefix", () => {
        expect(() => validateRedirectUri("https://appshield-demo-wisera.evil.com/cb", opts)).to.throw(ValidationError);
        expect(() => validateRedirectUri("https://appshield-demo.attacker.com/cb", opts)).to.throw(ValidationError);
    });

    it("rejects http and non-network schemes (https only)", () => {
        expect(() => validateRedirectUri("http://appshield-demo-wisera.inojob.com/cb", opts)).to.throw(ValidationError);
        expect(() => validateRedirectUri("javascript:alert(1)", opts)).to.throw(ValidationError);
        expect(() => validateRedirectUri("data:text/html,x", opts)).to.throw(ValidationError);
        expect(() => validateRedirectUri("file:///etc/passwd", opts)).to.throw(ValidationError);
    });

    it("rejects malformed and empty URIs", () => {
        expect(() => validateRedirectUri("not a url", opts)).to.throw(ValidationError);
        expect(() => validateRedirectUri("", opts)).to.throw(ValidationError);
    });

    it("rejects overly long URIs", () => {
        const long = "https://appshield-demo-wisera.inojob.com/" + "a".repeat(3000);
        expect(() => validateRedirectUri(long, opts)).to.throw(ValidationError);
    });
});
