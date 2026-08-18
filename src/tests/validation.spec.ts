import { expect } from "chai";
import {
    computeAllowedHosts,
    computeAppHosts,
    validateCallbackPath,
    validateContainerName,
    validateRedirectUri,
    ValidationError,
} from "../validation.js";

const SUFFIXES = ["wisera.inojob.com", "80-241-218-30.nip.io", "80-241-218-30.sslip.io"];

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
    it("computes <app>-<suffix> for each configured suffix", () => {
        expect(computeAppHosts("appshield-demo", SUFFIXES)).to.deep.equal([
            "appshield-demo-wisera.inojob.com",
            "appshield-demo-80-241-218-30.nip.io",
            "appshield-demo-80-241-218-30.sslip.io",
        ]);
    });

    it("returns an empty set when no suffixes are configured", () => {
        expect(computeAppHosts("myapp", [])).to.deep.equal([]);
    });

    it("lowercases the result and is agnostic to what the suffix is", () => {
        expect(computeAppHosts("MyApp", ["Alice.Example.COM", "tenant-7.internal"])).to.deep.equal([
            "myapp-alice.example.com",
            "myapp-tenant-7.internal",
        ]);
    });
});

describe("computeAllowedHosts", () => {
    it("gives an ordinary app only its own <app>-<suffix> hosts", () => {
        expect(
            computeAllowedHosts({ clientId: "myapp", hostSuffixes: SUFFIXES, rootClientId: "maison" }),
        ).to.deep.equal(computeAppHosts("myapp", SUFFIXES));
    });

    it("appends the bare suffixes for the root app, after its own hosts", () => {
        // Order is load-bearing: callers treat entry 0 as their canonical origin,
        // and for an AppShield acting as an OAuth AS that value is the issuer.
        expect(
            computeAllowedHosts({ clientId: "maison", hostSuffixes: SUFFIXES, rootClientId: "maison" }),
        ).to.deep.equal([
            "maison-wisera.inojob.com",
            "maison-80-241-218-30.nip.io",
            "maison-80-241-218-30.sslip.io",
            "wisera.inojob.com",
            "80-241-218-30.nip.io",
            "80-241-218-30.sslip.io",
        ]);
    });

    it("gives nobody the bare suffixes when no root app is configured", () => {
        for (const rootClientId of ["", undefined]) {
            expect(
                computeAllowedHosts({ clientId: "maison", hostSuffixes: SUFFIXES, rootClientId }),
            ).to.deep.equal(computeAppHosts("maison", SUFFIXES));
        }
    });

    it("lowercases the bare suffixes and dedups against the app's own hosts", () => {
        expect(
            computeAllowedHosts({ clientId: "app", hostSuffixes: ["Alice.EXAMPLE.com"], rootClientId: "app" }),
        ).to.deep.equal(["app-alice.example.com", "alice.example.com"]);
        // A suffix list that already spells out the app's own host must not
        // produce the same URI twice.
        expect(
            computeAllowedHosts({ clientId: "app", hostSuffixes: ["x.test", "app-x.test"], rootClientId: "app" }),
        ).to.deep.equal(["app-x.test", "app-app-x.test", "x.test"]);
    });
});

describe("validateRedirectUri", () => {
    // The allowlist is recomputed from the PTR-attested client_id + suffix list —
    // exactly what server.ts passes to the validator.
    const allowedHosts = new Set(computeAppHosts("appshield-demo", SUFFIXES));
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

describe("validateRedirectUri with a root app's allowlist", () => {
    const rootOpts = {
        clientId: "maison",
        allowedHosts: new Set(
            computeAllowedHosts({ clientId: "maison", hostSuffixes: SUFFIXES, rootClientId: "maison" }),
        ),
    };

    it("accepts the bare root hostname for the root app", () => {
        expect(() => validateRedirectUri("https://wisera.inojob.com/nhl-auth/oidc/callback", rootOpts)).to.not.throw();
        expect(() => validateRedirectUri("https://maison-wisera.inojob.com/nhl-auth/oidc/callback", rootOpts)).to.not.throw();
    });

    it("still refuses another app's host", () => {
        expect(() => validateRedirectUri("https://beacon-wisera.inojob.com/cb", rootOpts)).to.throw(ValidationError);
    });

    it("refuses the bare hostname for an app that is NOT the root app", () => {
        // The whole security property: being able to ASK for the bare host is not
        // enough — the caller has to be the container the root domain points at.
        const opts = {
            clientId: "beacon",
            allowedHosts: new Set(
                computeAllowedHosts({ clientId: "beacon", hostSuffixes: SUFFIXES, rootClientId: "maison" }),
            ),
        };
        expect(() => validateRedirectUri("https://wisera.inojob.com/cb", opts)).to.throw(ValidationError);
    });
});

describe("validateCallbackPath", () => {
    it("accepts ordinary callback paths", () => {
        expect(validateCallbackPath("/nhl-auth/oidc/callback")).to.equal("/nhl-auth/oidc/callback");
        expect(validateCallbackPath("/")).to.equal("/");
        expect(validateCallbackPath("/cb?tenant=a")).to.equal("/cb?tenant=a");
    });

    it("rejects anything that is not a plain absolute path", () => {
        expect(() => validateCallbackPath("cb")).to.throw(ValidationError);
        expect(() => validateCallbackPath("https://evil.com/cb")).to.throw(ValidationError);
        expect(() => validateCallbackPath("//evil.com/cb")).to.throw(ValidationError);
        expect(() => validateCallbackPath("/\\evil.com/cb")).to.throw(ValidationError);
        expect(() => validateCallbackPath("/cb#frag")).to.throw(ValidationError);
        expect(() => validateCallbackPath("/a/../../cb")).to.throw(ValidationError);
        expect(() => validateCallbackPath("/cb with space")).to.throw(ValidationError);
    });

    it("rejects control characters (header/URI smuggling into the join)", () => {
        expect(() => validateCallbackPath("/cb" + String.fromCharCode(7) + "x")).to.throw(ValidationError);
        expect(() => validateCallbackPath("/cb" + String.fromCharCode(10) + "Host: evil")).to.throw(ValidationError);
        expect(() => validateCallbackPath("/cb" + String.fromCharCode(0))).to.throw(ValidationError);
    });

    it("rejects non-strings, empties and overly long paths", () => {
        expect(() => validateCallbackPath(undefined)).to.throw(ValidationError);
        expect(() => validateCallbackPath(42)).to.throw(ValidationError);
        expect(() => validateCallbackPath(["/cb"])).to.throw(ValidationError);
        expect(() => validateCallbackPath("")).to.throw(ValidationError);
        expect(() => validateCallbackPath("/" + "a".repeat(512))).to.throw(ValidationError);
    });
});
