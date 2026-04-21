import { expect } from "chai";
import { validateContainerName, validateRedirectUri, ValidationError } from "../validation.js";

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

describe("validateRedirectUri", () => {
    const opts = { clientId: "myapp", hostnameSuffix: undefined };

    it("accepts exact first-label match", () => {
        expect(() => validateRedirectUri("https://myapp.nsl.sh/cb", opts)).to.not.throw();
        expect(() => validateRedirectUri("https://myapp.example.com/nhl-auth/oidc/callback", opts)).to.not.throw();
    });

    it("accepts dash-suffixed first label (user-specific subdomain)", () => {
        expect(() => validateRedirectUri("https://myapp-alice.nsl.sh/cb", opts)).to.not.throw();
        expect(() => validateRedirectUri("https://myapp-bob.nsl.sh/cb", opts)).to.not.throw();
    });

    it("rejects unrelated hostnames", () => {
        expect(() => validateRedirectUri("https://otherapp.nsl.sh/cb", opts)).to.throw(ValidationError);
        expect(() => validateRedirectUri("https://evil.com/cb", opts)).to.throw(ValidationError);
    });

    it("rejects prefix-match without dash separator (typosquat defense)", () => {
        // These are the critical negative cases — a naive startsWith would let them through.
        expect(() => validateRedirectUri("https://myapp2.nsl.sh/cb", opts)).to.throw(ValidationError);
        expect(() => validateRedirectUri("https://myappX.nsl.sh/cb", opts)).to.throw(ValidationError);
        expect(() => validateRedirectUri("https://myappa.nsl.sh/cb", opts)).to.throw(ValidationError);
    });

    it("rejects empty first label after dash (myapp-.nsl.sh)", () => {
        expect(() => validateRedirectUri("https://myapp-.nsl.sh/cb", opts)).to.throw(ValidationError);
    });

    it("rejects bare dash-only suffix", () => {
        expect(() => validateRedirectUri("https://myapp-/cb", opts)).to.throw(ValidationError);
    });

    it("enforces hostname suffix when configured", () => {
        const opts2 = { clientId: "myapp", hostnameSuffix: ".nsl.sh" };
        expect(() => validateRedirectUri("https://myapp-alice.nsl.sh/cb", opts2)).to.not.throw();
        expect(() => validateRedirectUri("https://myapp-alice.other.com/cb", opts2)).to.throw(ValidationError);
    });

    it("rejects non-http(s) schemes", () => {
        expect(() => validateRedirectUri("javascript:alert(1)", opts)).to.throw(ValidationError);
        expect(() => validateRedirectUri("data:text/html,x", opts)).to.throw(ValidationError);
        expect(() => validateRedirectUri("file:///etc/passwd", opts)).to.throw(ValidationError);
    });

    it("rejects malformed URIs", () => {
        expect(() => validateRedirectUri("not a url", opts)).to.throw(ValidationError);
        expect(() => validateRedirectUri("", opts)).to.throw(ValidationError);
    });

    it("rejects overly long URIs", () => {
        const long = "https://myapp.nsl.sh/" + "a".repeat(3000);
        expect(() => validateRedirectUri(long, opts)).to.throw(ValidationError);
    });
});
