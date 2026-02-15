(async function () {
    function fpComponent() {
        return [
            navigator.userAgent,
            navigator.language,
            screen.width + "x" + screen.height,
            screen.colorDepth,
            Intl.DateTimeFormat().resolvedOptions().timeZone,
            navigator.platform
        ].join("::");
    }

    async function sha256(input) {
        const buffer = new TextEncoder().encode(input);
        const hash = await crypto.subtle.digest("SHA-256", buffer);
        return Array.from(new Uint8Array(hash))
            .map(b => b.toString(16).padStart(2, "0"))
            .join("");
    }

    const fingerprint = await sha256(fpComponent());

    const input = document.getElementById("device_fingerprint");
    if (input) input.value = fingerprint;
})();
