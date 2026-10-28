/* Generated during Netlify builds. For local hosting, set window.LEMS_API_BASE_URL before this script. */
(function () {
    const apiBase = String(window.LEMS_API_BASE_URL || "").replace(/\/$/, "");
    const originalFetch = window.fetch.bind(window);

    window.fetch = function (input, init) {
        let request = input;
        const options = Object.assign({}, init || {});
        let rawUrl = typeof input === "string" ? input : (input && input.url) || "";
        const isLocalApi = /^https?:\/\/(localhost|127\.0\.0\.1):3000\//i.test(rawUrl);
        const isRelativeApi = rawUrl.startsWith("/api/");
        if (apiBase && (isLocalApi || isRelativeApi)) {
            const path = isLocalApi ? rawUrl.replace(/^https?:\/\/(localhost|127\.0\.0\.1):3000/i, "") : rawUrl;
            request = apiBase + path;
        }

        const targetUrl = typeof request === "string" ? request : (request && request.url) || "";
        if (targetUrl.includes("/api/")) {
            const token = sessionStorage.getItem("lemsToken");
            const headers = new Headers(options.headers || (request instanceof Request ? request.headers : undefined));
            if (token && !headers.has("Authorization")) headers.set("Authorization", "Bearer " + token);
            options.headers = headers;
        }
        return originalFetch(request, options);
    };
})();