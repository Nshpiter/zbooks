import { serve } from "https://deno.land/std@0.177.1/http/server.ts";
import { getCookies, Cookie, setCookie } from "https://deno.land/std@0.177.1/http/cookie.ts";

// --- Configuration ---
const ZLIB_BASE_URL = "z-library.sk"; // Use the appropriate base domain Z-Library resolves to
// const PROXY_DOMAIN = ""; // <<<<<====== MAKE SURE THIS IS YOUR CUSTOM DOMAIN (现在从环境变量读取)
const HAS_AGREED_COOKIE = "has_agreed";
const HIDE_TELEGRAM_GROUP_COOKIE = "hide_telegram_group";
const AUTH_COOKIE_NAME = "proxy_auth_session"; // Name for the authentication cookie

// --- Get Password from Environment Variable ---
// !! IMPORTANT: Set PROXY_PASSWORD in your Deno Deploy environment variables !!
const REQUIRED_PASSWORD = Deno.env.get("PROXY_PASSWORD");
if (!REQUIRED_PASSWORD) {
  console.error("FATAL ERROR: PROXY_PASSWORD environment variable is not set!");
  console.error("Please set the PROXY_PASSWORD environment variable in your Deno Deploy project settings.");
  // Optional: Exit if password not set, otherwise auth is disabled
  // Deno.exit(1);
}

// --- Get Domain from Environment Variable ---
const PROXY_DOMAIN = Deno.env.get("PROXY_DOMAIN");

if (!PROXY_DOMAIN) {
    console.error("FATAL ERROR: PROXY_DOMAIN environment variable is not set!");
    console.error("Please set the PROXY_DOMAIN environment variable in your Deno Deploy project settings.");
    Deno.exit(1); // 可选：如果域名未设置，退出程序
}

// --- Main Request Handler ---
async function handler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  // --- Uptime-Kuma Status Endpoint ---
  if (path === "/status") {
    return new Response("OK", { status: 200 });
  }

  const params = url.searchParams;
  const incomingCookies = getCookies(req.headers);

  // --- 1. Authentication Check ---
  if (REQUIRED_PASSWORD) {
      const isAuthenticated = await isValidAuthCookie(incomingCookies);

      if (!isAuthenticated) {
          if (req.method === 'POST' && path === '/auth-login') {
              return await handleLoginSubmission(req);
          }
          const attemptedUrl = path + url.search;
          return handleLoginPage(false, attemptedUrl);
      }
  } else {
      console.warn("Warning: PROXY_PASSWORD is not set. Authentication is disabled.");
  }

  // --- 2. Disclaimer / Config Pages (Only if Authenticated or Auth Disabled) ---
  const hasAgreed = incomingCookies[HAS_AGREED_COOKIE] === "true";

  // Show disclaimer only if authenticated (or auth disabled) and haven't agreed
  if (!hasAgreed) {
    if (path === "/re-config") { // Allow access to config page even without agreeing
        return handleConfigPage(req);
    }
    // Extract potential redirect URL from login to pass to disclaimer
    const redirectTo = params.get('redirect_to') || '/'; // Get from query param if login redirected here
    return handleDisclaimerPage(req, params.has("flags-nogroup"), redirectTo); // Pass redirect URL
  }

  // Handle re-config page if user has agreed
  if (path === "/re-config") {
    return handleConfigPage(req);
  }

  // --- 3. Proxy Logic (Only if Authenticated/Auth Disabled and Agreed) ---
  const lang = incomingCookies["lang"] || null; // Default to null if no lang cookie
  const targetHost = lang === 'zh' ? `zh.${ZLIB_BASE_URL}` : ZLIB_BASE_URL;
  const targetUrl = new URL(req.url);
  targetUrl.protocol = "https:";
  targetUrl.host = targetHost;
  targetUrl.port = "";

  try {
    const requestHeaders = getModifiedRequestHeaders(req.headers, targetHost, lang);
    console.log(`[Auth OK] [Agreed] [${new Date().toISOString()}] Requesting: ${targetUrl.toString()}`);

    const targetResponse = await fetch(targetUrl.toString(), {
      method: req.method,
      headers: requestHeaders,
      body: req.body,
      redirect: "manual", // Important: handle redirects manually
    });

    console.log(`[Auth OK] [Agreed] [${new Date().toISOString()}] Response Status from ${targetHost}: ${targetResponse.status}`);
    const responseHeaders = new Headers(targetResponse.headers);

    // Modify Response Headers (Location, Cookies, etc.)
    modifyResponseHeaders(responseHeaders, targetResponse, targetUrl, lang);

    return new Response(targetResponse.body, {
      status: targetResponse.status,
      statusText: targetResponse.statusText,
      headers: responseHeaders,
    });

  } catch (error) {
    console.error(`[Auth OK] [Agreed] [${new Date().toISOString()}] Proxy Error:`, error);
    if (error instanceof TypeError && error.message.includes('fetch failed')) {
         return new Response(`Proxy error: Could not connect to origin server (${targetHost}). Please try again later.`, { status: 502 });
    }
    return new Response("Proxy error occurred. Check logs.", { status: 500 });
  }
}

// --- Authentication Helper Functions ---

/** Checks if the authentication cookie is present and valid. */
async function isValidAuthCookie(cookies: Record<string, string>): Promise<boolean> {
    // Simple check: Does the cookie exist with the correct value?
    return cookies[AUTH_COOKIE_NAME] === "ok";
}

/** Displays the HTML login page */
function handleLoginPage(showError: boolean = false, attemptedUrl: string = "/"): Response {
    const backgroundImage = "https://raw.githubusercontent.com/Nshpiter/docker-accelerate/refs/heads/main/background.jpg";
    const errorMessage = showError ? '<p class="error-message">密码错误，请重试</p>' : '';
    const htmlContent = `
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>需要登录</title>
    <style>
        body{display:flex;justify-content:center;align-items:center;min-height:100vh;font-family:sans-serif,"Microsoft YaHei","SimHei";margin:0;background-image:url('${backgroundImage}');background-size:cover;background-position:center;background-repeat:no-repeat;}
        .login-container{background-color:rgba(255,255,255,0.85);padding:40px;border-radius:8px;box-shadow:0 4px 15px rgba(0,0,0,0.2);text-align:center;max-width:400px;width:90%;}
        h1{color:#333;margin-bottom:15px;font-size:24px;}
        p{color:#555;margin-bottom:30px;}
        label{display:block;text-align:left;margin-bottom:8px;font-weight:bold;color:#444;}
        input[type="password"]{width:calc(100% - 24px);padding:12px;margin-bottom:20px;border:1px solid #bbb;border-radius:4px;font-size:16px;background-color:rgba(255,255,255,0.9);}
        button{background-color:#007bff;color:white;padding:12px 25px;border:none;border-radius:4px;font-size:16px;font-weight:bold;cursor:pointer;width:100%;transition:background-color 0.3s ease;}
        button:hover{background-color:#0056b3;}
        .error-message{color:#dc3545;margin-bottom:15px;font-weight:bold;}
    </style>
</head>
<body>
    <div class="login-container">
        <h1>需要登录</h1>
        <p>请输入密码以访问代理服务</p>
        ${errorMessage}
        <form method="POST" action="/auth-login">
            <label for="password">密码:</label>
            <input type="password" id="password" name="password" required autofocus>
            <input type="hidden" name="redirect_to" value="${encodeURIComponent(attemptedUrl)}">
            <button type="submit">登录</button>
        </form>
    </div>
</body>
</html>`;
    return new Response(htmlContent, {
        status: 401, headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
}

/** Handles the submission of the login form. */
async function handleLoginSubmission(req: Request): Promise<Response> {
    if (!REQUIRED_PASSWORD) {
        console.error(`[${new Date().toISOString()}] Login submission attempt but PROXY_PASSWORD is not configured.`);
        return new Response("Authentication is not configured on the server.", { status: 500 });
    }
    try {
        const formData = await req.formData();
        const submittedPassword = formData.get("password") as string;
        const redirectTo = formData.get("redirect_to") as string || "/";

        if (submittedPassword === REQUIRED_PASSWORD) {
            const headers = new Headers();
            // --- *** START FIX *** ---
            const cookie: Cookie = {
                name: AUTH_COOKIE_NAME,
                value: "ok",
                path: "/",
                domain: PROXY_DOMAIN, // Explicitly set domain
                httpOnly: true,
                secure: true,
                sameSite: "Lax",
                maxAge: 86400 * 30, // 30 days
            };
            // --- *** END FIX *** ---
            setCookie(headers, cookie);

            // Redirect to the original destination or homepage
            // Add redirect_to as a query parameter for the disclaimer page to pick up
            let safeRedirectTo = "/";
            try {
                const decodedRedirect = decodeURIComponent(redirectTo);
                if (decodedRedirect.startsWith("/") && !decodedRedirect.startsWith("//") && !decodedRedirect.includes(":") ) {
                     safeRedirectTo = decodedRedirect;
                }
            } catch (e) { /* Keep default */ }

            const redirectUrl = new URL(req.url); // Use current request URL as base
            redirectUrl.pathname = "/"; // Redirect to root (where disclaimer check happens)
            redirectUrl.searchParams.set("redirect_to", safeRedirectTo); // Pass original target

            console.log(`[${new Date().toISOString()}] Authentication successful. Redirecting via / to check agreement. Original target: ${safeRedirectTo}`);
            headers.set("Location", redirectUrl.toString());
            return new Response(null, { status: 302, headers });

        } else {
            console.log(`[${new Date().toISOString()}] Authentication failed: Incorrect password attempt.`);
            const attemptedUrl = decodeURIComponent(redirectTo);
            return handleLoginPage(true, attemptedUrl);
        }
    } catch (error) {
         console.error(`[${new Date().toISOString()}] Error processing login form:`, error);
         return new Response("Error processing login request.", { status: 500 });
    }
}


// --- Existing Helper Functions (Proxy/Disclaimer/Config) ---

/** Modifies response headers: Location, Set-Cookie, etc. */
function modifyResponseHeaders(responseHeaders: Headers, targetResponse: Response, targetUrl: URL, lang: string | null): void {
    // 1. Handle Redirects (Location Header)
     if (responseHeaders.has("location")) {
      const originalLocation = responseHeaders.get("location")!;
      try {
        const targetLocation = new URL(originalLocation, targetUrl);
        if (targetLocation.hostname.endsWith(ZLIB_BASE_URL)) {
          const newLocation = targetLocation.pathname + targetLocation.search + targetLocation.hash;
          responseHeaders.set("location", newLocation);
        }
      } catch (e) {
         if (originalLocation.startsWith("/")) {
            responseHeaders.set("location", originalLocation);
        } else { /* Keep external or potentially invalid ones */ }
      }
    }

    // 2. Remove problematic headers
    responseHeaders.delete("X-Frame-Options");
    responseHeaders.delete("Content-Security-Policy");
    responseHeaders.delete("Strict-Transport-Security");

    // 3. Process and Modify Set-Cookie Headers
    const originalSetCookieHeaders = targetResponse.headers.getSetCookie();
    responseHeaders.delete("Set-Cookie");

    for (const cookieString of originalSetCookieHeaders) {
        try {
            const modifiedCookieString = modifyCookieString(cookieString, PROXY_DOMAIN);
            if (modifiedCookieString) {
                responseHeaders.append("Set-Cookie", modifiedCookieString);
            }
        } catch (e) {
            console.error(`[${new Date().toISOString()}] Error processing cookie string "${cookieString}":`, e);
        }
    }

    // 4. Force Set siteLanguage Cookie (Always, if authenticated and agreed)
    const siteLanguageValue = lang === 'zh' ? 'zh' : 'en';
    const siteLanguageCookie: Cookie = {
      name: "siteLanguage", value: siteLanguageValue, path: "/",
      domain: PROXY_DOMAIN, // <<< Ensure domain is set here too
      secure: true, sameSite: "None",
      maxAge: 31536000 // 1 year
    };
    const siteLanguageCookieString = getCookieString(siteLanguageCookie);
    responseHeaders.append("Set-Cookie", siteLanguageCookieString);

    // 5. Vary Header
    if (!responseHeaders.has("Vary")) {
        responseHeaders.set("Vary", "Cookie");
    } else {
        const vary = responseHeaders.get("Vary")!;
        if (!vary.split(',').map(s => s.trim().toLowerCase()).includes('cookie')) {
            responseHeaders.set("Vary", `${vary}, Cookie`);
        }
    }
}

/** Creates modified headers for the outgoing request to Z-Library. */
function getModifiedRequestHeaders(originalHeaders: Headers, targetHost: string, lang: string | null): Headers {
  const headers = new Headers(originalHeaders);
  headers.set("Host", targetHost);
  headers.set("Referer", `https://${targetHost}/`);
  headers.set("Origin", `https://${targetHost}`);
  if (lang === 'zh') {
    headers.set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8");
  } else {
     const originalAcceptLanguage = headers.get("Accept-Language");
     if (!originalAcceptLanguage || !originalAcceptLanguage.toLowerCase().startsWith('en')) {
        headers.set("Accept-Language", "en-US,en;q=0.9");
     }
  }
  headers.delete("via");
  headers.delete("x-forwarded-for");
  headers.delete("x-forwarded-host");
  headers.delete("x-forwarded-proto");
  headers.delete("x-real-ip");
  headers.delete("forwarded");
  return headers;
}

/** Parses a Set-Cookie string, modifies domain/attributes, and returns the new string. */
function modifyCookieString(cookieString: string, proxyDomain: string): string | null {
    if (!cookieString) return null;
    const parts = cookieString.split(';').map(part => part.trim());
    if (parts.length === 0) return null;
    const nameValueMatch = parts[0].match(/^([^=]+)=(.*)$/);
    if (!nameValueMatch) return null;
    const name = nameValueMatch[1];
    const value = nameValueMatch[2];

    if (name === AUTH_COOKIE_NAME) return null; // Ignore if Z-lib tries to set our auth cookie

    const modifiedAttributes = [`${name}=${value}`];
    let domainSet = false;

    for (let i = 1; i < parts.length; i++) {
        const attribute = parts[i];
        const lowerAttr = attribute.toLowerCase();
        if (lowerAttr.startsWith("domain=")) {
            modifiedAttributes.push(`Domain=${proxyDomain}`); // Always override
            domainSet = true;
        } else if (lowerAttr.startsWith("secure") || lowerAttr.startsWith("samesite=")) {
            // Skip, we will add them manually
        } else if (lowerAttr.startsWith("path=") || lowerAttr.startsWith("expires=") || lowerAttr.startsWith("max-age=") || lowerAttr.startsWith("httponly")) {
            modifiedAttributes.push(attribute); // Keep standard ones
        } else if(attribute) {
             modifiedAttributes.push(attribute); // Keep unknown ones
        }
    }

    if (!domainSet) modifiedAttributes.push(`Domain=${proxyDomain}`);
    modifiedAttributes.push("Secure"); // Always add Secure
    modifiedAttributes.push("SameSite=None"); // Use None for potential cross-site needs

    return [...new Set(modifiedAttributes)].join('; '); // Remove duplicates and join
}

/** Creates a Set-Cookie header string from a Cookie object. */
function getCookieString(cookie: Cookie): string {
    let parts = [`${cookie.name}=${encodeURIComponent(cookie.value)}`];
    if (cookie.expires) parts.push(`Expires=${cookie.expires.toUTCString()}`);
    if (cookie.maxAge !== undefined) parts.push(`Max-Age=${cookie.maxAge}`);
    if (cookie.domain) parts.push(`Domain=${cookie.domain}`); // <<< Use this
    if (cookie.path) parts.push(`Path=${cookie.path}`);
    if (cookie.secure) parts.push("Secure");
    if (cookie.httpOnly) parts.push("HttpOnly");
    if (cookie.sameSite) parts.push(`SameSite=${cookie.sameSite}`);
    return parts.join("; ");
}

/** Handles the /re-config page for setting the language cookie. */
function handleConfigPage(req: Request): Response {
  // Inject PROXY_DOMAIN into the HTML for the JS
  const htmlContent = `
<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><title>配置语言 / Configure Language</title><meta name="viewport" content="width=device-width, initial-scale=1.0"><style>body{font-family:sans-serif,"Microsoft YaHei","SimHei";line-height:1.6;padding:20px;max-width:600px;margin:40px auto;background-color:#f4f4f4;}.container{background-color:#fff;border:1px solid #ddd;padding:30px;border-radius:8px;box-shadow:0 2px 5px rgba(0,0,0,0.1);}h1{text-align:center;color:#333;border-bottom:1px solid #eee;padding-bottom:10px;margin-bottom:20px;}p{color:#555;margin-bottom:20px;text-align:center;}.buttons{display:flex;justify-content:center;gap:15px;margin-bottom:20px;}button{padding:10px 25px;font-size:16px;cursor:pointer;border:none;border-radius:4px;background-color:#007bff;color:white;transition:background-color 0.2s;}button:hover{background-color:#0056b3;}.back-link{display:block;text-align:center;margin-top:25px;color:#007bff;text-decoration:none;}.back-link:hover{text-decoration:underline;}</style></head><body><div class="container"><h1>设置语言 / Set Language</h1><p>选择您想使用的语言 / Choose your preferred language:</p><div class="buttons"><button onclick="setLanguage('')">English (Default)</button><button onclick="setLanguage('zh')">中文 (Chinese)</button></div><a href="/" class="back-link">返回首页 / Back to Home</a></div><script>
    // Inject proxy domain into script for cookie setting
    const proxyDomain = "${PROXY_DOMAIN}";
    function setLanguage(lang) {
      const expires = new Date();
      expires.setFullYear(expires.getFullYear() + 1); // Cookie expires in 1 year
      // Ensure SameSite=None and Secure are set, and DOMAIN
      const cookieString = "lang=" + lang + "; path=/; expires=" + expires.toUTCString() + "; Secure; SameSite=None; domain=" + proxyDomain;
      document.cookie = cookieString;
      alert("语言偏好已保存。正在重定向到首页... / Language preference saved. Redirecting to homepage...");
      window.location.href = "/"; // Redirect back to home
    }
  </script></body></html>`;
  return new Response(htmlContent, { headers: { "content-type": "text/html; charset=utf-8" } });
}

/** Handles the disclaimer page shown on first visit after authentication. */
function handleDisclaimerPage(req: Request, hideTelegramInitially: boolean, redirectTo: string = "/"): Response {
  const cookies = getCookies(req.headers);
  const hideTelegramPref = cookies[HIDE_TELEGRAM_GROUP_COOKIE] === "true";
  const hideTelegram = hideTelegramInitially || hideTelegramPref;
  let telegramSection = `
      <div class="section telegram-section">
        <h2>获取最新网址 / Get Latest URL</h2>
        <p>此网站可能会被阻止访问, 在我们的 Telegram 群组获取最新网址 / This site might get blocked, get the latest URL in our Telegram group: </p>
        <p>加入 Telegram 群组 / Join Telegram Group: <a href="https://t.me/theOpenProxy_Group" target="_blank">加入群组 / Join Group</a></p>
        <button onclick="hideTelegramGroup()" class="hide-button">不再显示此部分 / Do Not Show Again</button>
      </div>`;
  if (hideTelegram) telegramSection = "";

  // Inject PROXY_DOMAIN and redirectTo into the HTML for the JS
  const htmlContent = `
<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><title>欢迎与免责声明 / Welcome & Disclaimer</title><meta name="viewport" content="width=device-width, initial-scale=1.0"><style>body{font-family:sans-serif,"Microsoft YaHei","SimHei";line-height:1.7;padding:10px;background-color:#f8f9fa;color:#333;}.container{max-width:850px;margin:20px auto;background-color:#fff;border:1px solid #dee2e6;padding:25px 35px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.08);}h1,h2{border-bottom:1px solid #eee;padding-bottom:8px;margin-bottom:18px;color:#0056b3;}h1{text-align:center;font-size:1.8em;}h2{font-size:1.4em;margin-top:25px;}.section{border:1px solid #e9ecef;padding:15px 20px;margin-bottom:20px;background-color:#fdfdfd;border-radius:5px;}button{padding:12px 25px;font-size:16px;cursor:pointer;border:none;border-radius:4px;margin-right:10px;margin-top:10px;transition:background-color 0.2s;}.agree-button{background-color:#28a745;color:white;font-weight:bold;}.agree-button:hover{background-color:#218838;}.hide-button{background-color:#6c757d;color:white;font-size:14px;padding:8px 15px;}.hide-button:hover{background-color:#5a6268;}.footer{text-align:center;margin-top:30px;padding-top:20px;border-top:1px solid #eee;}a{color:#007bff;text-decoration:none;}a:hover{text-decoration:underline;}ul{padding-left:25px;list-style:disc;margin-bottom:15px;}li{margin-bottom:10px;}i{color:#555;font-size:0.95em;}.telegram-section{background-color:#e7f3ff;border-color:#b8daff;}</style></head><body><div class="container"><h1>欢迎! / Welcome!</h1><div class="section disclaimer"><h2>注意事项 / Important Notes</h2><ul><li>本代理服务仅供学习和研究使用，请勿用于非法用途。<br><i>This proxy service is for learning and research purposes only. Do not use for illegal activities.</i></li><li>请遵守 Z-Library 的相关条款和规定。<br><i>Please adhere to Z-Library's terms and conditions.</i></li><li>本代理服务不对 Z-Library 的内容负责。<br><i>This proxy service is not responsible for the content provided by Z-Library.</i></li><li>请自行承担使用本代理服务可能带来的风险。<br><i>Use this proxy service at your own risk.</i></li></ul></div><div class="section"><h2>免责声明 / Disclaimer</h2><p>本代理服务不对因使用本服务而产生的任何损失承担责任。<br><i>This service assumes no liability for any loss resulting from its use.</i></p></div><div class="section"><h2>关于 / About</h2><p>本代理服务由 The Open Proxy 提供。<br><i>This proxy service is provided by The Open Proxy.</i></p></div><div class="section"><h2>切换语言 / Change Language</h2><p>您可以通过访问 <a href="/re-config">/re-config</a> 页面来切换语言。<br><i>You can change the language by visiting the <a href="/re-config">/re-config</a> page.</i></p></div>${telegramSection}</div><div class="footer"><button class="agree-button" onclick="agreeAndProceed()">我已阅读并同意 / I Have Read and Agree</button></div><script>
    const HAS_AGREED_COOKIE = "${HAS_AGREED_COOKIE}";
    const HIDE_TELEGRAM_GROUP_COOKIE = "${HIDE_TELEGRAM_GROUP_COOKIE}";
    const PROXY_DOMAIN = "${PROXY_DOMAIN}"; // Inject proxy domain
    const finalRedirectTarget = "${redirectTo}"; // Inject final destination
    const hideTelegramParam = ${hideTelegramInitially};

    function setPermCookie(name, value) {
        const expires = new Date();
        expires.setFullYear(expires.getFullYear() + 1);
        // Ensure domain, Secure, SameSite=None are set correctly
        document.cookie = name + "=" + value + "; path=/; expires=" + expires.toUTCString() + "; Secure; SameSite=None; domain=" + PROXY_DOMAIN;
    }

    function agreeAndProceed() {
      setPermCookie(HAS_AGREED_COOKIE, "true");
      if (hideTelegramParam && !document.cookie.includes(HIDE_TELEGRAM_GROUP_COOKIE + "=true")) {
         setPermCookie(HIDE_TELEGRAM_GROUP_COOKIE, "true");
      }
      // Redirect to the actual destination passed from login/handler
      window.location.href = finalRedirectTarget || '/';
    }

    function hideTelegramGroup() {
        setPermCookie(HIDE_TELEGRAM_GROUP_COOKIE, "true");
        alert("Telegram 群组部分将在下次访问时隐藏。 / Telegram group section will be hidden on next visit.");
        const tgSection = document.querySelector('.telegram-section');
        if (tgSection) tgSection.style.display = 'none';
    }
  </script></body></html>`;
  return new Response(htmlContent, {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}


// --- Start Server ---
console.log(`[${new Date().toISOString()}] Server starting...`);
if (REQUIRED_PASSWORD) {
    console.log(`[${new Date().toISOString()}] Authentication enabled. Access via https://${PROXY_DOMAIN}/`);
} else {
     console.warn(`[${new Date().toISOString()}] WARNING: Authentication DISABLED because PROXY_PASSWORD env var is not set. Access via https://${PROXY_DOMAIN}/`);
}
serve(handler);
