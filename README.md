# Eat My Cookies

> **⚠️ Offensive-security demonstration. Read this section first.**
>
> This repository is a **working session-hijacking / account-takeover toolkit**. It is
> published **for education, security research, and authorized testing only** — so that
> developers, defenders, and everyday users can *see how this class of attack actually
> works* and learn to recognize and defend against it.
>
> A browser session (cookies + local storage + device fingerprint) is enough to log in
> as someone **without their password and without triggering MFA**. This project shows,
> end to end, how a malicious extension can harvest that material and how an attacker can
> replay it to impersonate the victim.
>
> **Do not run this against any person, account, device, or system you do not own or do
> not have explicit written permission to test.** Doing so is illegal in most
> jurisdictions (unauthorized access, wiretapping, computer-fraud statutes) regardless of
> intent. If you want to try it, use **your own test accounts on machines you control, in
> an isolated environment.** The authors/publishers accept no liability for misuse.

---

"Eat My Cookies" demonstrates the full lifecycle of a **cookie/session theft** attack:

1. A browser extension — deceptively presented to the user as an **"Extension Manager"** —
   collects the browser's session material (cookies across all sites, `localStorage`/
   `sessionStorage`, browsing history, and the device's fingerprint) and uploads it to a
   backend.
2. A backend **API** receives each capture and stores one document per profile in MongoDB.
3. A **replay script** pulls a stored profile and reconstructs that browser session inside
   a real Chrome instance — restoring not just cookies but the *client identity* (user
   agent, client hints, timezone, locale, storage, and history) so the impersonated
   session looks consistent to the target site.
4. A **landing page** ("reinstall" page) is included as the social-engineering front used
   to get the extension (re)installed.

The point of publishing it openly is transparency: this technique is used in the wild, and
the most effective defense is understanding it. The detection/defense notes below are the
part that matters most.
