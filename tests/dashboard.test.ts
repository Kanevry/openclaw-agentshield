import { describe, it, expect } from "vitest";
import { getDashboardHtml } from "../src/lib/dashboard.js";

describe("getDashboardHtml", () => {
  // Test 1: Returns valid HTML with DOCTYPE
  it("returns HTML starting with DOCTYPE", () => {
    const html = getDashboardHtml();
    expect(html).toMatch(/^<!DOCTYPE html>/);
  });

  // Test 2: Contains required elements
  it("contains title, stats cards, and events container", () => {
    const html = getDashboardHtml();
    expect(html).toContain("<title>AgentShield Dashboard</title>");
    expect(html).toContain('id="stat-total"');
    expect(html).toContain('id="stat-blocked"');
    expect(html).toContain('id="stat-warned"');
    expect(html).toContain('id="stat-allowed"');
    expect(html).toContain('id="events"');
  });

  // Test 3: No nonce attributes (Tailwind CDN incompatible with CSP nonces)
  it("has no nonce attributes", () => {
    const html = getDashboardHtml();
    expect(html).not.toContain('nonce=');
  });

  // Test 5: Contains SSE connection script
  it("contains EventSource SSE connection", () => {
    const html = getDashboardHtml();
    expect(html).toContain("EventSource");
    expect(html).toContain("/agentshield/events");
  });

  // Test 6: Contains stats fetch
  it("fetches stats on load", () => {
    const html = getDashboardHtml();
    expect(html).toContain("/agentshield/api/stats");
  });

  // Test 7: Contains JSON.parse with try/catch (SSE safety)
  it("has try/catch around JSON.parse in SSE handler", () => {
    const html = getDashboardHtml();
    expect(html).toContain("try { entry = JSON.parse(e.data); } catch { return; }");
  });

  // Test 8: Contains DOM event cap
  it("caps DOM events at MAX_DOM_EVENTS", () => {
    const html = getDashboardHtml();
    expect(html).toContain("MAX_DOM_EVENTS");
  });

  // Test 9: Uses textContent not innerHTML for dynamic content (XSS prevention)
  it("uses textContent for dynamic content (XSS safe)", () => {
    const html = getDashboardHtml();
    // innerHTML is only used for clearing: eventsEl.innerHTML = ''
    const innerHTMLUses = (html.match(/innerHTML/g) || []).length;
    expect(innerHTMLUses).toBe(1); // Only the clearing use
  });

  // Test 10: Generates consistent HTML across calls
  it("generates consistent HTML across calls", () => {
    const html1 = getDashboardHtml();
    const html2 = getDashboardHtml();
    expect(html1).toBe(html2);
  });
});
