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

  // Test 3: Nonce appears in script tags when provided
  it("includes nonce in script tags when provided", () => {
    const nonce = "test-nonce-123";
    const html = getDashboardHtml(nonce);
    expect(html).toContain(`nonce="${nonce}"`);
    // Should appear in both <script> and <style> tags
    const nonceCount = (html.match(/nonce="test-nonce-123"/g) || []).length;
    expect(nonceCount).toBeGreaterThanOrEqual(2); // script + style at minimum
  });

  // Test 4: No nonce attributes when not provided
  it("has no nonce attributes when nonce is not provided", () => {
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

  // Test 10: Nonce is different each call (when UUID is used)
  it("generates valid HTML with different nonces", () => {
    const html1 = getDashboardHtml("nonce-1");
    const html2 = getDashboardHtml("nonce-2");
    expect(html1).toContain("nonce-1");
    expect(html2).toContain("nonce-2");
    expect(html1).not.toContain("nonce-2");
  });
});
