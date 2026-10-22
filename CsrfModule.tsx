// client/src/modules/CsrfModule.jsx
// Member 2: Faisal Imran - CSRF Module Frontend
// Create lab session, send a protected state-changing request, and
// a dedicated invalid-token test to confirm Safe mode blocks forged requests.

import { useState } from "react";

const API = "http://localhost:5000";

export default function CsrfModule({ mode, setMessage }) {
  const vulnerable = mode === "vulnerable";

  const [csrfEmail, setCsrfEmail] = useState("changed-by-lab@example.com");
  const [csrfToken, setCsrfToken] = useState("");
  const [csrfSessionReady, setCsrfSessionReady] = useState(false);
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);

  async function createCsrfSession() {
    setBusy(true);
    setMessage("");
    setResult(null);
    setCsrfSessionReady(false);
    setCsrfToken("");

    try {
      const response = await fetch(`${API}/api/lab/csrf/session`, {
        method: "GET",
        credentials: "include"
      });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Could not create the lab session.");
      }

      if (!data.csrfToken) {
        throw new Error("The server did not return a CSRF token.");
      }

      setCsrfToken(data.csrfToken);
      setCsrfSessionReady(true);
      setMessage("Lab session created. You can now run the CSRF test.");
    } catch (error) {
      setMessage(`Session setup failed: ${error.message}`);
    } finally {
      setBusy(false);
    }
  }

  async function runCsrfTest() {
    if (!csrfEmail.trim()) {
      setMessage("Enter a test email first.");
      return;
    }

    setBusy(true);
    setMessage("");
    setResult(null);

    try {
      const headers = { "Content-Type": "application/json" };

      if (!vulnerable) {
        if (!csrfSessionReady || !csrfToken) {
          throw new Error("Create a lab session first to obtain a CSRF token.");
        }
        headers["x-csrf-token"] = csrfToken;
      }

      const response = await fetch(`${API}/api/lab/csrf/change-email`, {
        method: "POST",
        credentials: "include",
        headers,
        body: JSON.stringify({
          email: csrfEmail.trim(),
          mode
        })
      });

      const data = await response.json();
      setResult({ type: "csrf", data, status: response.status });

      setMessage(
        response.ok
          ? `Request accepted in ${mode} mode.`
          : `Request rejected (${response.status}).`
      );
    } catch (error) {
      setMessage(error.message || "Could not connect to the CSRF endpoint.");
    } finally {
      setBusy(false);
    }
  }

  async function runInvalidCsrfTest() {
    if (!csrfSessionReady) {
      setMessage("Create a lab session first.");
      return;
    }

    setBusy(true);
    setMessage("");
    setResult(null);

    try {
      const response = await fetch(`${API}/api/lab/csrf/change-email`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "x-csrf-token": "invalid-token-for-testing"
        },
        body: JSON.stringify({
          email: csrfEmail.trim(),
          mode: "safe"
        })
      });

      const data = await response.json();
      setResult({ type: "csrf", data, status: response.status });

      setMessage(
        response.status === 403
          ? "PASS: Safe mode rejected the invalid CSRF token."
          : `FAIL: Expected HTTP 403, received HTTP ${response.status}.`
      );
    } catch {
      setMessage("Could not connect to the CSRF endpoint.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">LAB 02</p>
          <h2>Cross-Site Request Forgery</h2>
        </div>
        <span className="tag">State-changing request</span>
      </div>

      <div className="lab-section">
        <h3>Change account email</h3>
        <p>
          Create a lab session first. Safe mode sends the session's CSRF
          token; Vulnerable mode intentionally omits that token for
          comparison.
        </p>

        <button
          className="primary-button"
          disabled={busy}
          onClick={createCsrfSession}
        >
          {busy ? "Please wait..." : "Create lab session"}
        </button>

        <div className="detail-row">
          <span>Lab session</span>
          <strong>{csrfSessionReady ? "Ready" : "Not created"}</strong>
        </div>

        <label htmlFor="csrf-email">New test email</label>
        <input
          id="csrf-email"
          type="email"
          value={csrfEmail}
          onChange={(event) => setCsrfEmail(event.target.value)}
          placeholder="Enter a test email"
          required
        />

        <div className="detail-row">
          <span>Current mode</span>
          <strong>{vulnerable ? "Vulnerable" : "Safe"}</strong>
        </div>

        <button
          className="primary-button"
          disabled={busy}
          onClick={runCsrfTest}
        >
          {busy ? "Sending request..." : "Send test request"}
        </button>

        <button
          className="primary-button"
          disabled={busy || !csrfSessionReady}
          onClick={runInvalidCsrfTest}
        >
          Test with Invalid CSRF Token
        </button>

        {result?.type === "csrf" && (
          <div className="result-card">
            <h4>CSRF response · HTTP {result.status}</h4>
            <pre>{JSON.stringify(result.data, null, 2)}</pre>
          </div>
        )}
      </div>
    </section>
  );
}
