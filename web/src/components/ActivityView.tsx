import { useEffect, useState } from "react";
import { api, type ActivityEvent } from "../api/client";

export function ActivityView() {
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    void (async () => {
      try {
        const resp = await api.activity(50);
        setEvents(resp.events);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  if (loading) return <p>Loading activity…</p>;
  if (error) return <p style={{ color: "crimson" }}>{error}</p>;

  return (
    <div>
      <h3 style={{ marginTop: 0 }}>Recent activity</h3>
      {events.length === 0 ? (
        <p style={{ color: "#666" }}>No activity recorded yet.</p>
      ) : (
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}>
          <thead>
            <tr style={{ textAlign: "left", borderBottom: "1px solid #ddd" }}>
              <th style={{ padding: "0.4rem" }}>Time</th>
              <th style={{ padding: "0.4rem" }}>Event</th>
              <th style={{ padding: "0.4rem" }}>IP</th>
            </tr>
          </thead>
          <tbody>
            {events.map((ev) => (
              <tr key={ev.id} style={{ borderBottom: "1px solid #eee" }}>
                <td style={{ padding: "0.4rem" }}>{new Date(ev.created_at).toLocaleString()}</td>
                <td style={{ padding: "0.4rem" }}>{ev.event_type}</td>
                <td style={{ padding: "0.4rem" }}>{ev.ip ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
